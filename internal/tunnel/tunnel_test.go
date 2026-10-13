package tunnel

import (
	"context"
	"github.com/s1d9e/sleepy/internal/socks"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/s1d9e/sleepy/internal/crypto"
	"github.com/s1d9e/sleepy/internal/doh"
)

// startEcho starts a TCP echo server and returns its address.
func startEcho(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestEndToEndTunnelOverDoH(t *testing.T) {
	echoAddr, closeEcho := startEcho(t)
	defer closeEcho()

	domain := "tunnel.example.com"
	psk := crypto.DerivePSK("e2e-test")

	// DoH server.
	ds, err := doh.NewServer(doh.ServerConfig{Domain: domain, PSK: psk})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewTLSServer(ds)
	defer ts.Close()

	// Tunnel server over the DoH server.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = NewServer(ctx, ds)

	// DoH client.
	dc, err := doh.NewClient(ctx, doh.ClientConfig{
		Domain:     domain,
		Session:    "e2e1",
		PSK:        psk,
		Endpoint:   ts.URL + doh.Path,
		HTTPClient: ts.Client(),
		Scheduler:  doh.SchedulerConfig{Baseline: 2 * time.Millisecond, Burst: time.Millisecond, Jitter: 0.1},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Tunnel client.
	tc := NewClient(ctx, dc)
	go func() { _ = tc.Run(ctx) }()

	// Open a stream to the echo server through the tunnel.
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	var echoPort uint16
	for _, ch := range echoPortStr {
		echoPort = echoPort*10 + uint16(ch-'0')
	}

	conn, err := tc.Dial(echoHost, echoPort)
	if err != nil {
		t.Fatalf("tunnel Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("end-to-end payload through the sleepy tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", buf, msg)
	}
}

// TestEndToEndTunnelWithPadding enables length-hiding padding on both sides
// and proves the frames still flow: the client pads every uplink frame (the
// server strips it), and the server pads every downlink frame (the client
// strips it). Symmetric config, self-describing length prefix.
func TestEndToEndTunnelWithPadding(t *testing.T) {
	echoAddr, closeEcho := startEcho(t)
	defer closeEcho()

	domain := "tunnel.example.com"
	psk := crypto.DerivePSK("e2e-padding")

	ds, err := doh.NewServer(doh.ServerConfig{Domain: domain, PSK: psk, Padding: true})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewTLSServer(ds)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = NewServer(ctx, ds)

	dc, err := doh.NewClient(ctx, doh.ClientConfig{
		Domain:     domain,
		Session:    "pad1",
		PSK:        psk,
		Endpoint:   ts.URL + doh.Path,
		HTTPClient: ts.Client(),
		Scheduler:  doh.SchedulerConfig{Baseline: 2 * time.Millisecond, Burst: time.Millisecond, Jitter: 0.1},
		Padding:    true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	tc := NewClient(ctx, dc)
	go func() { _ = tc.Run(ctx) }()

	// Small payload: without padding this would be a tiny record; with
	// padding it must be inflated to a bucket and still round-trip.
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	var echoPort uint16
	for _, ch := range echoPortStr {
		echoPort = echoPort*10 + uint16(ch-'0')
	}

	conn, err := tc.Dial(echoHost, echoPort)
	if err != nil {
		t.Fatalf("tunnel Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("padded payload through the sleepy tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", buf, msg)
	}
}

// TestEndToEndLargePayload exercises the uplink chunking fix: a payload far
// larger than one uplink frame (~108 B) must be split across many DNS-name
// frames, reassembled by the mux, echoed, and returned intact.
func TestEndToEndLargePayload(t *testing.T) {
	echoAddr, closeEcho := startEcho(t)
	defer closeEcho()

	domain := "tunnel.example.com"
	psk := crypto.DerivePSK("e2e-large")

	ds, err := doh.NewServer(doh.ServerConfig{Domain: domain, PSK: psk})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewTLSServer(ds)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = NewServer(ctx, ds)

	dc, err := doh.NewClient(ctx, doh.ClientConfig{
		Domain:     domain,
		Session:    "e2ebig",
		PSK:        psk,
		Endpoint:   ts.URL + doh.Path,
		HTTPClient: ts.Client(),
		Scheduler:  doh.SchedulerConfig{Baseline: 2 * time.Millisecond, Burst: time.Millisecond, Jitter: 0.1},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// The uplink limit for this session/domain must be small (name-bounded),
	// confirming the chunking actually kicks in.
	uplinkMax := dc.MaxUplinkPayload()
	if uplinkMax <= 0 || uplinkMax >= 8192 {
		t.Fatalf("unexpected uplink max %d", uplinkMax)
	}

	tc := NewClient(ctx, dc)
	go func() { _ = tc.Run(ctx) }()

	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	var echoPort uint16
	for _, ch := range echoPortStr {
		echoPort = echoPort*10 + uint16(ch-'0')
	}

	conn, err := tc.Dial(echoHost, echoPort)
	if err != nil {
		t.Fatalf("tunnel Dial: %v", err)
	}
	defer conn.Close()

	// 8 KiB payload → dozens of uplink frames.
	msg := make([]byte, 8192)
	for i := range msg {
		msg[i] = byte(i % 251)
	}
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	for i := range buf {
		if buf[i] != msg[i] {
			t.Fatalf("mismatch at byte %d: got %d want %d", i, buf[i], msg[i])
		}
	}
}

func TestEndToEndThroughSOCKS5(t *testing.T) {
	echoAddr, closeEcho := startEcho(t)
	defer closeEcho()

	domain := "tunnel.example.com"
	psk := crypto.DerivePSK("socks-e2e")

	ds, err := doh.NewServer(doh.ServerConfig{Domain: domain, PSK: psk})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewTLSServer(ds)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = NewServer(ctx, ds)

	dc, err := doh.NewClient(ctx, doh.ClientConfig{
		Domain:     domain,
		Session:    "socks1",
		PSK:        psk,
		Endpoint:   ts.URL + doh.Path,
		HTTPClient: ts.Client(),
		Scheduler:  doh.SchedulerConfig{Baseline: 2 * time.Millisecond, Burst: time.Millisecond, Jitter: 0.1},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	tc := NewClient(ctx, dc)
	go func() { _ = tc.Run(ctx) }()

	// Start the SOCKS5 listener on an ephemeral port.
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks listen: %v", err)
	}
	defer socksLn.Close()
	go func() { _ = socks.Serve(socksLn, tc.Handler()) }()

	// SOCKS5 client handshake.
	socksConn, err := net.Dial("tcp", socksLn.Addr().String())
	if err != nil {
		t.Fatalf("socks dial: %v", err)
	}
	defer socksConn.Close()

	if _, err := socksConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(socksConn, sel); err != nil {
		t.Fatalf("selection: %v", err)
	}

	// CONNECT to the echo address (relay ignores the target, so any host
	// works; use the real one for realism).
	host, portStr, _ := net.SplitHostPort(echoAddr)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	var port uint16
	for _, ch := range portStr {
		port = port*10 + uint16(ch-'0')
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := socksConn.Write(req); err != nil {
		t.Fatalf("connect: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(socksConn, reply); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("socks reply = %d, want success", reply[1])
	}

	msg := []byte("socks5 through sleepy")
	if _, err := socksConn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(socksConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: %q", buf)
	}
}
