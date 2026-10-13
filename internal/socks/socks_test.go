package socks

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// echoHandler returns a handler that dials a local TCP echo server.
func startEchoServer(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestSOCKS5ConnectEcho(t *testing.T) {
	echoAddr, closeEcho := startEchoServer(t)
	defer closeEcho()

	// SOCKS5 server that forwards to the echo server regardless of target.
	tunnelHandler := func(host string, port uint16) (io.ReadWriteCloser, error) {
		return net.Dial("tcp", echoAddr)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() { _ = Serve(ln, tunnelHandler) }()

	// Client: perform a SOCKS5 handshake and CONNECT.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Greeting.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		t.Fatalf("read selection: %v", err)
	}
	if sel[0] != 0x05 || sel[1] != 0x00 {
		t.Fatalf("selection = %v", sel)
	}

	// CONNECT to a domain target.
	host := "example.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], 80)
	req = append(req, port[:]...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("connect: %v", err)
	}

	// Reply: VER REP RSV ATYP ... (>= 10 bytes for IPv4 bind addr).
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != replySuccess {
		t.Fatalf("reply code = %d, want success", reply[1])
	}

	// Send data through the tunnel, expect the echo.
	msg := []byte("hello through socks")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

func TestSOCKS5RejectsUnsupportedCommand(t *testing.T) {
	echoAddr, closeEcho := startEchoServer(t)
	defer closeEcho()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		_ = Serve(ln, func(h string, p uint16) (io.ReadWriteCloser, error) {
			return net.Dial("tcp", echoAddr)
		})
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	io.ReadFull(conn, make([]byte, 2))

	// BIND command (0x02) is unsupported.
	req := []byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != replyNotAllowed {
		t.Fatalf("reply code = %d, want not-allowed", reply[1])
	}
}
