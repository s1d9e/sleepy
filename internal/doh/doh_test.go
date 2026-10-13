package doh

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/s1d9e/sleepy/internal/crypto"
)

func TestHandshakeAndEchoOverDoH(t *testing.T) {
	domain := "tunnel.example.com"
	psk := crypto.DerivePSK("integration-test")

	srv, err := NewServer(ServerConfig{Domain: domain, PSK: psk})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ts := httptest.NewTLSServer(srv)
	defer ts.Close()

	// The client's endpoint is the test server, but the QNAME domain must
	// match the server's configured domain.
	cfg := ClientConfig{
		Domain:     domain,
		Session:    "abc123",
		PSK:        psk,
		Endpoint:   ts.URL + Path,
		HTTPClient: ts.Client(),
		Scheduler:  SchedulerConfig{Baseline: 5 * time.Millisecond, Burst: time.Millisecond, Jitter: 0.1},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewClient(ctx, cfg)
	if err != nil {
		t.Fatalf("NewClient (handshake): %v", err)
	}

	// Register a handler that echoes one downlink frame.
	var got []byte
	srv.HandleStream(func(session string, frame []byte) error {
		got = append(got, frame...)
		srv.QueueDownlink(session, []byte("echo:"+string(frame)))
		return nil
	})

	// Queue one uplink frame and run the pump until we see the echo.
	if err := client.Send([]byte("ping")); err != nil {
		t.Fatalf("Send: %v", err)
	}

	echoCh := make(chan string, 1)
	go func() {
		_ = client.Run(ctx, func(downlink []byte) error {
			if len(downlink) > 0 {
				echoCh <- string(downlink)
			}
			return nil
		})
	}()

	select {
	case echo := <-echoCh:
		if echo != "echo:ping" {
			t.Fatalf("echo = %q, want %q", echo, "echo:ping")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for echo")
	}

	if string(got) != "ping" {
		t.Fatalf("server received %q, want %q", got, "ping")
	}
}

// flakyHandler wraps an inner handler and fails the first `failures`
// requests, then passes through — simulating a server that goes down and
// comes back.
type flakyHandler struct {
	inner    http.Handler
	mu       sync.Mutex
	failures int
}

func (f *flakyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	if f.failures > 0 {
		f.failures--
		f.mu.Unlock()
		http.Error(w, "flaky outage", http.StatusBadGateway)
		return
	}
	f.mu.Unlock()
	f.inner.ServeHTTP(w, r)
}

func (f *flakyHandler) setFailures(n int) {
	f.mu.Lock()
	f.failures = n
	f.mu.Unlock()
}

func TestClientReconnectsAfterOutage(t *testing.T) {
	domain := "tunnel.example.com"
	psk := crypto.DerivePSK("reconnect-test")

	srv, err := NewServer(ServerConfig{Domain: domain, PSK: psk})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	flaky := &flakyHandler{inner: srv}
	ts := httptest.NewTLSServer(flaky)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var mu sync.Mutex
	var echoes []string
	srv.HandleStream(func(session string, frame []byte) error {
		mu.Lock()
		echoes = append(echoes, string(frame))
		mu.Unlock()
		srv.QueueDownlink(session, []byte("echo:"+string(frame)))
		return nil
	})

	// Start with a healthy server so the initial handshake succeeds.
	cfg := ClientConfig{
		Domain:     domain,
		Session:    "recon1",
		PSK:        psk,
		Endpoint:   ts.URL + Path,
		HTTPClient: ts.Client(),
		Scheduler:  SchedulerConfig{Baseline: 2 * time.Millisecond, Burst: time.Millisecond, Jitter: 0.1},
		Reconnect:  ReconnectConfig{MaxTransient: 2, BaseBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond},
	}
	client, err := NewClient(ctx, cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Count re-handshakes.
	var reconn atomic.Int32
	client.OnReconnect(func() { reconn.Add(1) })

	// Queue one frame, run, confirm the echo.
	if err := client.Send([]byte("before-outage")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	echoCh := make(chan string, 8)
	go func() {
		_ = client.Run(ctx, func(dl []byte) error {
			if len(dl) > 0 {
				echoCh <- string(dl)
			}
			return nil
		})
	}()

	select {
	case e := <-echoCh:
		if e != "echo:before-outage" {
			t.Fatalf("echo = %q", e)
		}
	case <-ctx.Done():
		t.Fatal("timed out before outage")
	}

	// Now simulate an outage long enough to exhaust transient retries,
	// then recovery.
	flaky.setFailures(50)
	// Queue a frame that must survive the outage and be delivered after
	// reconnect.
	if err := client.Send([]byte("during-outage")); err != nil {
		t.Fatalf("Send during outage: %v", err)
	}
	// Give the pump time to burn through retries, then heal the server.
	time.Sleep(150 * time.Millisecond)
	flaky.setFailures(0)

	// The frame sent during the outage should eventually be echoed once
	// the client re-handshakes and reseals it.
	deadline := time.After(10 * time.Second)
	for {
		select {
		case e := <-echoCh:
			if e == "echo:during-outage" {
				if reconn.Load() == 0 {
					t.Fatal("expected at least one re-handshake")
				}
				return
			}
		case <-deadline:
			t.Fatalf("frame lost after outage; re-handshakes=%d", reconn.Load())
		}
	}
}

func TestDecoyResolverRefusesUnknownDomain(t *testing.T) {
	psk := crypto.DerivePSK("decoy-test")
	srv, err := NewServer(ServerConfig{Domain: "tunnel.example.com", PSK: psk})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewTLSServer(srv)
	defer ts.Close()

	// Build a query for a foreign domain.
	q, err := buildQuery("www.google.com", 0x1234)
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+Path, strings.NewReader(string(q)))
	req.Header.Set("Content-Type", ContentType)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	// With no Upstream configured, expect REFUSED (rcode 5).
	_, ok, perr := parseResponse(body[:n])
	if perr == nil && ok {
		t.Fatal("decoy query returned a TXT answer with no upstream configured")
	}
}

func TestSchedulerBurstThenBaseline(t *testing.T) {
	s := NewScheduler(SchedulerConfig{
		Baseline:   50 * time.Millisecond,
		Burst:      5 * time.Millisecond,
		BurstSteps: 3,
		Jitter:     0.1,
		Seed:       1,
	})
	// No data pending -> baseline intervals (>= ~40ms).
	start := time.Now()
	if !s.Next(context.Background()) {
		t.Fatal("Next returned false")
	}
	if d := time.Since(start); d < 35*time.Millisecond {
		t.Fatalf("baseline interval too short: %v", d)
	}
	// Arm a burst -> intervals shrink.
	s.Notify(3)
	start = time.Now()
	if !s.Next(context.Background()) {
		t.Fatal("Next returned false in burst")
	}
	if d := time.Since(start); d > 30*time.Millisecond {
		t.Fatalf("burst interval too long: %v", d)
	}
}
