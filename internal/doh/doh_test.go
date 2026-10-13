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
	"github.com/s1d9e/sleepy/internal/pad"
	"github.com/s1d9e/sleepy/internal/protocol"
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

// TestSchedulerBurstHoldsUnderBacklog is a regression test for the decay
// math. The old code computed frac = remaining/12 with NO upper clamp and
// base = burst + frac*(baseline-burst), so a backlog > 12 pushed frac > 1 and
// the interval ABOVE the baseline: the more data queued, the slower it went.
// A deep backlog must instead HOLD the fast burst rate, and no interval may
// ever explode past the baseline.
//
// The scheduler applies jitter (Jitter:0 falls back to the 0.4 default), so
// these assertions use invariant thresholds rather than exact values. With
// jitter 0.4: burst-phase intervals land in [60ms,140ms] and baseline-phase
// in [900ms,2100ms]; the midpoint baseline/2=750ms cleanly separates them.
func TestSchedulerBurstHoldsUnderBacklog(t *testing.T) {
	const (
		baseline = 1500 * time.Millisecond
		burst    = 100 * time.Millisecond
		steps    = 12
	)
	s := NewScheduler(SchedulerConfig{
		Baseline:   baseline,
		Burst:      burst,
		BurstSteps: steps,
		Seed:       1, // reproducible jitter stream
	})
	fast := baseline / 2 // separates burst-phase from baseline-phase

	// Simulate a deep uplink backlog: 60 frames queued.
	s.Notify(60)

	// The first exchange of a full burst must be burst-like (fast), not the
	// baseline. The old unbounded-decay bug blew this up to ~7s.
	if first := s.nextInterval(); first >= fast {
		t.Fatalf("first burst interval = %v, want < %v (burst-like)", first, fast)
	}

	// Drain the whole backlog. The burst rate must be held for many ticks
	// (not collapsed after a single frame), and no interval may explode past
	// a sane multiple of the baseline.
	var maxInterval time.Duration
	held := 0
	for i := 0; i < 60; i++ {
		d := s.nextInterval()
		if d > maxInterval {
			maxInterval = d
		}
		if d < fast {
			held++
		}
	}
	// With steps=12 the burst floor is held until remaining decays to steps;
	// over a 60-frame backlog that's ~48 fast ticks (the last ~12 ramp up).
	if held < 40 {
		t.Fatalf("burst rate held for only %d/60 ticks; a deep backlog must sustain the burst", held)
	}
	// Healthy decay tops out near baseline*1.4 (jitter); the old bug reached
	// ~17s. A 2x ceiling catches any unbounded regression.
	if maxInterval > 2*baseline {
		t.Fatalf("interval %v exceeded 2*baseline %v under backlog (unbounded decay)", maxInterval, 2*baseline)
	}
}

// TestSchedulerUsesConfiguredSteps pins that BurstSteps (not a hardcoded
// constant) drives the decay ramp. With steps=3 the ramp must complete over
// ~3 ticks; if the scheduler ignored the config and used 12, the burst floor
// would never be reached for a small backlog.
func TestSchedulerUsesConfiguredSteps(t *testing.T) {
	const (
		baseline = 1500 * time.Millisecond
		burst    = 100 * time.Millisecond
		steps    = 3 // deliberately small and != the old hardcoded 12
	)
	s := NewScheduler(SchedulerConfig{
		Baseline:   baseline,
		Burst:      burst,
		BurstSteps: steps,
		Seed:       1,
	})
	fast := baseline / 2

	s.Notify(10) // backlog of 10
	s.nextInterval()
	held := 0
	for i := 0; i < 9; i++ {
		if d := s.nextInterval(); d < fast {
			held++
		}
	}
	// Burst is held while remaining decays from 9 down to steps=3, then the
	// ramp lifts the interval. That's ~7 fast ticks. If steps were hardcoded
	// to 12, frac would never approach 1 for remaining<=9 and no tick would
	// land in the burst band.
	if held < 5 {
		t.Fatalf("burst held %d ticks, want >= 5; BurstSteps=%d is being ignored", held, steps)
	}
}

// TestCadenceProfiles verifies the named profiles resolve to sensible,
// correctly-ordered settings: stealth must be the slowest (most human-like),
// fast the most aggressive. It also pins that an explicit field overrides the
// preset, and that an unknown profile falls back to the built-in defaults.
func TestCadenceProfiles(t *testing.T) {
	resolved := func(profile string) SchedulerConfig {
		// No explicit fields: let every value come from the preset so we can
		// compare the presets against each other.
		return SchedulerConfig{Profile: profile}.withDefaults()
	}

	stealth := resolved(ProfileStealth)
	balanced := resolved(ProfileBalanced)
	fast := resolved(ProfileFast)

	// Burst interval must decrease across profiles (more aggressive = faster).
	if !(stealth.Burst > balanced.Burst && balanced.Burst > fast.Burst) {
		t.Fatalf("burst order wrong: stealth=%v balanced=%v fast=%v",
			stealth.Burst, balanced.Burst, fast.Burst)
	}
	// Baseline (idle keepalive) must also decrease across profiles.
	if !(stealth.Baseline > balanced.Baseline && balanced.Baseline > fast.Baseline) {
		t.Fatalf("baseline order wrong: stealth=%v balanced=%v fast=%v",
			stealth.Baseline, balanced.Baseline, fast.Baseline)
	}
	// Jitter must decrease (fast is least human-like, stealth most).
	if !(stealth.Jitter > fast.Jitter) {
		t.Fatalf("jitter order wrong: stealth=%v fast=%v", stealth.Jitter, fast.Jitter)
	}

	// An explicit field must override the preset.
	o := SchedulerConfig{Profile: ProfileStealth, Burst: 7 * time.Millisecond}.withDefaults()
	if o.Burst != 7*time.Millisecond {
		t.Fatalf("explicit Burst ignored: got %v want 7ms", o.Burst)
	}

	// An unknown profile must fall back to the built-in defaults
	// (baseline 1500ms, burst 100ms).
	u := SchedulerConfig{Profile: "no-such", Jitter: 0.5}.withDefaults()
	if u.Baseline != 1500*time.Millisecond || u.Burst != 100*time.Millisecond {
		t.Fatalf("unknown profile did not fall back to defaults: %+v", u)
	}
}

// TestPaddedFullSizeFrameFitsBudget pins the invariant that padding depends
// on: a full-size uplink frame (the largest the stream will chunk to) must
// always find a bucket big enough to hold it, and the padded record plus AEAD
// overhead must still fit the DNS-name budget. Chunking and the bucket set
// were derived independently, so a full-size frame landed above every bucket
// (Pad failed with ErrTooLarge) while small payloads happened to fit — which
// is why every unit test passed yet every bulk transfer with -padding
// crashed the client.
func TestPaddedFullSizeFrameFitsBudget(t *testing.T) {
	cases := []struct{ session, domain string }{
		{"pad1", "tunnel.example.com"},
		{"h0i9321p", "localhost"}, // short domain: the crash case
		{"sess01", "x.example.org"},
	}
	for _, tc := range cases {
		// Wire the padding config exactly as NewClient does (without the
		// handshake) so the test isolates the chunk-vs-bucket invariant.
		budget := protocol.MaxNamePayload(len(tc.session), len(tc.domain))
		c := &Client{
			session: tc.session,
			domain:  tc.domain,
			padding: pad.UplinkBuckets(budget, crypto.SeqPrefixSize+crypto.Overhead),
		}
		if c.padding == nil {
			t.Fatalf("%s/%s: padding unexpectedly disabled (budget %d too small)",
				tc.session, tc.domain, budget)
		}

		// Reproduce the mux: a frame is header + a full-size payload.
		frame := make([]byte, protocol.HeaderSize+c.MaxUplinkPayload())
		padded, err := pad.Pad(frame, c.padding)
		if err != nil {
			t.Fatalf("%s/%s: full-size frame (%d B) failed to pad: %v",
				tc.session, tc.domain, len(frame), err)
		}

		// The sealed record (seq prefix + padded + auth tag) must fit the
		// query-name budget, else EncodeName overflows the 253-byte limit.
		sealed := crypto.SeqPrefixSize + len(padded) + crypto.Overhead
		if sealed > budget {
			t.Fatalf("%s/%s: sealed padded frame %d B exceeds name budget %d B",
				tc.session, tc.domain, sealed, budget)
		}
	}
}
