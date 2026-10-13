package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/s1d9e/sleepy/internal/crypto"
	"github.com/s1d9e/sleepy/internal/doh"
)

// Throughput calibration harness.
//
// The tunnel is a request/response transport: every DoH exchange carries one
// uplink frame in the query NAME and returns one downlink frame in a TXT
// record. Throughput is gated by the scheduler cadence (burst/baseline
// intervals), not by the network. These benchmarks measure the real numbers
// so the scheduler can be calibrated against a target bitrate.
//
// Run (slow cadence benchmarks need an explicit -benchtime):
//
//	go test ./internal/tunnel/ -bench 'Throughput|Latency' -benchtime 1x -v

// counter is a race-safe monotonic byte counter.
type counter struct{ n atomic.Int64 }

func (c *counter) add(v int64) { c.n.Add(v) }
func (c *counter) get() int64  { return c.n.Load() }

// startSink starts a TCP server that reads and discards everything, counting
// bytes received. It measures UPLINK throughput (client -> server).
func startSink(t testing.TB) (addr string, received *counter, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sink listen: %v", err)
	}
	c := &counter{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 32*1024)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						c.add(int64(n))
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), c, func() { ln.Close() }
}

// startSource starts a TCP server that writes n bytes then idles so buffered
// frames flush. It measures DOWNLINK throughput (server -> client).
func startSource(t testing.TB, n int) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("source listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 64*1024)
				for i := range buf {
					buf[i] = byte(i)
				}
				written := 0
				for written < n {
					m := len(buf)
					if n-written < m {
						m = n - written
					}
					wn, err := conn.Write(buf[:m])
					if err != nil {
						return
					}
					written += wn
				}
				// Keep the connection open so buffered frames flush.
				time.Sleep(3 * time.Second)
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// benchStack wires the full tunnel (target + DoH server + tunnel server +
// client) and returns a connected stream plus teardown.
type benchStack struct {
	conn   io.ReadWriteCloser
	client *doh.Client
	cancel context.CancelFunc
}

func newBenchStack(t testing.TB, targetAddr string, sess string, sched doh.SchedulerConfig) *benchStack {
	t.Helper()
	domain := "tunnel.example.com"
	psk := crypto.DerivePSK("bench")

	ds, err := doh.NewServer(doh.ServerConfig{Domain: domain, PSK: psk})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewTLSServer(ds)

	ctx, cancel := context.WithCancel(context.Background())
	_ = NewServer(ctx, ds)

	dc, err := doh.NewClient(ctx, doh.ClientConfig{
		Domain:     domain,
		Session:    sess,
		PSK:        psk,
		Endpoint:   ts.URL + doh.Path,
		HTTPClient: ts.Client(),
		Scheduler:  sched,
	})
	if err != nil {
		cancel()
		ts.Close()
		t.Fatalf("NewClient: %v", err)
	}

	tc := NewClient(ctx, dc)
	go func() { _ = tc.Run(ctx) }()

	host, portStr, _ := net.SplitHostPort(targetAddr)
	var port uint16
	for _, ch := range portStr {
		port = port*10 + uint16(ch-'0')
	}
	conn, err := tc.Dial(host, port)
	if err != nil {
		cancel()
		ts.Close()
		t.Fatalf("tunnel Dial: %v", err)
	}
	return &benchStack{
		conn:   conn,
		client: dc,
		cancel: func() { cancel(); ts.Close() },
	}
}

// waitUntil polls cond until true or the timeout elapses.
func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

// fill returns a byte slice of length n (for payload buffers).
func fill(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// readFullTimeout reads exactly len(buf) bytes or returns an error on timeout.
// The stream is an io.ReadWriteCloser (not a net.Conn), so we cannot set a
// read deadline; a goroutine does the blocking read and we select on a timer.
func readFullTimeout(rw io.ReadWriteCloser, buf []byte, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(rw, buf)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("bench: read timeout after %v", timeout)
	}
}

// BenchmarkUplinkThroughput pushes payload bytes through a sink target and
// reports effective KB/s and Kbps at the production scheduler cadence.
func BenchmarkUplinkThroughput(b *testing.B) {
	const payload = 16 * 1024
	sched := doh.SchedulerConfig{} // production defaults

	addr, received, closeFn := startSink(b)
	defer closeFn()

	for i := 0; i < b.N; i++ {
		st := newBenchStack(b, addr, "up"+string(rune('a'+i)), sched)
		before := received.get()
		buf := fill(payload)

		start := time.Now()
		written := 0
		for written < payload {
			m := 64 * 1024
			if payload-written < m {
				m = payload - written
			}
			if _, err := st.conn.Write(buf[written : written+m]); err != nil {
				st.cancel()
				b.Fatalf("write: %v", err)
			}
			written += m
		}
		// Throughput is measured until the sink has received all bytes.
		ok := waitUntil(120*time.Second, func() bool {
			return received.get()-before >= payload
		})
		elapsed := time.Since(start)
		st.cancel()
		if !ok {
			b.Fatalf("uplink timeout: got %d of %d bytes", received.get()-before, payload)
		}
		b.ReportMetric(float64(payload)/elapsed.Seconds()/1024, "KB/s-up")
		b.ReportMetric(float64(payload)*8/elapsed.Seconds()/1000, "Kbps-up")
	}
}

// BenchmarkDownlinkThroughput pulls payload bytes from a source target and
// reports effective KB/s and Kbps at the production scheduler cadence.
func BenchmarkDownlinkThroughput(b *testing.B) {
	const payload = 16 * 1024
	sched := doh.SchedulerConfig{}

	addr, closeFn := startSource(b, payload)
	defer closeFn()

	for i := 0; i < b.N; i++ {
		st := newBenchStack(b, addr, "dn"+string(rune('a'+i)), sched)

		readBuf := make([]byte, payload)
		start := time.Now()
		rerr := readFullTimeout(st.conn, readBuf, 120*time.Second)
		elapsed := time.Since(start)
		st.cancel()
		if rerr != nil {
			b.Fatalf("downlink read: %v", rerr)
		}
		b.ReportMetric(float64(payload)/elapsed.Seconds()/1024, "KB/s-down")
		b.ReportMetric(float64(payload)*8/elapsed.Seconds()/1000, "Kbps-down")
	}
}

// BenchmarkRoundTripLatency measures the time for one tiny write to be echoed
// back — the fundamental exchange cost of the transport. Uses a fast scheduler
// so the number reflects transport cost, not cadence pacing.
func BenchmarkRoundTripLatency(b *testing.B) {
	addr, closeEcho := startEcho(b)
	defer closeEcho()
	sched := doh.SchedulerConfig{Baseline: time.Millisecond, Burst: time.Millisecond, Jitter: 0.05}

	for i := 0; i < b.N; i++ {
		st := newBenchStack(b, addr, "rt"+string(rune('a'+i%26)), sched)

		msg := []byte("x")
		start := time.Now()
		if _, err := st.conn.Write(msg); err != nil {
			st.cancel()
			b.Fatalf("write: %v", err)
		}
		buf := make([]byte, 1)
		if err := readFullTimeout(st.conn, buf, 10*time.Second); err != nil {
			st.cancel()
			b.Fatalf("read: %v", err)
		}
		elapsed := time.Since(start)
		st.cancel()
		b.ReportMetric(float64(elapsed.Microseconds()), "us-rtt")
	}
}

// BenchmarkFrameEfficiency measures the uplink payload that fits in one frame
// (one DoH query name) for a typical session/domain, and reports the implied
// queries-per-KB cost.
func BenchmarkFrameEfficiency(b *testing.B) {
	addr, received, closeFn := startSink(b)
	defer closeFn()

	sched := doh.SchedulerConfig{Baseline: time.Millisecond, Burst: time.Millisecond, Jitter: 0.05}
	st := newBenchStack(b, addr, "eff1", sched)
	defer st.cancel()

	uplinkMax := st.client.MaxUplinkPayload()
	if uplinkMax <= 0 {
		b.Fatalf("MaxUplinkPayload = %d", uplinkMax)
	}
	buf := fill(uplinkMax)
	before := received.get()
	if _, err := st.conn.Write(buf); err != nil {
		b.Fatalf("write: %v", err)
	}
	ok := waitUntil(30*time.Second, func() bool {
		return received.get()-before >= int64(uplinkMax)
	})
	if !ok {
		b.Fatalf("frame not delivered")
	}
	b.ReportMetric(float64(uplinkMax), "B/uplink-frame")
}
