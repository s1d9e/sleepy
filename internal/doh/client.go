package doh

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/s1d9e/sleepy/internal/crypto"
	"github.com/s1d9e/sleepy/internal/pad"
	"github.com/s1d9e/sleepy/internal/protocol"
)

// Client is the Sleepy tunnel client: it performs the authenticated
// handshake, then pumps multiplexed frames over a paced DoH cadence.
// Transient transport failures are retried with exponential backoff; if the
// session appears dead the client re-handshakes automatically.
type Client struct {
	domain   string
	session  string // short session label embedded in the QNAME
	endpoint string // full DoH URL
	psk      []byte
	sess     *crypto.Session
	http     *http.Client
	sched    *Scheduler
	rc       ReconnectConfig

	// padding, when non-nil, holds the bucket set used to pad uplink
	// frames so their encrypted size leaks less information. nil disables
	// padding. Downlink padding is decided by the server.
	padding []int

	// ctx is the construction context, retained so Send can block on a
	// full uplink queue (backpressure) while still unblocking promptly if
	// the tunnel is torn down.
	ctx    context.Context
	uplink chan []byte // frames queued for transmission

	mu sync.Mutex
	// retry holds a plaintext frame that must be re-sealed and resent
	// after a session reset (at most one, since the pump is serial).
	retry []byte

	onReconnect func() // invoked after a successful re-handshake
}

// ReconnectConfig tunes automatic recovery from transport failures.
type ReconnectConfig struct {
	// MaxTransient is how many consecutive transient exchange failures
	// trigger a re-handshake. Default 3.
	MaxTransient int
	// BaseBackoff is the initial retry delay. Default 500ms.
	BaseBackoff time.Duration
	// MaxBackoff caps the retry delay. Default 30s.
	MaxBackoff time.Duration
}

func (r ReconnectConfig) withDefaults() ReconnectConfig {
	if r.MaxTransient <= 0 {
		r.MaxTransient = 3
	}
	if r.BaseBackoff <= 0 {
		r.BaseBackoff = 500 * time.Millisecond
	}
	if r.MaxBackoff <= 0 {
		r.MaxBackoff = 30 * time.Second
	}
	return r
}

// ClientConfig tunes the client.
type ClientConfig struct {
	// Domain is the tunnel domain, e.g. "tunnel.example.com".
	Domain string
	// Session is the short session label (DNS-safe, <= 32 chars).
	Session string
	// PSK authenticates the handshake (32 bytes).
	PSK []byte
	// Endpoint is the full DoH URL, e.g. "https://tunnel.example.com/dns-query".
	Endpoint string
	// HTTPClient overrides the underlying HTTP client (tests).
	HTTPClient *http.Client
	// Scheduler paces exchanges; zero-value uses defaults.
	Scheduler SchedulerConfig
	// Reconnect tunes automatic recovery; zero-value uses defaults.
	Reconnect ReconnectConfig
	// Padding enables length-hiding padding of uplink frames: every frame
	// is padded to a bucket so the encrypted size leaks less information.
	// The server must be configured with the same setting, since padding is
	// not negotiated on the wire. Off by default.
	Padding bool
}

// NewClient performs the handshake and returns a ready client.
func NewClient(ctx context.Context, cfg ClientConfig) (*Client, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("doh: domain required")
	}
	if len(cfg.PSK) != crypto.KeyLen {
		return nil, fmt.Errorf("doh: PSK must be %d bytes", crypto.KeyLen)
	}
	if cfg.Session == "" {
		return nil, fmt.Errorf("doh: session label required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://" + cfg.Domain + Path
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}

	c := &Client{
		domain:   cfg.Domain,
		session:  cfg.Session,
		endpoint: cfg.Endpoint,
		psk:      cfg.PSK,
		http:     hc,
		sched:    NewScheduler(cfg.Scheduler),
		rc:       cfg.Reconnect.withDefaults(),
		ctx:      ctx,
		uplink:   make(chan []byte, 256),
	}

	// When padding is enabled, derive the uplink bucket set from the
	// DNS-name budget so a padded frame still fits a single query name.
	if cfg.Padding {
		budget := protocol.MaxNamePayload(len(cfg.Session), len(cfg.Domain))
		c.padding = pad.UplinkBuckets(budget, crypto.SeqPrefixSize+crypto.Overhead)
	}

	if err := c.handshake(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// handshake performs the authenticated DoH handshake and stores the
// derived session. It is also used to re-establish a dropped session.
func (c *Client) handshake(ctx context.Context) error {
	hsMsg, sess, err := crypto.ClientHandshake(c.psk)
	if err != nil {
		return err
	}
	resp, err := c.exchange(ctx, hsMsg)
	if err != nil {
		return fmt.Errorf("doh: handshake exchange: %w", err)
	}
	if err := crypto.CompleteClientHandshake(c.psk, sess, resp); err != nil {
		return fmt.Errorf("doh: handshake: %w", err)
	}
	c.mu.Lock()
	c.sess = sess
	c.mu.Unlock()
	return nil
}

// OnReconnect registers a callback invoked after each successful
// re-handshake (useful for resetting higher-layer state).
func (c *Client) OnReconnect(fn func()) {
	c.mu.Lock()
	c.onReconnect = fn
	c.mu.Unlock()
}

func (c *Client) currentSession() *crypto.Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sess
}

// Session exposes the crypto session (for tests).
func (c *Client) Session() *crypto.Session { return c.currentSession() }

// MaxUplinkPayload returns the largest frame payload that fits in a single
// uplink query name, given this client's session label and tunnel domain.
// Producers of uplink frames must chunk to this size; anything larger would
// encode to a DNS name over the 253-byte limit and be dropped.
//
// When padding is enabled the budget shrinks by two more bytes: Pad()
// prepends a 2-byte length prefix and rounds the frame up to a bucket, so
// the largest frame must still land inside the largest bucket. Chunking to
// the unpadded maximum instead produced frames no bucket could hold, making
// Pad fail with ErrTooLarge on any full-size frame — i.e. on every bulk
// transfer, while small test payloads happened to fit a smaller bucket.
func (c *Client) MaxUplinkPayload() int {
	max := protocol.MaxUplinkFramePayload(
		len(c.session),
		len(c.domain),
		crypto.SeqPrefixSize,
		crypto.Overhead,
	)
	if c.padding != nil {
		if top := largestBucket(c.padding); top >= 0 {
			if capped := top - protocol.HeaderSize - pad.Overhead; capped < max {
				max = capped
			}
		}
	}
	if max < 0 {
		return 0
	}
	return max
}

// largestBucket returns the biggest bucket in a set (the sets built here are
// ascending, but this does not rely on that), or -1 for an empty set.
func largestBucket(buckets []int) int {
	top := -1
	for _, b := range buckets {
		if b > top {
			top = b
		}
	}
	return top
}

// Outbound implements protocol.Carrier: yields frames to transmit.
func (c *Client) Outbound() <-chan []byte { return c.uplink }

// Send implements protocol.Carrier: queues one encoded frame.
//
// When the uplink queue is full, Send BLOCKS until there is room rather than
// dropping the frame: this backpressures the caller (the mux writer), which
// in turn throttles the TCP read from the SOCKS client, so a bulk transfer
// slows down instead of failing with a queue-full error. The block is
// interruptible by the client's context so a torn-down tunnel cannot hang a
// writer forever.
func (c *Client) Send(frame []byte) error {
	// Arm a burst: one exchange per queued frame.
	c.sched.Notify(1)
	select {
	case c.uplink <- frame:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("doh: client closed: %w", c.ctx.Err())
	}
}

// Run pumps the tunnel until ctx is done. It drains queued frames at the
// burst cadence and exchanges keepalives at the baseline cadence, feeding
// every downlink payload to handleDownlink.
//
// Transient exchange failures are retried with the SAME sealed record
// (identical sequence number) so the server's anti-replay window
// de-duplicates in case the original actually landed. After MaxTransient
// consecutive failures the session is presumed dead: a fresh handshake is
// performed and any in-flight plaintext frame is re-sealed under the new
// session.
func (c *Client) Run(ctx context.Context, handleDownlink func([]byte) error) error {
	consecutive := 0
	for {
		// Re-arm the burst from the real backlog: one fast exchange per
		// queued frame. Without this the burst would collapse to a single
		// frame and sustained transfers would fall back to the baseline
		// keepalive rate (measured ~72 B/s instead of the burst rate).
		if pending := len(c.uplink); pending > 0 {
			c.sched.Notify(pending)
		}

		if !c.sched.Next(ctx) {
			return ctx.Err()
		}

		// Pick up a frame: a re-sealed retry first, else the queue.
		frame, ok := c.takeRetry()
		if !ok {
			select {
			case frame = <-c.uplink:
			default:
				frame = nil // keepalive
			}
		}

		sess := c.currentSession()
		// Pad the frame before sealing so the encrypted record leaks less
		// size information. Keepalives (nil) are padded too, making them
		// indistinguishable in size from a small frame.
		toSeal := frame
		if c.padding != nil {
			padded, perr := pad.Pad(frame, c.padding)
			if perr != nil {
				return fmt.Errorf("doh: pad uplink: %w", perr)
			}
			toSeal = padded
		}
		record, err := sess.Sealer(true).Seal(toSeal)
		if err != nil {
			return fmt.Errorf("doh: seal: %w", err)
		}

		resp, err := c.exchangeWithRetry(ctx, record)
		if err != nil {
			// Persistent failure: re-handshake and re-seal the frame.
			if herr := c.reestablish(ctx); herr != nil {
				return fmt.Errorf("doh: reconnect failed: %w", herr)
			}
			if frame != nil {
				c.putRetry(frame)
			}
			consecutive++
			continue
		}
		consecutive = 0

		if len(resp) == 0 {
			continue
		}
		sess = c.currentSession()
		plain, err := sess.Opener(true).Open(resp)
		if err != nil {
			// Downlink failed to authenticate — the session is out of
			// sync; re-handshake before the next exchange.
			if herr := c.reestablish(ctx); herr != nil {
				return fmt.Errorf("doh: reconnect failed: %w", herr)
			}
			continue
		}
		// The server pads downlink frames when padding is enabled (the
		// setting is symmetric). Strip the padding to recover the frame.
		if c.padding != nil {
			plain, err = pad.Unpad(plain)
			if err != nil {
				return fmt.Errorf("doh: unpad downlink: %w", err)
			}
		}
		if err := handleDownlink(plain); err != nil {
			return fmt.Errorf("doh: downlink: %w", err)
		}
		// Downlink self-clocking: this exchange returned data, so the
		// server likely has more pending. Re-arm a full burst so we keep
		// pulling at the fast rate until responses come back empty (then
		// the scheduler decays to the baseline keepalive on its own).
		// Without this, a pure downlink transfer would be gated by the
		// uplink backlog (which stays empty) and crawl at the baseline
		// cadence — one frame per keepalive.
		if len(plain) > 0 {
			c.sched.ArmBurst()
		}
	}
}

// exchangeWithRetry attempts the exchange, retrying the SAME record a few
// times with backoff before giving up (so the caller can re-handshake).
func (c *Client) exchangeWithRetry(ctx context.Context, record []byte) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < c.rc.MaxTransient; attempt++ {
		resp, err := c.exchange(ctx, record)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !sleepCtx(ctx, backoffDelay(c.rc, attempt)) {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

// reestablish performs a fresh handshake after a dead session, retrying
// with exponential backoff until the server responds or ctx is cancelled.
// This keeps the tunnel alive across outages longer than a single retry
// budget. On success it notifies the reconnect hook.
func (c *Client) reestablish(ctx context.Context) error {
	attempt := 0
	for {
		err := c.handshake(ctx)
		if err == nil {
			c.mu.Lock()
			hook := c.onReconnect
			c.mu.Unlock()
			if hook != nil {
				hook()
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Still unreachable: back off and try again.
		if !sleepCtx(ctx, backoffDelay(c.rc, attempt)) {
			return ctx.Err()
		}
		attempt++
	}
}

func (c *Client) putRetry(frame []byte) {
	c.mu.Lock()
	c.retry = frame
	c.mu.Unlock()
}

func (c *Client) takeRetry() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.retry == nil {
		return nil, false
	}
	f := c.retry
	c.retry = nil
	return f, true
}

// backoffDelay computes an exponential backoff with jitter for attempt.
func backoffDelay(rc ReconnectConfig, attempt int) time.Duration {
	d := rc.BaseBackoff << uint(attempt)
	if d > rc.MaxBackoff || d <= 0 {
		d = rc.MaxBackoff
	}
	// Add up to 50% jitter so retries don't synchronize.
	jitter := time.Duration(randInt63n(int64(d/2 + 1)))
	return d + jitter
}

// sleepCtx sleeps for d, returning false if ctx was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func randInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	v := int64(uint64(b[0])<<56|uint64(b[1])<<48|uint64(b[2])<<40|uint64(b[3])<<32|
		uint64(b[4])<<24|uint64(b[5])<<16|uint64(b[6])<<8|uint64(b[7])>>1) >> 1
	return v % n
}

// exchange sends one DoH query carrying record and returns the TXT
// payload of the response.
func (c *Client) exchange(ctx context.Context, record []byte) ([]byte, error) {
	name := protocol.EncodeName(record, c.session, c.domain)

	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	idNum := uint16(id[0])<<8 | uint16(id[1])

	packed, err := buildQuery(name, idNum)
	if err != nil {
		return nil, err
	}

	// RFC 8484 POST: body is the wire-format DNS message.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.doHURL(), bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("Accept", ContentType)

	httpResp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: HTTP %d", httpResp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	payload, ok, err := parseResponse(body)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return payload, nil
}

func (c *Client) doHURL() string {
	if c.endpoint != "" {
		return c.endpoint
	}
	return "https://" + c.domain + Path
}

// EncodeURLQuery encodes a DNS message for a GET-style DoH URL, exposed
// for interoperability testing.
func EncodeURLQuery(msg []byte) string {
	return base64.RawURLEncoding.EncodeToString(msg)
}
