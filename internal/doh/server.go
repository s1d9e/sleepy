package doh

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/s1d9e/sleepy/internal/crypto"
	"github.com/s1d9e/sleepy/internal/pad"
	"github.com/s1d9e/sleepy/internal/protocol"
	"golang.org/x/net/dns/dnsmessage"
)

// Server terminates the Sleepy tunnel over DoH and doubles as a decoy
// resolver: queries that don't carry a valid tunnel session are answered
// like an ordinary DNS resolver, so the endpoint is indistinguishable from
// a legitimate DoH service to any scanner or analyst.
type Server struct {
	domain string
	psk    []byte

	mu         sync.Mutex
	sessions   map[string]*crypto.Session
	downlink   map[string]*dlQueue
	pendingMux map[string]func([]byte) error

	// OnStream, when set, receives every decrypted tunnel frame. The
	// callback receives the session label and the plaintext mux frame.
	OnStream func(session string, frame []byte) error

	// Upstream, when set, is the resolver used for decoy queries (e.g.
	// "https://cloudflare-dns.com/dns-query"). Empty means REFUSED.
	Upstream string
	http     *http.Client

	// paddingDownlink, when non-nil, holds the bucket set used to pad
	// downlink frames. nil disables padding. Uplink frames are padded by
	// the client; the server only needs to strip that padding, which it
	// does whenever padding is enabled here (the setting is symmetric).
	paddingDownlink []int
	paddingEnabled  bool
}

// dlQueue buffers downlink frames waiting for the client's next query.
type dlQueue struct {
	mu    sync.Mutex
	queue [][]byte
}

func (q *dlQueue) push(frame []byte) {
	q.mu.Lock()
	q.queue = append(q.queue, frame)
	q.mu.Unlock()
}

func (q *dlQueue) pop() []byte {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.queue) == 0 {
		return nil
	}
	f := q.queue[0]
	q.queue = q.queue[1:]
	return f
}

// ServerConfig tunes the server.
type ServerConfig struct {
	// Domain is the tunnel domain, e.g. "tunnel.example.com".
	Domain string
	// PSK authenticates handshakes (32 bytes).
	PSK []byte
	// Upstream resolver for decoy queries; empty refuses them.
	Upstream string
	// HTTPClient overrides the client used for decoy forwarding.
	HTTPClient *http.Client
	// Padding enables length-hiding padding of downlink frames (and
	// stripping of client padding). Must match the client's setting, since
	// padding is not negotiated on the wire. Off by default.
	Padding bool
}

// NewServer builds a server; no network I/O happens until ServeHTTP.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("doh: domain required")
	}
	if len(cfg.PSK) != crypto.KeyLen {
		return nil, fmt.Errorf("doh: PSK must be %d bytes", crypto.KeyLen)
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	s := &Server{
		domain:         cfg.Domain,
		psk:            cfg.PSK,
		sessions:       make(map[string]*crypto.Session),
		downlink:       make(map[string]*dlQueue),
		pendingMux:     make(map[string]func([]byte) error),
		Upstream:       cfg.Upstream,
		http:           hc,
		paddingEnabled: cfg.Padding,
	}
	if cfg.Padding {
		// Downlink travels in TXT records, which have a much larger
		// budget than the uplink's DNS name; use the default bucket set.
		s.paddingDownlink = pad.Buckets
	}
	return s, nil
}

// RegisterSession attaches a mux handler and pending-downlink hook for a
// session label. Called by the tunnel layer when it accepts a session.
func (s *Server) RegisterSession(label string, sess *crypto.Session, handler func([]byte) error) {
	s.mu.Lock()
	s.sessions[label] = sess
	s.pendingMux[label] = handler
	if s.downlink[label] == nil {
		s.downlink[label] = &dlQueue{}
	}
	s.mu.Unlock()
}

// HandleStream registers the global callback for inbound tunnel frames.
func (s *Server) HandleStream(fn func(session string, frame []byte) error) {
	s.mu.Lock()
	s.OnStream = fn
	s.mu.Unlock()
}

// QueueDownlink schedules an encoded frame to be returned in the client's
// next response.
func (s *Server) QueueDownlink(label string, frame []byte) {
	s.mu.Lock()
	q := s.downlink[label]
	if q == nil {
		q = &dlQueue{}
		s.downlink[label] = q
	}
	s.mu.Unlock()
	q.push(frame)
}

func (s *Server) session(label string) *crypto.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[label]
}

func (s *Server) handler(label string) func([]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingMux[label]
}

func (s *Server) dl(label string) *dlQueue {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.downlink[label]
	if q == nil {
		q = &dlQueue{}
		s.downlink[label] = q
	}
	return q
}

// Handshake performs the server side of the handshake for a session label
// and registers the derived session.
func (s *Server) Handshake(label string, clientRecord []byte) ([]byte, *crypto.Session, error) {
	resp, sess, err := crypto.ServerHandshake(s.psk, clientRecord)
	if err != nil {
		return nil, nil, err
	}
	s.RegisterSession(label, sess, nil)
	return resp, sess, nil
}

// ServeHTTP implements the DoH endpoint.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	packed, err := readDNSMessage(r)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var p dnsmessage.Parser
	hdr, err := p.Start(packed)
	if err != nil {
		http.Error(w, "bad dns", http.StatusBadRequest)
		return
	}
	q, err := p.Question()
	if err != nil {
		writeRcode(w, hdr.ID, dnsmessage.Question{}, dnsmessage.RCodeFormatError)
		return
	}

	name := q.Name.String()

	// Is this a tunnel query?
	record, label, derr := protocol.DecodeName(name, s.domain)
	if derr == nil {
		s.handleTunnel(w, hdr.ID, q, label, record)
		return
	}
	if derr == protocol.ErrNotTunnel {
		// Outside our domain: decoy or refuse.
		s.handleDecoy(w, r, hdr.ID, q, packed)
		return
	}
	// Malformed tunnel-looking name: behave like a confused resolver.
	writeRcode(w, hdr.ID, q, dnsmessage.RCodeServerFailure)
}

// handleTunnel processes a valid tunnel query.
func (s *Server) handleTunnel(w http.ResponseWriter, id uint16, q dnsmessage.Question, label string, record []byte) {
	sess := s.session(label)

	// A record is a handshake if no session exists yet, or if it carries
	// the handshake magic (a client re-handshaking after an outage, reusing
	// the same session label). In the latter case we replace the session.
	if sess == nil || crypto.IsHandshake(record) {
		resp, _, err := s.Handshake(label, record)
		if err != nil {
			log.Printf("doh: handshake rejected for %q: %v", label, err)
			writeRcode(w, id, q, dnsmessage.RCodeRefused)
			return
		}
		s.writeTXT(w, id, q, resp)
		return
	}

	// Decrypt and dispatch to the session's handler. An empty plaintext is
	// a keepalive: there is no frame to dispatch, just a pending-downlink
	// poll.
	plain, err := sess.Opener(false).Open(record)
	if err != nil {
		log.Printf("doh: bad record from %q: %v", label, err)
		writeRcode(w, id, q, dnsmessage.RCodeServerFailure)
		return
	}

	// When padding is enabled (symmetric config), the client padded the
	// uplink frame before sealing; strip it to recover the real frame.
	if s.paddingEnabled {
		plain, err = pad.Unpad(plain)
		if err != nil {
			log.Printf("doh: bad uplink padding from %q: %v", label, err)
			writeRcode(w, id, q, dnsmessage.RCodeServerFailure)
			return
		}
	}

	if len(plain) > 0 {
		s.mu.Lock()
		onStream := s.OnStream
		perSession := s.pendingMux[label]
		s.mu.Unlock()

		if onStream != nil {
			if err := onStream(label, plain); err != nil {
				log.Printf("doh: session %q frame error: %v", label, err)
			}
		} else if perSession != nil {
			if err := perSession(plain); err != nil {
				log.Printf("doh: session %q frame error: %v", label, err)
			}
		}
	}

	// Respond with any pending downlink (sealed by the session's sealer).
	// When padding is enabled, pad the frame first so its encrypted size
	// leaks less information.
	var payload []byte
	if dl := s.dl(label).pop(); dl != nil {
		toSeal := dl
		if s.paddingDownlink != nil {
			padded, perr := pad.Pad(dl, s.paddingDownlink)
			if perr == nil {
				toSeal = padded
			}
		}
		if sealed, serr := sess.Sealer(false).Seal(toSeal); serr == nil {
			payload = sealed
		}
	}
	if payload == nil {
		payload = []byte{}
	}
	s.writeTXT(w, id, q, payload)
}

// handleDecoy answers queries outside the tunnel domain as a normal
// resolver, forwarding to Upstream when configured.
func (s *Server) handleDecoy(w http.ResponseWriter, r *http.Request, id uint16, q dnsmessage.Question, packed []byte) {
	if s.Upstream == "" {
		writeRcode(w, id, q, dnsmessage.RCodeRefused)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.Upstream, bytes.NewReader(packed))
	if err != nil {
		writeRcode(w, id, q, dnsmessage.RCodeServerFailure)
		return
	}
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("Accept", ContentType)

	resp, err := s.http.Do(req)
	if err != nil {
		writeRcode(w, id, q, dnsmessage.RCodeServerFailure)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		writeRcode(w, id, q, dnsmessage.RCodeServerFailure)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) writeTXT(w http.ResponseWriter, id uint16, q dnsmessage.Question, payload []byte) {
	resp, err := buildTXTResponse(q.Name.String(), id, payload)
	if err != nil {
		writeRcode(w, id, q, dnsmessage.RCodeServerFailure)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

func writeRcode(w http.ResponseWriter, id uint16, q dnsmessage.Question, rcode dnsmessage.RCode) {
	m := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       id,
			Response: true,
			RCode:    rcode,
		},
	}
	if q.Name.String() != "" {
		m.Questions = []dnsmessage.Question{q}
	}
	packed, err := m.Pack()
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packed)
}

func readDNSMessage(r *http.Request) ([]byte, error) {
	if r.Method == http.MethodGet {
		dns := r.URL.Query().Get("dns")
		if dns == "" {
			return nil, fmt.Errorf("missing dns param")
		}
		return base64.RawURLEncoding.DecodeString(dns)
	}
	return io.ReadAll(io.LimitReader(r.Body, 64*1024))
}
