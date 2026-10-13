// Package tunnel glues the DoH transport, the stream multiplexer, and the
// TCP endpoints together.
//
// Client side: a local SOCKS5 listener opens a mux stream per connection;
// the stream's frames are sealed and pumped over DoH at the scheduler's
// cadence.
//
// Server side: each DoH session owns a mux; inbound frames feed the mux,
// accepted streams are dialed to the requested TCP target, and the
// target's bytes are queued back as downlink.
package tunnel

import (
	"sync"

	"github.com/s1d9e/sleepy/internal/protocol"
)

// streamConn adapts a protocol.Stream to io.ReadWriteCloser so it can be
// relayed with io.Copy from the SOCKS layer.
type streamConn struct {
	s *protocol.Stream

	// maxChunk caps the payload of each written frame. For client-side
	// conns this is the uplink limit (frames travel in a DNS name and are
	// size-constrained); for server-side conns the larger downlink limit
	// applies. Defaults to protocol.MaxPayload.
	maxChunk int

	// firstRead delivers the SYN frame's payload (dial target) on
	// server-accepted streams before any data.
	pending []byte
	once    sync.Once
}

// newClientConn wraps a client-initiated stream (no SYN delivery needed).
// uplinkMax is the largest frame payload that fits the uplink path.
func newClientConn(s *protocol.Stream, uplinkMax int) *streamConn {
	if uplinkMax <= 0 {
		uplinkMax = protocol.MaxPayload
	}
	return &streamConn{s: s, maxChunk: uplinkMax}
}

// newServerConn wraps an accepted stream, stashing the SYN payload. The
// server downlink travels in TXT records, which tolerate larger frames.
func newServerConn(s *protocol.Stream, target []byte) *streamConn {
	return &streamConn{s: s, pending: target, maxChunk: protocol.MaxPayload}
}

func (c *streamConn) Read(p []byte) (int, error) {
	// Serve any stashed SYN/dial-target bytes first (server side only).
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}

	f, err := c.s.Read()
	if err != nil {
		return 0, err
	}
	if len(f.Payload) > len(p) {
		// Buffer the remainder for the next Read.
		n := copy(p, f.Payload)
		c.pending = append(c.pending[:0], f.Payload[n:]...)
		return n, nil
	}
	return copy(p, f.Payload), nil
}

func (c *streamConn) Write(p []byte) (int, error) {
	// Chunk to the frame payload limit for this direction.
	maxChunk := c.maxChunk
	if maxChunk <= 0 {
		maxChunk = protocol.MaxPayload
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxChunk {
			n = maxChunk
		}
		if err := c.s.WriteData(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// CloseWrite half-closes (FIN) so the peer sees EOF.
func (c *streamConn) CloseWrite() error {
	return c.s.CloseWrite()
}

func (c *streamConn) Close() error {
	return c.s.Close()
}
