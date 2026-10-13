package protocol

import (
	"context"
	"fmt"
	"io"
	"sync"
)

// The multiplexer interleaves multiple logical TCP streams over a single
// ordered, reliable carrier (the DoH request/response cadence). Each side
// runs a Mux that:
//
//   - opens outbound streams (client side) via Open, or accepts inbound
//     ones (server side) via Accept,
//   - serializes writes so frames never interleave mid-frame,
//   - bounds memory with a bounded receive queue per stream; a slow
//     consumer applies backpressure to HandleIncoming, which in turn
//     slows the carrier drain.
//
// The carrier is abstract: the Mux never touches the network. The owner
// drains encoded frames via Carrier.Outbound and feeds received frames
// via HandleIncoming.

// Carrier abstracts the transport beneath the multiplexer.
type Carrier interface {
	// Outbound yields encoded frames to transmit to the peer.
	Outbound() <-chan []byte
	// Send queues one encoded frame for transmission.
	Send(frame []byte) error
}

const (
	// streamQueue bounds buffered inbound frames per stream. Combined
	// with MaxPayload it caps per-stream memory at ~32 KiB.
	streamQueue = 32

	// acceptQueue bounds concurrent inbound streams per session.
	acceptQueue = 64
)

// Stream is one logical TCP connection through the tunnel.
type Stream struct {
	ID  uint16
	mux *Mux

	rx     chan Frame // inbound data frames; the SYN frame is delivered first
	closed chan struct{}

	closeOnce sync.Once
}

// Mux multiplexes streams over a Carrier.
type Mux struct {
	isClient bool
	carrier  Carrier

	mu       sync.Mutex
	streams  map[uint16]*Stream
	nextID   uint16
	accepted chan *Stream

	ctx    context.Context
	cancel context.CancelFunc
}

// NewMux creates a multiplexer. isClient determines stream ID parity:
// client-initiated streams use odd IDs, server-initiated even ones, so
// both sides can open streams without collisions.
func NewMux(ctx context.Context, carrier Carrier, isClient bool) *Mux {
	ctx, cancel := context.WithCancel(ctx)
	var first uint16 = 2
	if isClient {
		first = 1
	}
	return &Mux{
		isClient: isClient,
		carrier:  carrier,
		streams:  make(map[uint16]*Stream),
		nextID:   first,
		accepted: make(chan *Stream, acceptQueue),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Accept returns the channel of inbound streams (server side).
func (m *Mux) Accept() <-chan *Stream { return m.accepted }

// Open creates a new outbound stream. synPayload is carried to the peer
// inside the SYN frame (the dial target, when opening from the client).
func (m *Mux) Open(synPayload []byte) (*Stream, error) {
	m.mu.Lock()
	if int(m.nextID) > MaxStreamID {
		m.mu.Unlock()
		return nil, ErrStreamExhausted
	}
	id := m.nextID
	m.nextID += 2
	s := m.newStream(id)
	m.streams[id] = s
	m.mu.Unlock()

	if err := m.send(Frame{StreamID: id, Flags: FlagSYN, Payload: synPayload}); err != nil {
		m.removeStream(id)
		return nil, fmt.Errorf("protocol: send SYN: %w", err)
	}
	return s, nil
}

func (m *Mux) newStream(id uint16) *Stream {
	return &Stream{
		ID:     id,
		mux:    m,
		rx:     make(chan Frame, streamQueue),
		closed: make(chan struct{}),
	}
}

func (m *Mux) send(f Frame) error {
	enc, err := f.Encode(nil)
	if err != nil {
		return err
	}
	return m.carrier.Send(enc)
}

func (m *Mux) removeStream(id uint16) {
	m.mu.Lock()
	delete(m.streams, id)
	m.mu.Unlock()
}

func (m *Mux) getStream(id uint16) *Stream {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streams[id]
}

// HandleIncoming processes one encoded frame received from the carrier.
func (m *Mux) HandleIncoming(enc []byte) error {
	f, _, err := DecodeFrame(enc)
	if err != nil {
		return err
	}

	switch {
	case f.Flags&FlagSYN != 0:
		return m.handleSYN(f)
	case f.Flags&FlagRST != 0:
		if s := m.getStream(f.StreamID); s != nil {
			s.close()
			m.removeStream(f.StreamID)
		}
		return nil
	}

	s := m.getStream(f.StreamID)
	if s == nil {
		// Data for an unknown stream: RST so the peer stops sending.
		return m.send(Frame{StreamID: f.StreamID, Flags: FlagRST})
	}

	if f.Flags&FlagFIN != 0 {
		// Deliver the FIN so Read returns io.EOF after draining.
		s.deliver(f)
		s.close()
		m.removeStream(f.StreamID)
		return nil
	}
	s.deliver(f)
	return nil
}

func (m *Mux) handleSYN(f Frame) error {
	// Reject IDs from our own half of the parity space: both sides use
	// distinct parities precisely so that collisions cannot happen.
	ours := uint16(2)
	if m.isClient {
		ours = 1
	}
	if f.StreamID == 0 || f.StreamID%2 == ours%2 {
		return m.send(Frame{StreamID: f.StreamID, Flags: FlagRST})
	}

	m.mu.Lock()
	if _, exists := m.streams[f.StreamID]; exists {
		m.mu.Unlock()
		return m.send(Frame{StreamID: f.StreamID, Flags: FlagRST})
	}
	s := m.newStream(f.StreamID)
	m.streams[f.StreamID] = s
	m.mu.Unlock()

	select {
	case m.accepted <- s:
		// Deliver the SYN payload as the first frame so the acceptor
		// can read the dial target.
		s.rx <- Frame{StreamID: s.ID, Flags: FlagSYN, Payload: f.Payload}
		return nil
	case <-m.ctx.Done():
		return m.ctx.Err()
	default:
		m.removeStream(f.StreamID)
		return m.send(Frame{StreamID: f.StreamID, Flags: FlagRST})
	}
}

// Close tears down the mux and all streams.
func (m *Mux) Close() error {
	m.cancel()
	m.mu.Lock()
	streams := make([]*Stream, 0, len(m.streams))
	for id, s := range m.streams {
		streams = append(streams, s)
		delete(m.streams, id)
	}
	m.mu.Unlock()
	for _, s := range streams {
		s.close()
	}
	return nil
}

// Read returns the next inbound frame from the stream. On server-accepted
// streams the first frame is the SYN (dial target). After the peer
// half-closes, Read returns io.EOF once buffered frames are drained.
func (s *Stream) Read() (Frame, error) {
	select {
	case f := <-s.rx:
		if f.Flags&FlagFIN != 0 {
			return Frame{}, io.EOF
		}
		return f, nil
	case <-s.closed:
		// Drain anything already buffered before reporting EOF.
		select {
		case f := <-s.rx:
			if f.Flags&FlagFIN != 0 {
				return Frame{}, io.EOF
			}
			return f, nil
		default:
			return Frame{}, io.EOF
		}
	case <-s.mux.ctx.Done():
		return Frame{}, s.mux.ctx.Err()
	}
}

// WriteData sends one data frame on the stream.
func (s *Stream) WriteData(payload []byte) error {
	select {
	case <-s.closed:
		return io.ErrClosedPipe
	default:
	}
	return s.mux.send(Frame{StreamID: s.ID, Payload: payload})
}

// CloseWrite half-closes the stream (sends FIN) and stops tracking it
// locally. Inbound frames for the ID are still accepted until the peer's
// FIN/RST arrives or the mux closes.
func (s *Stream) CloseWrite() error {
	return s.mux.send(Frame{StreamID: s.ID, Flags: FlagFIN})
}

// Close resets the stream abruptly and notifies the peer.
func (s *Stream) Close() error {
	s.close()
	s.mux.removeStream(s.ID)
	return s.mux.send(Frame{StreamID: s.ID, Flags: FlagRST})
}

// deliver queues an inbound frame, respecting closure.
func (s *Stream) deliver(f Frame) {
	select {
	case s.rx <- f:
	case <-s.closed:
	case <-s.mux.ctx.Done():
	}
}

func (s *Stream) close() {
	s.closeOnce.Do(func() { close(s.closed) })
}
