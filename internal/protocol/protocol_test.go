package protocol

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []Frame{
		{StreamID: 1, Flags: FlagSYN, Payload: []byte("example.com:443")},
		{StreamID: 42, Flags: FlagData, Payload: bytes.Repeat([]byte("x"), MaxPayload)},
		{StreamID: 65535, Flags: FlagFIN},
		{StreamID: 7, Flags: FlagRST},
		{StreamID: 3, Payload: nil},
	}
	for _, want := range cases {
		enc, err := want.Encode(nil)
		if err != nil {
			t.Fatalf("Encode(%+v): %v", want, err)
		}
		got, n, err := DecodeFrame(enc)
		if err != nil {
			t.Fatalf("DecodeFrame: %v", err)
		}
		if n != len(enc) {
			t.Fatalf("consumed %d of %d bytes", n, len(enc))
		}
		if got.StreamID != want.StreamID || got.Flags != want.Flags {
			t.Fatalf("header mismatch: %+v != %+v", got, want)
		}
		if !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("payload mismatch")
		}
	}
}

func TestFrameRejectsOversize(t *testing.T) {
	f := Frame{StreamID: 1, Payload: make([]byte, MaxPayload+1)}
	if _, err := f.Encode(nil); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestFrameRejectsBadStreamID(t *testing.T) {
	if _, err := (&Frame{StreamID: 0}).Encode(nil); err == nil {
		t.Fatal("stream ID 0 accepted")
	}
	// MaxStreamID+1 overflows uint16 to 0, which is the same rejection;
	// verify the boundary value is accepted instead.
	if _, err := (&Frame{StreamID: MaxStreamID}).Encode(nil); err != nil {
		t.Fatalf("MaxStreamID rejected: %v", err)
	}
}

func TestDecodeFrameTruncated(t *testing.T) {
	f := Frame{StreamID: 1, Payload: []byte("hello")}
	enc, _ := f.Encode(nil)
	if _, _, err := DecodeFrame(enc[:len(enc)-2]); err == nil {
		t.Fatal("truncated frame accepted")
	}
	if _, _, err := DecodeFrame(enc[:3]); err == nil {
		t.Fatal("short header accepted")
	}
}

func TestCodecNameRoundTrip(t *testing.T) {
	// Use a payload that actually fits one query name.
	max := MaxNamePayload(6, len("tunnel.example.com"))
	data := make([]byte, max)
	for i := range data {
		data[i] = byte(i * 7)
	}
	name := EncodeName(data, "s1a2b3", "tunnel.example.com")

	// DNS constraints.
	if len(name) > 253 {
		t.Fatalf("name too long: %d", len(name))
	}
	for _, l := range splitLabels(name) {
		if len(l) > 63 {
			t.Fatalf("label too long: %d", len(l))
		}
	}

	got, session, err := DecodeName(name, "tunnel.example.com")
	if err != nil {
		t.Fatalf("DecodeName: %v", err)
	}
	if session != "s1a2b3" {
		t.Fatalf("session = %q", session)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("round trip mismatch")
	}
}

func TestDecodeNameRejectsForeignDomain(t *testing.T) {
	if _, _, err := DecodeName("abc.decoy.com", "tunnel.example.com"); err != ErrNotTunnel {
		t.Fatalf("expected ErrNotTunnel, got %v", err)
	}
}

func TestCodecTXTRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte{7, 8, 9}, 1000)
	strs := EncodeTXT(data)
	for _, s := range strs {
		if len(s) > 255 {
			t.Fatalf("TXT string too long: %d", len(s))
		}
	}
	if !bytes.Equal(DecodeTXT(strs), data) {
		t.Fatal("TXT round trip mismatch")
	}
}

func TestMaxUplinkFramePayloadFitsName(t *testing.T) {
	// Uplink frames travel in the QNAME. The largest frame payload must
	// produce a record that, once AEAD-sealed (seq + tag) and base32'd,
	// still fits a 253-byte name.
	const (
		aeadSeq = 8
		aeadTag = 16
	)
	for _, tc := range []struct {
		session, domain string
	}{
		{"abc12345", "tunnel.example.com"},
		{"s1", "t.example.co"},
		{"sesslabel12", "a.very.long.tunnel.domain.example.org"},
	} {
		sessLen := len(tc.session)
		domLen := len(tc.domain)
		payload := MaxUplinkFramePayload(sessLen, domLen, aeadSeq, aeadTag)
		if payload <= 0 {
			t.Fatalf("payload <= 0 for %+v", tc)
		}

		// Simulate the full uplink: record = seq + header + payload + tag.
		recordLen := aeadSeq + HeaderSize + payload + aeadTag
		fakeRecord := make([]byte, recordLen)
		name := EncodeName(fakeRecord, tc.session, tc.domain)
		if len(name) > 253 {
			t.Fatalf("%+v: name len %d exceeds 253 (payload=%d record=%d)",
				tc, len(name), payload, recordLen)
		}

		// One byte more must overflow (proves the bound is tight).
		overRecord := make([]byte, recordLen+1)
		overName := EncodeName(overRecord, tc.session, tc.domain)
		if len(overName) <= 253 {
			t.Fatalf("%+v: expected overflow at payload+1, name len %d", tc, len(overName))
		}
	}
}

func TestMaxNamePayload(t *testing.T) {
	// Sanity: for a typical config, payload should be > 120 bytes.
	p := MaxNamePayload(8, len("tunnel.example.com"))
	if p < 120 {
		t.Fatalf("MaxNamePayload too small: %d", p)
	}
	// Encoded data must actually fit a name.
	data := make([]byte, p)
	name := EncodeName(data, "abcdefgh", "tunnel.example.com")
	if len(name) > 253 {
		t.Fatalf("encoded name exceeds limit: %d", len(name))
	}
}

func splitLabels(name string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			out = append(out, name[start:i])
			start = i + 1
		}
	}
	return out
}

// loopbackCarrier wires two muxes together in memory. Frames are delivered
// in order (like the real DoH transport) through a single dispatcher
// goroutine per direction.
type loopbackCarrier struct {
	peer *Mux
	ch   chan []byte
	done chan struct{}
}

func newLoopbackCarrier() *loopbackCarrier {
	return &loopbackCarrier{
		ch:   make(chan []byte, 128),
		done: make(chan struct{}),
	}
}

// bind attaches the peer mux and starts the in-order dispatcher.
func (c *loopbackCarrier) bind(peer *Mux) {
	c.peer = peer
	go func() {
		for {
			select {
			case f := <-c.ch:
				_ = peer.HandleIncoming(f)
			case <-c.done:
				return
			}
		}
	}()
}

// Close stops the dispatcher.
func (c *loopbackCarrier) Close() { close(c.done) }

func (c *loopbackCarrier) Outbound() <-chan []byte { return c.ch }

func (c *loopbackCarrier) Send(frame []byte) error {
	select {
	case c.ch <- frame:
		return nil
	case <-c.done:
		return io.ErrClosedPipe
	}
}

func TestMuxStreamRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c2s := newLoopbackCarrier()
	s2c := newLoopbackCarrier()
	client := NewMux(ctx, c2s, true)
	server := NewMux(ctx, s2c, false)
	c2s.bind(server)
	s2c.bind(client)

	// Client opens a stream with a dial target.
	stream, err := client.Open([]byte("example.com:443"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Server accepts it.
	var srv *Stream
	select {
	case srv = <-server.Accept():
	case <-ctx.Done():
		t.Fatal("server never accepted")
	}

	// First frame on the accepted stream is the SYN/dial target.
	syn, err := srv.Read()
	if err != nil {
		t.Fatalf("read SYN: %v", err)
	}
	if syn.Flags&FlagSYN == 0 || string(syn.Payload) != "example.com:443" {
		t.Fatalf("unexpected SYN frame: %+v", syn)
	}

	// Client -> server data.
	msg := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if err := stream.WriteData(msg); err != nil {
		t.Fatalf("WriteData: %v", err)
	}
	frame, err := srv.Read()
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(frame.Payload, msg) {
		t.Fatalf("payload mismatch: %q", frame.Payload)
	}

	// Server -> client data.
	reply := []byte("HTTP/1.1 200 OK\r\n")
	if err := srv.WriteData(reply); err != nil {
		t.Fatalf("server write: %v", err)
	}
	frame, err = stream.Read()
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(frame.Payload, reply) {
		t.Fatalf("reply mismatch: %q", frame.Payload)
	}

	// Half-close propagates EOF.
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if _, err := srv.Read(); err != io.EOF {
		t.Fatalf("expected EOF after FIN, got %v", err)
	}
}

func TestMuxMultipleStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c2s := newLoopbackCarrier()
	s2c := newLoopbackCarrier()
	client := NewMux(ctx, c2s, true)
	server := NewMux(ctx, s2c, false)
	c2s.bind(server)
	s2c.bind(client)

	// Server: echo everything back, on every accepted stream. The first
	// inbound frame is the SYN (dial target); skip it.
	go func() {
		for srv := range server.Accept() {
			go func(s *Stream) {
				syn, err := s.Read()
				if err != nil || syn.Flags&FlagSYN == 0 {
					_ = s.Close()
					return
				}
				for {
					f, err := s.Read()
					if err != nil {
						_ = s.CloseWrite()
						return
					}
					if err := s.WriteData(f.Payload); err != nil {
						return
					}
				}
			}(srv)
		}
	}()

	const n = 8
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			s, err := client.Open([]byte("target:80"))
			if err != nil {
				errs <- err
				return
			}
			payload := []byte{byte(i)}
			if err := s.WriteData(payload); err != nil {
				errs <- err
				return
			}
			f, err := s.Read()
			if err != nil {
				errs <- err
				return
			}
			if len(f.Payload) != 1 || f.Payload[0] != byte(i) {
				errs <- fmt.Errorf("stream %d echo mismatch: %v", i, f.Payload)
				return
			}
			errs <- nil
		}(i)
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestMuxStreamIDsParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	m := NewMux(ctx, sinkCarrier{}, true)
	for i := 0; i < 5; i++ {
		s, err := m.Open(nil)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if s.ID%2 != 1 {
			t.Fatalf("client stream ID %d not odd", s.ID)
		}
	}
	srv := NewMux(ctx, sinkCarrier{}, false)
	for i := 0; i < 5; i++ {
		s, err := srv.Open(nil)
		if err != nil {
			t.Fatalf("server Open: %v", err)
		}
		if s.ID%2 != 0 {
			t.Fatalf("server stream ID %d not even", s.ID)
		}
	}
}

// sinkCarrier discards frames so Open can be exercised without a peer.
type sinkCarrier struct{}

func (sinkCarrier) Outbound() <-chan []byte { return nil }
func (sinkCarrier) Send(frame []byte) error { return nil }
