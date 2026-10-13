package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/s1d9e/sleepy/internal/doh"
	"github.com/s1d9e/sleepy/internal/protocol"
)

// Server terminates DoH sessions and relays each tunnel stream to a local
// TCP target.
type Server struct {
	doh *doh.Server

	mu       sync.Mutex
	sessions map[string]*sessionMux
}

type sessionMux struct {
	mux *protocol.Mux
}

// NewServer builds a tunnel server over an established DoH server. It
// registers the frame handler so every decrypted tunnel frame is routed to
// the right session's multiplexer.
func NewServer(ctx context.Context, ds *doh.Server) *Server {
	ts := &Server{
		doh:      ds,
		sessions: make(map[string]*sessionMux),
	}
	ds.HandleStream(ts.handleFrame)
	return ts
}

// handleFrame routes one decrypted frame to its session's mux.
func (s *Server) handleFrame(session string, frame []byte) error {
	sm := s.getOrCreate(session)
	return sm.mux.HandleIncoming(frame)
}

func (s *Server) getOrCreate(session string) *sessionMux {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sm, ok := s.sessions[session]; ok {
		return sm
	}
	// Each session gets its own mux, non-client (even stream IDs). The
	// carrier pushes downlink frames straight into the DoH server's
	// per-session queue, which the next response to that client carries.
	mux := protocol.NewMux(context.Background(), &sessionCarrier{s: s, session: session}, false)
	sm := &sessionMux{mux: mux}
	s.sessions[session] = sm
	// Accept loop: dial each requested target and relay.
	go s.acceptLoop(mux)
	return sm
}

// sessionCarrier sends downlink frames back to the client via the DoH
// server's per-session downlink queue. Outbound is unused on the server
// side (the server never reads from a carrier channel).
type sessionCarrier struct {
	s       *Server
	session string
}

func (c *sessionCarrier) Outbound() <-chan []byte { return nil }

func (c *sessionCarrier) Send(frame []byte) error {
	c.s.doh.QueueDownlink(c.session, frame)
	return nil
}

// acceptLoop services accepted streams: read the dial target from the SYN,
// connect, and relay both directions.
func (s *Server) acceptLoop(mux *protocol.Mux) {
	for srv := range mux.Accept() {
		go func(st *protocol.Stream) {
			// First frame is the SYN carrying the dial target.
			syn, err := st.Read()
			if err != nil || syn.Flags&protocol.FlagSYN == 0 {
				_ = st.Close()
				return
			}
			target := string(syn.Payload)
			host, portStr, ok := strings.Cut(target, ":")
			if !ok {
				_ = st.Close()
				return
			}
			var port uint16
			fmt.Sscanf(portStr, "%d", &port)

			conn, err := net.Dial("tcp", net.JoinHostPort(host, portStr))
			if err != nil {
				_ = st.Close()
				return
			}
			relay(st, conn, port)
		}(srv)
	}
}

// relay copies bytes between a mux stream and a TCP connection.
func relay(st *protocol.Stream, conn net.Conn, _ uint16) {
	defer conn.Close()
	defer st.Close()

	done := make(chan struct{}, 2)
	// TCP -> tunnel.
	go func() {
		buf := make([]byte, protocol.MaxPayload)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if werr := st.WriteData(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				_ = st.CloseWrite()
				break
			}
		}
		done <- struct{}{}
	}()
	// Tunnel -> TCP.
	go func() {
		for {
			f, err := st.Read()
			if err != nil {
				break
			}
			if _, werr := conn.Write(f.Payload); werr != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// unused io guard (kept for interface documentation).
var _ io.ReadWriteCloser = (*streamConn)(nil)
