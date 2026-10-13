package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/s1d9e/sleepy/internal/doh"
	"github.com/s1d9e/sleepy/internal/protocol"
	"github.com/s1d9e/sleepy/internal/socks"
)

// Client wires a local SOCKS5 listener to a DoH tunnel.
type Client struct {
	doh *doh.Client
	mux *protocol.Mux
}

// NewClient builds a tunnel client over an established DoH client.
func NewClient(ctx context.Context, dc *doh.Client) *Client {
	mux := protocol.NewMux(ctx, dc, true)
	return &Client{doh: dc, mux: mux}
}

// Run pumps the tunnel: it drains the DoH client's downlink into the mux
// and lets the mux's outbound frames flow through the DoH uplink. Blocks
// until ctx is done.
func (c *Client) Run(ctx context.Context) error {
	return c.doh.Run(ctx, func(downlink []byte) error {
		return c.mux.HandleIncoming(downlink)
	})
}

// Dial opens a TCP connection through the tunnel. It returns a
// ReadWriteCloser that relays over the mux.
func (c *Client) Dial(host string, port uint16) (io.ReadWriteCloser, error) {
	syn := []byte(fmt.Sprintf("%s:%d", host, port))
	s, err := c.mux.Open(syn)
	if err != nil {
		return nil, err
	}
	return newClientConn(s, c.doh.MaxUplinkPayload()), nil
}

// Handler returns a handler suitable for socks.Serve.
func (c *Client) Handler() socks.Handler {
	return func(host string, port uint16) (io.ReadWriteCloser, error) {
		return c.Dial(host, port)
	}
}

// ListenAndServe runs a SOCKS5 listener on addr and serves until ctx is
// done.
func (c *Client) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	return socks.Serve(ln, c.Handler())
}
