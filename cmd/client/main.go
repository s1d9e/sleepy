// sleepy-client opens a local SOCKS5 proxy that forwards TCP traffic
// through the DoH tunnel to a sleepy-server.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/s1d9e/sleepy/internal/crypto"
	"github.com/s1d9e/sleepy/internal/doh"
	"github.com/s1d9e/sleepy/internal/tunnel"
)

func main() {
	var (
		server   = flag.String("server", "", "tunnel domain, e.g. tunnel.example.com (required)")
		secret   = flag.String("secret-key", "", "pre-shared key passphrase (required)")
		listen   = flag.String("listen", "127.0.0.1:1080", "local SOCKS5 listen address")
		endpoint = flag.String("endpoint", "", "override DoH URL (default https://<server>/dns-query)")
		session  = flag.String("session", "", "session label (default: random)")
		insecure = flag.Bool("insecure", false, "skip TLS certificate verification (lab only)")
		padding  = flag.Bool("padding", false, "length-hide frames (must match the server's -padding)")
	)
	flag.Parse()

	if *server == "" || *secret == "" {
		fmt.Fprintln(os.Stderr, "usage: sleepy-client -server tunnel.example.com -secret-key <passphrase> [flags]")
		flag.PrintDefaults()
		os.Exit(2)
	}

	psk := crypto.DerivePSK(*secret)

	if *session == "" {
		*session = randomSession()
	}

	hc := &http.Client{Timeout: 30 * time.Second}
	if *insecure {
		hc.Transport = &http.Transport{
			TLSClientConfig: tlsInsecureConfig(),
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dc, err := doh.NewClient(ctx, doh.ClientConfig{
		Domain:     *server,
		Session:    *session,
		PSK:        psk,
		Endpoint:   *endpoint,
		HTTPClient: hc,
		Padding:    *padding,
	})
	if err != nil {
		log.Fatalf("handshake failed: %v", err)
	}
	log.Printf("handshake ok (session=%s)", *session)

	tc := tunnel.NewClient(ctx, dc)

	// Pump the tunnel in the background.
	go func() {
		if err := tc.Run(ctx); err != nil && ctx.Err() == nil {
			log.Fatalf("tunnel: %v", err)
		}
	}()

	log.Printf("SOCKS5 listening on %s — route traffic through it", *listen)
	if err := tc.ListenAndServe(ctx, *listen); err != nil && ctx.Err() == nil {
		log.Fatalf("socks: %v", err)
	}
}

// randomSession returns a short DNS-safe session label.
func randomSession() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "session0"
	}
	var s strings.Builder
	for _, c := range b {
		s.WriteByte(alphabet[int(c)%len(alphabet)])
	}
	return s.String()
}

// tlsInsecureConfig returns a TLS config that skips verification — lab use
// only, never in a real engagement where the endpoint is untrusted.
func tlsInsecureConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in via -insecure
}
