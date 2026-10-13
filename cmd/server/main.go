// sleepy-server terminates the Sleepy DoH tunnel and optionally serves as
// a decoy resolver for names outside the tunnel domain.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/s1d9e/sleepy/internal/crypto"
	"github.com/s1d9e/sleepy/internal/doh"
	"github.com/s1d9e/sleepy/internal/tunnel"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	var (
		domain     = flag.String("domain", "", "tunnel domain, e.g. tunnel.example.com (required)")
		secret     = flag.String("secret-key", "", "pre-shared key passphrase (required)")
		listen     = flag.String("listen", ":443", "address to listen on")
		certFile   = flag.String("cert", "", "TLS certificate file (PEM); if set with -key, serves TLS directly")
		keyFile    = flag.String("key", "", "TLS private key file (PEM)")
		autocertOn = flag.Bool("autocert", false, "obtain and renew a Let's Encrypt certificate automatically (needs port 80 reachable for HTTP-01)")
		cacheDir   = flag.String("autocert-cache", "autocert-cache", "directory to cache autocert certificates")
		email      = flag.String("email", "", "contact email for the Let's Encrypt account (recommended with -autocert)")
		upstream   = flag.String("upstream", "https://cloudflare-dns.com/dns-query", "decoy resolver upstream; empty refuses foreign queries")
		padding    = flag.Bool("padding", false, "length-hide frames (must match the client's -padding)")
	)
	flag.Parse()

	if *domain == "" || *secret == "" {
		fmt.Fprintln(os.Stderr, "usage: sleepy-server -domain tunnel.example.com -secret-key <passphrase> [flags]")
		flag.PrintDefaults()
		os.Exit(2)
	}

	if *autocertOn && (*certFile != "" || *keyFile != "") {
		log.Fatal("use either -autocert or -cert/-key, not both")
	}

	psk := crypto.DerivePSK(*secret)

	ds, err := doh.NewServer(doh.ServerConfig{
		Domain:   *domain,
		PSK:      psk,
		Upstream: *upstream,
		Padding:  *padding,
	})
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Wire the tunnel layer: each session's frames are relayed to a local
	// TCP target.
	_ = tunnel.NewServer(ctx, ds)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           ds,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("sleepy-server listening on %s (domain=%s, upstream=%s)", *listen, *domain, *upstream)

	switch {
	case *autocertOn:
		// Automatic Let's Encrypt via HTTP-01. The autocert manager
		// handles the ACME challenge on this same listener and renews
		// certificates before expiry.
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*domain),
			Cache:      autocert.DirCache(*cacheDir),
			Email:      *email,
		}
		srv.TLSConfig = m.TLSConfig()
		// HTTP-01 challenges are served over plaintext HTTP; redirect
		// everything else to HTTPS.
		srv.Handler = httpsRedirectHandler(ds)
		go func() {
			// ACME HTTP-01 listener on :80.
			chalSrv := &http.Server{
				Addr:              ":80",
				Handler:           m.HTTPHandler(nil),
				ReadHeaderTimeout: 10 * time.Second,
			}
			log.Printf("autocert: serving ACME HTTP-01 challenges on :80")
			if err := chalSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("autocert: challenge listener: %v", err)
			}
		}()
		err = srv.ListenAndServeTLS("", "")
	case *certFile != "" && *keyFile != "":
		err = srv.ListenAndServeTLS(*certFile, *keyFile)
	default:
		log.Printf("warning: no -cert/-key/-autocert given; serving plaintext HTTP (put a TLS terminator or use TLS in production)")
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
}

// httpsRedirectHandler serves the ACME challenge path and redirects other
// plaintext requests to HTTPS.
func httpsRedirectHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/acme-challenge/" || r.TLS != nil {
			next.ServeHTTP(w, r)
			return
		}
		target := "https://" + r.Host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}
