// Package doh implements the Sleepy transport: DNS-over-HTTPS carrying the
// multiplexed tunnel frames.
//
// Uplink frames travel in the query NAME (base32 labels); downlink frames
// travel in TXT records of the DNS response. The client speaks DoH with a
// real resolver-facing HTTP endpoint, so on the wire every exchange is a
// valid RFC 8484 DNS-over-HTTPS transaction.
//
// This package provides three pieces:
//
//   - the DNS message helpers (build query, parse response),
//   - a Client that runs the request/response cadence and exposes the
//     transport as a protocol.Carrier,
//   - a Server handler that decodes sessions, feeds the multiplexer, and
//     doubles as a decoy resolver for names outside the tunnel domain.
package doh

import (
	"fmt"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Content types and paths per RFC 8484.
const (
	ContentType = "application/dns-message"
	Path        = "/dns-query"
)

// maxUDPPayload mirrors the classic EDNS0 UDP size; large enough for a TXT
// downlink chunk, small enough to look like ordinary stub traffic.
const maxUDPPayload = 1232

// dnsName converts a string to a canonical dnsmessage.Name (FQDN, ending
// with a dot), panicking on invalid names. Tunnel names are always
// produced by our own encoder, so they are valid by construction.
func dnsName(s string) dnsmessage.Name {
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	n, err := dnsmessage.NewName(s)
	if err != nil {
		// Should not happen for names we generate.
		panic(fmt.Sprintf("doh: invalid name %q: %v", s, err))
	}
	return n
}

// buildQuery assembles a DNS query carrying payload in the QNAME with
// QTYPE=TXT. id is the DNS transaction ID (random, anti-correlation).
func buildQuery(name string, id uint16) ([]byte, error) {
	q := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			Response:         false,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsName(name),
				Type:  dnsmessage.TypeTXT,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	return q.Pack()
}

// parseResponse unpacks a DNS response and returns the TXT payload found in
// the answer section. ok=false means the response carried no TXT data.
func parseResponse(msg []byte) (payload []byte, ok bool, err error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		return nil, false, fmt.Errorf("doh: parse header: %w", err)
	}
	if !hdr.Response {
		return nil, false, fmt.Errorf("doh: not a response")
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return nil, false, fmt.Errorf("doh: rcode %v", hdr.RCode)
	}
	for {
		_, err := p.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, false, fmt.Errorf("doh: parse questions: %w", err)
		}
	}
	for {
		rr, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, false, fmt.Errorf("doh: parse answers: %w", err)
		}
		if rr.Type != dnsmessage.TypeTXT {
			// Skip the resource body.
			if _, err := p.Answer(); err != nil {
				return nil, false, fmt.Errorf("doh: skip answer: %w", err)
			}
			continue
		}
		res, err := p.Answer()
		if err != nil {
			return nil, false, fmt.Errorf("doh: parse TXT: %w", err)
		}
		txtRes, isTXT := res.Body.(*dnsmessage.TXTResource)
		if !isTXT {
			continue
		}
		for _, s := range txtRes.TXT {
			payload = append(payload, s...)
		}
		ok = true
	}
	return payload, ok, nil
}

// buildTXTResponse assembles a DNS response with one TXT answer carrying
// payload under name.
func buildTXTResponse(name string, id uint16, payload []byte) ([]byte, error) {
	// Split into <=255 byte character-strings per RFC 1035.
	var strs []string
	for len(payload) > 0 {
		n := 255
		if len(payload) < n {
			n = len(payload)
		}
		strs = append(strs, string(payload[:n]))
		payload = payload[n:]
	}
	if len(strs) == 0 {
		strs = []string{""}
	}

	m := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:            id,
			Response:      true,
			RCode:         dnsmessage.RCodeSuccess,
			Authoritative: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsName(name),
				Type:  dnsmessage.TypeTXT,
				Class: dnsmessage.ClassINET,
			},
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsName(name),
					Type:  dnsmessage.TypeTXT,
					Class: dnsmessage.ClassINET,
					TTL:   1,
				},
				Body: &dnsmessage.TXTResource{TXT: strs},
			},
		},
	}
	return m.Pack()
}
