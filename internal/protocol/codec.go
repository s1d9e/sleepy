package protocol

import (
	"encoding/base32"
	"fmt"
	"strings"
)

// DNS codec: packs protocol frames into DNS messages.
//
// Uplink (client -> server): the encrypted record is carried in the query
// NAME. base32 (lowercase, no padding) maps any ciphertext to the DNS-safe
// alphabet [a-z2-7]; the resulting string is split into labels of at most
// 63 bytes:
//
//	<l1>.<l2>...<ln>.<session>.<tunnel-domain>
//
// Downlink (server -> client): the encrypted record is carried in TXT
// records of the response, which tolerate ~1600 bytes per RR without
// fragmentation concerns under DoH.
//
// Both directions use the same base32 alphabet, so a single decoder serves
// either side.

// b32 is the DNS-safe base32 codec used on the wire.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodeName encodes data as a DNS name under domain, splitting into
// labels of at most 63 bytes. session is the short session label the
// server uses to route to the right crypto session.
func EncodeName(data []byte, session, domain string) string {
	enc := strings.ToLower(b32.EncodeToString(data))
	var labels []string
	for len(enc) > 63 {
		labels = append(labels, enc[:63])
		enc = enc[63:]
	}
	if len(enc) > 0 {
		labels = append(labels, enc)
	}
	labels = append(labels, session)
	return strings.Join(append(labels, domain), ".")
}

// DecodeName extracts the payload from a query name that must end with
// "."+domain. It returns the data and the session label. Names that do not
// belong to the tunnel domain are rejected with ErrNotTunnel so the server
// can treat them as decoy lookups.
var ErrNotTunnel = fmt.Errorf("protocol: name outside tunnel domain")

func DecodeName(name, domain string) (data []byte, session string, err error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	suffix := "." + domain
	if !strings.HasSuffix(name, suffix) {
		return nil, "", ErrNotTunnel
	}
	prefix := strings.TrimSuffix(name, suffix)
	if prefix == "" {
		return nil, "", fmt.Errorf("protocol: missing session label")
	}

	labels := strings.Split(prefix, ".")
	// The last label of the prefix is the session; the rest is payload.
	session = labels[len(labels)-1]
	payload := labels[:len(labels)-1]
	if session == "" {
		return nil, "", fmt.Errorf("protocol: empty session label")
	}

	enc := strings.Join(payload, "")
	if enc == "" {
		return nil, "", fmt.Errorf("protocol: empty payload")
	}
	for _, l := range payload {
		if len(l) > 63 {
			return nil, "", fmt.Errorf("protocol: oversized label")
		}
	}
	data, err = b32.DecodeString(strings.ToUpper(enc))
	if err != nil {
		return nil, "", fmt.Errorf("protocol: base32 decode: %w", err)
	}
	return data, session, nil
}

// EncodeTXT packs data into TXT record character-strings. DNS TXT RDATA is
// a sequence of length-prefixed strings of at most 255 bytes; we split the
// payload accordingly. The DoH layer embeds the result in a TXT answer.
func EncodeTXT(data []byte) []string {
	var out []string
	for len(data) > 0 {
		n := 255
		if len(data) < n {
			n = len(data)
		}
		out = append(out, string(data[:n]))
		data = data[n:]
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}

// DecodeTXT concatenates TXT character-strings back into the payload.
func DecodeTXT(txt []string) []byte {
	var out []byte
	for _, s := range txt {
		out = append(out, s...)
	}
	return out
}

// MaxNamePayload returns how many plaintext bytes fit in one query name
// given the session label and tunnel domain lengths. Used by the client to
// size its chunks. All lengths are in bytes; base32 expands 5 -> 8.
func MaxNamePayload(sessionLen, domainLen int) int {
	// A name is: <payload labels>.<session>.<domain>. Every label adds a
	// dot separator. We search downward for the largest plaintext size
	// whose encoded form fits the 253-byte DNS limit.
	for n := (253 - domainLen - sessionLen - 2) * 5 / 8; n > 0; n-- {
		if encodedNameLen(n, sessionLen, domainLen) <= 253 {
			return n
		}
	}
	return 0
}

// MaxUplinkFramePayload returns the largest frame payload that survives the
// uplink path in a single query name. The uplink record is
// seq(aeadSeqPrefix) + frameHeader + payload + poly1305Tag, all base32-encoded
// into the name; this subtracts the fixed overhead from MaxNamePayload.
//
// aeadSeqPrefix is the AEAD sequence prefix size (8) and aeadTag the
// Poly1305 tag size (16); both are provided by the crypto layer to avoid an
// import cycle.
func MaxUplinkFramePayload(sessionLen, domainLen, aeadSeqPrefix, aeadTag int) int {
	record := MaxNamePayload(sessionLen, domainLen)
	payload := record - aeadSeqPrefix - aeadTag - HeaderSize
	if payload < 0 {
		return 0
	}
	return payload
}

// encodedNameLen computes the DNS name length for n plaintext bytes once
// base32-encoded and split into labels of at most 63 bytes.
func encodedNameLen(n, sessionLen, domainLen int) int {
	chars := (n*8 + 4) / 5 // base32 length, rounded up
	if chars == 0 {
		return sessionLen + domainLen + 1
	}
	labels := (chars + 62) / 63 // payload label count
	// payload chars + (labels-1) intra-payload dots + dot before session
	// + session + dot before domain + domain
	return chars + (labels - 1) + 1 + sessionLen + 1 + domainLen
}
