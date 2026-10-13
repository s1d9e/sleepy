// Package pad implements length-hiding padding for tunnel records.
//
// Without padding, the size of each encrypted record leaks the size of the
// underlying frame: an observer correlating DoH query-name lengths can
// fingerprint message sizes (e.g. distinguish a keystroke from a file
// chunk). Padding pads every record to a bucket drawn from a small set of
// sizes, collapsing the granularity of the leak from "any byte count" to
// "one of N buckets".
//
// Wire format (before sealing):
//
//	+----------------+------------------------+-------------------+
//	| length (2 B BE)| payload (length bytes) | random padding    |
//	+----------------+------------------------+-------------------+
//	  \_________ padded to the next bucket size ___________/
//
// The length prefix is inside the AEAD plaintext, so padding is
// indistinguishable from payload once encrypted. Decryption reads the
// length and strips the padding.
package pad

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// Overhead is the number of bytes the padding framing adds (the length
// prefix). Callers sizing their buckets must account for it.
const Overhead = 2

// ErrTooLarge is returned when a payload cannot fit any bucket.
var ErrTooLarge = errors.New("pad: payload exceeds every bucket")

// Buckets is the default set of padded sizes, in bytes (total record
// plaintext including the length prefix). The set is deliberately coarse:
// finer buckets leak more, coarser buckets waste bandwidth. Chosen to span
// the realistic frame sizes from a keystroke to a full chunk.
var Buckets = []int{64, 128, 256, 512, 1024, 1400}

// Select returns the smallest bucket that can hold n bytes of payload plus
// the length prefix, or an error if n fits none.
func Select(n int, buckets []int) (int, error) {
	need := n + Overhead
	for _, b := range buckets {
		if b >= need {
			return b, nil
		}
	}
	return 0, fmt.Errorf("%w: %d bytes", ErrTooLarge, n)
}

// Pad pads payload to the smallest bucket that holds it, prepending the
// payload length. The trailing bytes are filled with cryptographically
// random data so an observer cannot distinguish padding from a genuine
// payload by byte distribution. If buckets is nil, the default set is used.
func Pad(payload []byte, buckets []int) ([]byte, error) {
	if buckets == nil {
		buckets = Buckets
	}
	if len(payload) > 0xFFFF {
		return nil, fmt.Errorf("pad: payload too large: %d", len(payload))
	}
	size, err := Select(len(payload), buckets)
	if err != nil {
		return nil, err
	}

	out := make([]byte, size)
	binary.BigEndian.PutUint16(out[:Overhead], uint16(len(payload)))
	copy(out[Overhead:], payload)

	// Fill the remainder with random bytes so the whole record reads as
	// high-entropy data once sealed.
	if padLen := size - Overhead - len(payload); padLen > 0 {
		if _, err := rand.Read(out[Overhead+len(payload):]); err != nil {
			return nil, fmt.Errorf("pad: fill: %w", err)
		}
	}
	return out, nil
}

// Unpad recovers the payload from a padded record, rejecting malformed
// lengths. The input is the decrypted plaintext.
func Unpad(record []byte) ([]byte, error) {
	if len(record) < Overhead {
		return nil, errors.New("pad: record shorter than length prefix")
	}
	n := int(binary.BigEndian.Uint16(record[:Overhead]))
	if n > len(record)-Overhead {
		return nil, fmt.Errorf("pad: declared length %d exceeds record payload %d", n, len(record)-Overhead)
	}
	out := make([]byte, n)
	copy(out, record[Overhead:Overhead+n])
	return out, nil
}

// Size returns the padded size for a payload of n bytes without allocating,
// so callers can pre-check that a padded record fits a transport limit
// (e.g. the DNS-name budget for uplink). Returns -1 if n fits no bucket.
func Size(n int, buckets []int) int {
	if buckets == nil {
		buckets = Buckets
	}
	size, err := Select(n, buckets)
	if err != nil {
		return -1
	}
	return size
}

// UplinkBuckets returns the subset of the default buckets that fit a
// transport budget, given the per-record overhead that the transport adds
// on top of the padded plaintext (for the DoH uplink: the AEAD sequence
// prefix and tag). Padding is only useful if at least one bucket fits; if
// the budget is too small for any default bucket, a minimal two-bucket set
// (small/medium) is returned so short frames still get their length masked
// without ever exceeding the budget.
//
// Callers pass overhead = crypto.SeqPrefixSize + crypto.Overhead and a
// budget = the transport's max record size (e.g. protocol.MaxNamePayload).
func UplinkBuckets(budget, overhead int) []int {
	maxPlaintext := budget - overhead
	if maxPlaintext <= 0 {
		return nil
	}
	var out []int
	for _, b := range Buckets {
		if b <= maxPlaintext {
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		// Budget too small for even the smallest default bucket: fall
		// back to a minimal set that still fits.
		small := 16
		if small > maxPlaintext {
			small = maxPlaintext
		}
		out = []int{small}
	}
	return out
}
