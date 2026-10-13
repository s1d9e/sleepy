package pad

import (
	"bytes"
	"testing"
)

func TestPadUnpadRoundTrip(t *testing.T) {
	// 0..1024 covers every realistic frame payload (protocol.MaxPayload
	// is 1024); 1398 is the exact maximum that fits the largest bucket
	// (1398 + Overhead == 1400).
	sizes := []int{0, 1, 15, 63, 64, 100, 200, 511, 512, 1000, 1024, 1398}
	for _, n := range sizes {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i * 7)
		}

		padded, err := Pad(payload, nil)
		if err != nil {
			t.Fatalf("Pad(%d): %v", n, err)
		}

		// Padded size must be a bucket size.
		if !isBucket(len(padded)) {
			t.Fatalf("Pad(%d): padded size %d is not a bucket", n, len(padded))
		}

		got, err := Unpad(padded)
		if err != nil {
			t.Fatalf("Unpad(%d): %v", n, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("round trip mismatch at n=%d", n)
		}
	}
}

func TestPadLengthHiding(t *testing.T) {
	// Two payloads of different sizes within the same bucket must produce
	// the same padded length.
	p1 := make([]byte, 10)
	p2 := make([]byte, 60)
	a, err := Pad(p1, nil)
	if err != nil {
		t.Fatalf("Pad: %v", err)
	}
	b, err := Pad(p2, nil)
	if err != nil {
		t.Fatalf("Pad: %v", err)
	}
	if len(a) != len(b) {
		t.Fatalf("lengths leak: %d vs %d", len(a), len(b))
	}
}

func TestPadRejectsTooLarge(t *testing.T) {
	huge := make([]byte, 2000)
	if _, err := Pad(huge, nil); err == nil {
		t.Fatal("Pad accepted payload larger than every bucket")
	}
}

func TestUnpadRejectsMalformed(t *testing.T) {
	// Declared length larger than the record.
	rec := []byte{0xFF, 0xFF, 0x01, 0x02}
	if _, err := Unpad(rec); err == nil {
		t.Fatal("Unpad accepted declared length exceeding record")
	}
	// Shorter than the prefix.
	if _, err := Unpad([]byte{0x01}); err == nil {
		t.Fatal("Unpad accepted record shorter than prefix")
	}
}

func TestSizeMatchesPad(t *testing.T) {
	// Iterate over every payload that fits the largest bucket
	// (1400 - Overhead == 1398); beyond that Pad correctly errors.
	maxFit := Buckets[len(Buckets)-1] - Overhead
	for n := 0; n <= maxFit; n++ {
		padded, err := Pad(make([]byte, n), nil)
		if err != nil {
			t.Fatalf("Pad(%d): %v", n, err)
		}
		if Size(n, nil) != len(padded) {
			t.Fatalf("Size(%d) != len(Pad)=%d", n, len(padded))
		}
	}
	// One byte past the largest bucket must be rejected, and Size must
	// agree by reporting -1.
	if _, err := Pad(make([]byte, maxFit+1), nil); err == nil {
		t.Fatalf("Pad accepted payload past the largest bucket")
	}
	if Size(maxFit+1, nil) != -1 {
		t.Fatalf("Size should report -1 for oversized payload")
	}
}

func TestUplinkBucketsFitBudget(t *testing.T) {
	// Simulate the DoH uplink budget: the AEAD adds seq(8)+tag(16)=24 bytes
	// on top of the padded plaintext, and the whole record is base32'd into
	// the DNS name. For a typical session/domain the name budget is ~140.
	budget := 140
	overhead := 8 + 16
	buckets := UplinkBuckets(budget, overhead)
	if len(buckets) == 0 {
		t.Fatal("no uplink buckets produced")
	}
	for _, b := range buckets {
		if b+overhead > budget {
			t.Fatalf("bucket %d + overhead %d exceeds budget %d", b, overhead, budget)
		}
	}

	// A tiny budget must still yield a usable (non-empty) bucket set.
	tiny := UplinkBuckets(30, 24)
	if len(tiny) == 0 {
		t.Fatal("tiny budget produced no buckets")
	}
	if tiny[len(tiny)-1] > 30-24 {
		t.Fatalf("tiny bucket %d exceeds tiny budget", tiny[len(tiny)-1])
	}

	// A hopeless budget (overhead >= budget) yields nil (disable padding).
	if got := UplinkBuckets(24, 24); got != nil {
		t.Fatalf("expected nil for zero-width budget, got %v", got)
	}
}

func isBucket(n int) bool {
	for _, b := range Buckets {
		if b == n {
			return true
		}
	}
	return false
}
