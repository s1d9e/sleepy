package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestHandshakeRoundTrip(t *testing.T) {
	psk := DerivePSK("unit-test-passphrase")

	cMsg, cSess, err := ClientHandshake(psk)
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	if len(cMsg) != HandshakeSize {
		t.Fatalf("client msg size = %d, want %d", len(cMsg), HandshakeSize)
	}

	sMsg, sSess, err := ServerHandshake(psk, cMsg)
	if err != nil {
		t.Fatalf("ServerHandshake: %v", err)
	}
	if err := CompleteClientHandshake(psk, cSess, sMsg); err != nil {
		t.Fatalf("CompleteClientHandshake: %v", err)
	}

	// Both sides must agree: client seals, server opens.
	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	record, err := cSess.Sealer(true).Seal(plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := sSess.Opener(false).Open(record)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: %q != %q", got, plaintext)
	}

	// And the other direction.
	record, err = sSess.Sealer(false).Seal(plaintext)
	if err != nil {
		t.Fatalf("Seal reverse: %v", err)
	}
	got, err = cSess.Opener(true).Open(record)
	if err != nil {
		t.Fatalf("Open reverse: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("reverse round trip mismatch")
	}
}

func TestHandshakeWrongPSK(t *testing.T) {
	psk := DerivePSK("correct")
	other := DerivePSK("wrong")

	cMsg, _, err := ClientHandshake(psk)
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	if _, _, err := ServerHandshake(other, cMsg); err == nil {
		t.Fatal("server accepted handshake with wrong PSK")
	}
}

func TestHandshakeTampered(t *testing.T) {
	psk := DerivePSK("unit-test")
	cMsg, _, err := ClientHandshake(psk)
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}

	// Flip a bit in the ephemeral public key.
	tampered := append([]byte{}, cMsg...)
	tampered[10] ^= 0x01
	if _, _, err := ServerHandshake(psk, tampered); err == nil {
		t.Fatal("server accepted tampered handshake")
	}

	// Bad magic.
	badMagic := append([]byte{}, cMsg...)
	badMagic[0] = 'X'
	if _, _, err := ServerHandshake(psk, badMagic); err == nil {
		t.Fatal("server accepted bad magic")
	}

	// Truncated.
	if _, _, err := ServerHandshake(psk, cMsg[:10]); err == nil {
		t.Fatal("server accepted truncated handshake")
	}
}

func TestAEADReplayRejected(t *testing.T) {
	psk := DerivePSK("unit-test")
	cMsg, cSess, _ := ClientHandshake(psk)
	sMsg, sSess, err := ServerHandshake(psk, cMsg)
	if err != nil {
		t.Fatalf("ServerHandshake: %v", err)
	}
	if err := CompleteClientHandshake(psk, cSess, sMsg); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	sent, err := cSess.Sealer(true).Seal([]byte("hello"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := sSess.Opener(false).Open(sent); err != nil {
		t.Fatalf("first open should succeed: %v", err)
	}
	if _, err := sSess.Opener(false).Open(sent); err == nil {
		t.Fatal("replayed record accepted")
	}
}

func mustClientMsg(t *testing.T, psk []byte) []byte {
	t.Helper()
	msg, _, err := ClientHandshake(psk)
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	return msg
}

func TestAEADTamperRejected(t *testing.T) {
	psk := DerivePSK("unit-test")
	cMsg, cSess, _ := ClientHandshake(psk)
	sMsg, sSess, err := ServerHandshake(psk, cMsg)
	if err != nil {
		t.Fatalf("ServerHandshake: %v", err)
	}
	if err := CompleteClientHandshake(psk, cSess, sMsg); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	record, err := cSess.Sealer(true).Seal([]byte("sensitive payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Flip a bit in the ciphertext.
	record[len(record)-1] ^= 0x01
	if _, err := sSess.Opener(false).Open(record); err == nil {
		t.Fatal("tampered record accepted")
	}
}

func TestUniqueKeysPerHandshake(t *testing.T) {
	psk := DerivePSK("unit-test")
	_, s1, err := ServerHandshake(psk, mustClientMsg(t, psk))
	if err != nil {
		t.Fatalf("handshake 1: %v", err)
	}
	_, s2, err := ServerHandshake(psk, mustClientMsg(t, psk))
	if err != nil {
		t.Fatalf("handshake 2: %v", err)
	}

	r1, _ := s1.Sealer(false).Seal([]byte("same plaintext"))
	r2, _ := s2.Sealer(false).Seal([]byte("same plaintext"))
	if bytes.Equal(r1, r2) {
		t.Fatal("two sessions produced identical ciphertext for the same plaintext (nonce reuse!)")
	}
}

func TestSealLargePayload(t *testing.T) {
	psk := DerivePSK("unit-test")
	cMsg, cSess, _ := ClientHandshake(psk)
	sMsg, sSess, err := ServerHandshake(psk, cMsg)
	if err != nil {
		t.Fatalf("ServerHandshake: %v", err)
	}
	if err := CompleteClientHandshake(psk, cSess, sMsg); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	big := make([]byte, 4096)
	if _, err := rand.Read(big); err != nil {
		t.Fatalf("rand: %v", err)
	}
	record, err := cSess.Sealer(true).Seal(big)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := sSess.Opener(false).Open(record)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, big) {
		t.Fatal("large payload round trip mismatch")
	}
}
