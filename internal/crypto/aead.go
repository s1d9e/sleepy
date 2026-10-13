package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD seals and opens records for one direction of a session. The nonce is
// built from a 4-byte random prefix fixed at handshake time and a 64-bit
// counter, guaranteeing uniqueness without transmitting nonces. Records are
// additionally bound to their sequence number via AAD, which defeats
// replay and reordering by an on-path attacker.
//
// AEAD is safe for concurrent use.
type AEAD struct {
	aead   cipher.AEAD
	prefix [4]byte

	mu   sync.Mutex
	seq  uint64
	max  uint64
	sent bool
}

const (
	// Overhead is the Poly1305 tag size appended to every sealed record.
	Overhead = chacha20poly1305.Overhead

	// SeqPrefixSize is the size in bytes of the big-endian sequence number
	// that prefixes every sealed record (and doubles as its AAD).
	SeqPrefixSize = 8

	// MaxSeq is the maximum sequence number; the session must be
	// re-keyed before this value is reached.
	MaxSeq = 1<<64 - 2
)

func newAEAD(key []byte, prefix [4]byte) *AEAD {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		// Key length is fixed by construction; unreachable.
		panic(fmt.Sprintf("crypto: %v", err))
	}
	return &AEAD{aead: a, prefix: prefix}
}

// Seal encrypts plaintext, returning a record of len(seq)+len(plaintext)+Overhead.
func (s *AEAD) Seal(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	if s.seq >= MaxSeq {
		s.mu.Unlock()
		return nil, fmt.Errorf("crypto: sequence space exhausted, re-key required")
	}
	seq := s.seq
	s.seq++
	s.mu.Unlock()

	out := make([]byte, SeqPrefixSize, SeqPrefixSize+len(plaintext)+Overhead)
	binary.BigEndian.PutUint64(out, seq)

	nonce := s.nonce(seq)
	aad := out[:SeqPrefixSize] // the sequence number doubles as AAD
	out = s.aead.Seal(out, nonce, plaintext, aad)
	return out, nil
}

// Open decrypts a record produced by Seal on the peer side. It returns the
// plaintext and fails on tampering, replay, or reordering.
func (s *AEAD) Open(record []byte) ([]byte, error) {
	if len(record) < SeqPrefixSize+Overhead {
		return nil, fmt.Errorf("crypto: record too short")
	}
	seq := binary.BigEndian.Uint64(record[:SeqPrefixSize])

	s.mu.Lock()
	if !s.sent {
		// First record establishes the expected starting sequence.
		s.sent = true
		s.max = seq
	} else if seq <= s.max {
		s.mu.Unlock()
		return nil, fmt.Errorf("crypto: replayed or reordered record (seq %d)", seq)
	} else {
		s.max = seq
	}
	s.mu.Unlock()

	nonce := s.nonce(seq)
	plaintext, err := s.aead.Open(nil, nonce, record[SeqPrefixSize:], record[:SeqPrefixSize])
	if err != nil {
		return nil, fmt.Errorf("crypto: authentication failed: %w", err)
	}
	return plaintext, nil
}

// Seq returns the next sequence number that will be used by Seal.
func (s *AEAD) Seq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

func (s *AEAD) nonce(seq uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	copy(n[:4], s.prefix[:])
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}
