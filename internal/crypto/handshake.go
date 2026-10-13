// Package crypto implements the Sleepy handshake and record encryption.
//
// Handshake (mutual authentication via a pre-shared key):
//
//	Client -> Server:  magic || client_ephemeral_pub (32) || HMAC-SHA256(psk, magic||client_ephemeral_pub)
//	Server -> Client:  magic || server_ephemeral_pub (32) || HMAC-SHA256(psk, magic||server_ephemeral_pub||client_ephemeral_pub)
//
// Both sides derive the shared secret with X25519 and expand it with
// HKDF-SHA256 using the concatenation of both public keys as salt, yielding
// independent directional keys and nonce prefixes. Ephemeral keys give
// forward secrecy; the PSK authenticates both peers against a passive or
// active on-path attacker.
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// HandshakeSize is the size in bytes of a handshake message
// (magic || ephemeral public key || authentication tag).
const HandshakeSize = 8 + curve25519.PointSize + 32

var magic = [8]byte{'S', 'L', 'P', 'Y', '0', '0', '0', '1'}

// IsHandshake reports whether a record begins with the handshake magic.
// The server uses this to tell a fresh handshake apart from a data record,
// even when a session already exists for the label (which happens when a
// client re-handshakes after an outage). A sealed data record starts with
// an 8-byte big-endian sequence number; colliding with the magic would
// require seq == 0x534C505930303031 and a valid trailing HMAC, so the
// check is unambiguous in practice.
func IsHandshake(record []byte) bool {
	if len(record) < len(magic) {
		return false
	}
	return string(record[:len(magic)]) == string(magic[:])
}

// KeyLen is the length of a pre-shared key.
const KeyLen = 32

// Errors returned by the handshake.
var (
	ErrHandshakeSize    = errors.New("crypto: invalid handshake message size")
	ErrHandshakeMagic   = errors.New("crypto: invalid handshake magic")
	ErrHandshakeAuth    = errors.New("crypto: handshake authentication failed")
	ErrInvalidPublicKey = errors.New("crypto: invalid peer public key")
)

// Session holds the derived keys for one handshake epoch. Each direction is
// sealed with its own key and nonce prefix; the sequence counter is
// monotonic and must never repeat under the same key.
type Session struct {
	c2sKey []byte // client -> server AEAD key
	s2cKey []byte // server -> client AEAD key

	// NoncePrefixes are 4-byte per-direction prefixes. Full nonces are
	// prefix (4) || counter (8, big endian).
	c2sPrefix [4]byte
	s2cPrefix [4]byte

	// Ephemeral client state stashed between ClientHandshake and
	// CompleteClientHandshake.
	pendingClientPriv []byte
	pendingClientPub  []byte

	// Cached per-direction AEAD instances so sequence and anti-replay
	// state persist across calls.
	c2s, s2c *AEAD
}

// ClientHandshake performs the client side of the handshake, returning the
// message to send to the server and the resulting session.
func ClientHandshake(psk []byte) (msg []byte, sess *Session, err error) {
	if len(psk) != KeyLen {
		return nil, nil, fmt.Errorf("crypto: PSK must be exactly %d bytes", KeyLen)
	}

	var priv, pub [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, nil, fmt.Errorf("crypto: generate ephemeral key: %w", err)
	}
	curve25519.ScalarBaseMult(&pub, &priv)

	// magic || client_pub || HMAC(psk, magic||client_pub)
	body := append([]byte{}, magic[:]...)
	body = append(body, pub[:]...)
	mac := hmac.New(sha256.New, psk)
	mac.Write(body)
	msg = append(body, mac.Sum(nil)...)[:HandshakeSize]

	// The session is completed in CompleteClientHandshake once the server's
	// message is received; stash the private key for that step.
	sess = &Session{}
	sess.pendingClientPriv = priv[:]
	sess.pendingClientPub = pub[:]
	return msg, sess, nil
}

// CompleteClientHandshake processes the server's handshake message and
// derives the directional keys. It must be called exactly once, on the
// session returned by ClientHandshake.
func CompleteClientHandshake(psk []byte, sess *Session, serverMsg []byte) error {
	if len(psk) != KeyLen {
		return fmt.Errorf("crypto: PSK must be exactly %d bytes", KeyLen)
	}
	if len(serverMsg) != HandshakeSize {
		return ErrHandshakeSize
	}
	if string(serverMsg[:8]) != string(magic[:]) {
		return ErrHandshakeMagic
	}

	serverPub := serverMsg[8:40]
	mac := hmac.New(sha256.New, psk)
	mac.Write(magic[:])
	mac.Write(serverPub)
	mac.Write(sess.pendingClientPub)
	if !hmac.Equal(serverMsg[40:], mac.Sum(nil)) {
		return ErrHandshakeAuth
	}

	return deriveSession(sess, psk, sess.pendingClientPriv, serverPub, sess.pendingClientPub, serverPub)
}

// ServerHandshake processes the client's handshake message and returns the
// response to send plus the derived session.
func ServerHandshake(psk []byte, clientMsg []byte) (resp []byte, sess *Session, err error) {
	if len(psk) != KeyLen {
		return nil, nil, fmt.Errorf("crypto: PSK must be exactly %d bytes", KeyLen)
	}
	if len(clientMsg) != HandshakeSize {
		return nil, nil, ErrHandshakeSize
	}
	if string(clientMsg[:8]) != string(magic[:]) {
		return nil, nil, ErrHandshakeMagic
	}
	clientPub := clientMsg[8:40]
	mac := hmac.New(sha256.New, psk)
	mac.Write(clientMsg[:40])
	if !hmac.Equal(clientMsg[40:], mac.Sum(nil)) {
		return nil, nil, ErrHandshakeAuth
	}

	var priv, pub [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, nil, fmt.Errorf("crypto: generate ephemeral key: %w", err)
	}
	curve25519.ScalarBaseMult(&pub, &priv)

	body := append([]byte{}, magic[:]...)
	body = append(body, pub[:]...)
	mac = hmac.New(sha256.New, psk)
	mac.Write(magic[:])
	mac.Write(pub[:])
	mac.Write(clientPub)
	resp = append(body, mac.Sum(nil)...)[:HandshakeSize]

	sess = &Session{}
	if err := deriveSession(sess, psk, priv[:], clientPub, clientPub, pub[:]); err != nil {
		return nil, nil, err
	}
	return resp, sess, nil
}

// deriveSession expands the X25519 shared secret into directional keys. The
// public keys are always passed in canonical (client, server) order so both
// peers derive the same HKDF salt; remotePub identifies the peer key used
// for the X25519 agreement.
func deriveSession(sess *Session, psk, priv, remotePub, clientPub, serverPub []byte) error {
	var remote [32]byte
	copy(remote[:], remotePub)
	shared, err := curve25519.X25519(priv, remote[:])
	if err != nil {
		return ErrInvalidPublicKey
	}

	var zero [32]byte
	if subtleConstantTimeEqual(shared, zero[:]) {
		return ErrInvalidPublicKey
	}

	salt := sha256.Sum256(append(append([]byte{}, clientPub...), serverPub...))
	r := hkdf.New(sha256.New, shared[:], salt[:], []byte("sleepy-v1-directional"))

	sess.c2sKey = make([]byte, chacha20poly1305.KeySize)
	sess.s2cKey = make([]byte, chacha20poly1305.KeySize)
	if _, err := io_ReadFull(r, sess.c2sKey); err != nil {
		return err
	}
	if _, err := io_ReadFull(r, sess.s2cKey); err != nil {
		return err
	}
	if _, err := io_ReadFull(r, sess.c2sPrefix[:]); err != nil {
		return err
	}
	if _, err := io_ReadFull(r, sess.s2cPrefix[:]); err != nil {
		return err
	}
	// Eagerly build the per-direction AEADs so the session is safe for
	// concurrent use without lazy-init races.
	sess.c2s = newAEAD(sess.c2sKey, sess.c2sPrefix)
	sess.s2c = newAEAD(sess.s2cKey, sess.s2cPrefix)
	return nil
}

// Sealer returns the AEAD used by the given peer role for the client to
// server direction. The same instance is returned on every call so that
// sequence and anti-replay state persist.
func (s *Session) Sealer(client bool) *AEAD {
	if client {
		if s.c2s == nil {
			s.c2s = newAEAD(s.c2sKey, s.c2sPrefix)
		}
		return s.c2s
	}
	if s.s2c == nil {
		s.s2c = newAEAD(s.s2cKey, s.s2cPrefix)
	}
	return s.s2c
}

// Opener returns the AEAD used to open records sent by the peer of the
// given role. The same instance is returned on every call so that
// sequence and anti-replay state persist.
func (s *Session) Opener(client bool) *AEAD {
	if client {
		if s.s2c == nil {
			s.s2c = newAEAD(s.s2cKey, s.s2cPrefix)
		}
		return s.s2c
	}
	if s.c2s == nil {
		s.c2s = newAEAD(s.c2sKey, s.c2sPrefix)
	}
	return s.c2s
}

// io_ReadFull is io.ReadFull inlined for the hkdf reader without importing
// io at the top for a single use site.
func io_ReadFull(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// DerivePSK turns an arbitrary passphrase into a 32-byte PSK using
// HKDF-SHA256 with a fixed application salt. Callers should prefer
// supplying raw random keys; this convenience exists for --secret-key
// style flags.
func DerivePSK(passphrase string) []byte {
	r := hkdf.New(sha256.New, []byte(passphrase), []byte("sleepy-psk-v1"), []byte("psk"))
	key := make([]byte, KeyLen)
	_, _ = io_ReadFull(r, key)
	return key
}

// SequenceEncode appends a 64-bit sequence number to b. Exposed for
// tests and record framing.
func SequenceEncode(b []byte, seq uint64) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], seq)
	return append(b, tmp[:]...)
}

// subtleConstantTimeEqual reports whether a and b are equal in constant time.
func subtleConstantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
