// Package protocol implements the Sleepy wire protocol: a stream multiplexer
// that carries arbitrary TCP byte streams inside DNS messages, and a DNS
// codec that packs/unpacks protocol records into query names and TXT
// records.
//
// Frame layout (plaintext, before encryption):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|           Stream ID           |  Flags        |  Reserved     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|          Payload Length       |          Payload...           |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// A frame carries at most MaxPayload bytes of stream data. Frames from
// independent TCP connections are interleaved on the wire, identified by
// Stream ID, with per-stream flow control to avoid unbounded buffering.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// Frame header and payload constraints.
const (
	HeaderSize = 8

	// MaxPayload is the maximum frame payload. Chosen to fit comfortably
	// inside a DNS TXT record together with the framing overhead.
	MaxPayload = 1024

	// MaxStreamID is the largest usable stream identifier.
	MaxStreamID = 1<<16 - 1
)

// Flags bit assignments.
const (
	FlagSYN  byte = 1 << 0 // open a new stream, payload carries dial target
	FlagFIN  byte = 1 << 1 // half-close: no more data from sender
	FlagRST  byte = 1 << 2 // abrupt stream reset
	FlagData byte = 0      // plain data frame (no flags)
)

// Errors.
var (
	ErrFrameTooShort   = errors.New("protocol: frame shorter than header")
	ErrFrameTooLarge   = errors.New("protocol: frame payload exceeds limit")
	ErrBadStreamID     = errors.New("protocol: invalid stream ID")
	ErrStreamExhausted = errors.New("protocol: stream ID space exhausted")
)

// Frame is one multiplexed record.
type Frame struct {
	StreamID uint16
	Flags    byte
	Payload  []byte
}

// Encode appends the wire representation of f to dst and returns it.
func (f *Frame) Encode(dst []byte) ([]byte, error) {
	if f.StreamID == 0 || f.StreamID > MaxStreamID {
		return nil, ErrBadStreamID
	}
	if len(f.Payload) > MaxPayload {
		return nil, ErrFrameTooLarge
	}
	var hdr [HeaderSize]byte
	binary.BigEndian.PutUint16(hdr[0:2], f.StreamID)
	hdr[2] = f.Flags
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(f.Payload)))
	dst = append(dst, hdr[:]...)
	dst = append(dst, f.Payload...)
	return dst, nil
}

// DecodeFrame parses one frame from b, returning the frame and the number
// of bytes consumed.
func DecodeFrame(b []byte) (Frame, int, error) {
	if len(b) < HeaderSize {
		return Frame{}, 0, ErrFrameTooShort
	}
	sid := binary.BigEndian.Uint16(b[0:2])
	if sid == 0 || sid > MaxStreamID {
		return Frame{}, 0, ErrBadStreamID
	}
	flags := b[2]
	plen := int(binary.BigEndian.Uint16(b[4:6]))
	if plen > MaxPayload {
		return Frame{}, 0, ErrFrameTooLarge
	}
	if len(b) < HeaderSize+plen {
		return Frame{}, 0, fmt.Errorf("protocol: truncated payload: have %d want %d", len(b)-HeaderSize, plen)
	}
	payload := make([]byte, plen)
	copy(payload, b[HeaderSize:HeaderSize+plen])
	return Frame{StreamID: sid, Flags: flags, Payload: payload}, HeaderSize + plen, nil
}

// DialTarget builds the payload of a SYN frame: the TCP endpoint the
// server should connect to, in "host:port" form.
func DialTarget(host string, port uint16) []byte {
	return []byte(net.JoinHostPort(host, fmt.Sprintf("%d", port)))
}
