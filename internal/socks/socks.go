// Package socks implements a minimal SOCKS5 server (RFC 1928) that accepts
// TCP connections and hands each one to a handler, which the tunnel layer
// wires to a remote stream.
//
// Only the CONNECT command and NO AUTHENTICATION are supported — enough to
// drive ssh, curl, and browsers through the tunnel.
package socks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Command codes.
const (
	cmdConnect = 0x01
)

// Address types.
const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// Reply codes.
const (
	replySuccess           = 0x00
	replyGeneralFailure    = 0x01
	replyNotAllowed        = 0x02
	replyNetworkUnreach    = 0x03
	replyHostUnreach       = 0x04
	replyConnectionRefused = 0x05
)

// Request is a parsed CONNECT request.
type Request struct {
	Host string
	Port uint16
}

// Handler dials the target and returns a ReadWriteCloser to the remote, or
// an error. The tunnel layer supplies this.
type Handler func(host string, port uint16) (io.ReadWriteCloser, error)

// Serve accepts connections on ln and services SOCKS5 handshakes, passing
// each established tunnel stream to handler. It returns when ln is closed.
func Serve(ln net.Listener, handler Handler) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			_ = handleConn(c, handler)
		}(conn)
	}
}

func handleConn(conn net.Conn, handler Handler) error {
	defer conn.Close()

	// Greeting: VER NMETHODS METHODS...
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("socks: not SOCKS5")
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	// Reply: select NO AUTH (0x00).
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}

	// Request: VER CMD RSV ATYP ADDR PORT.
	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil {
		return err
	}
	if req[0] != 0x05 {
		return fmt.Errorf("socks: bad version")
	}
	if req[1] != cmdConnect {
		writeReply(conn, replyNotAllowed, nil)
		return fmt.Errorf("socks: unsupported command %d", req[1])
	}

	var host string
	switch req[3] {
	case atypIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return err
		}
		host = net.IP(ip[:]).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		d := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, d); err != nil {
			return err
		}
		host = string(d)
	case atypIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return err
		}
		host = net.IP(ip[:]).String()
	default:
		writeReply(conn, replyGeneralFailure, nil)
		return fmt.Errorf("socks: bad address type %d", req[3])
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	remote, err := handler(host, port)
	if err != nil {
		writeReply(conn, replyHostUnreach, nil)
		return err
	}
	defer remote.Close()

	if err := writeReply(conn, replySuccess, remote); err != nil {
		return err
	}

	// Bidirectional relay.
	errc := make(chan error, 2)
	go func() { _, e := io.Copy(remote, conn); errc <- e }()
	go func() { _, e := io.Copy(conn, remote); errc <- e }()
	<-errc
	return nil
}

// writeReply sends a SOCKS5 reply. When remote is non-nil its local
// address is used as the bound address; otherwise 0.0.0.0:0.
func writeReply(conn net.Conn, code byte, remote io.ReadWriteCloser) error {
	resp := []byte{0x05, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	if remote != nil {
		if c, ok := remote.(interface{ LocalAddr() net.Addr }); ok {
			if ta, ok := c.LocalAddr().(*net.TCPAddr); ok {
				if ip4 := ta.IP.To4(); ip4 != nil {
					copy(resp[4:8], ip4)
				}
				binary.BigEndian.PutUint16(resp[8:10], uint16(ta.Port))
			}
		}
	}
	_, err := conn.Write(resp)
	return err
}
