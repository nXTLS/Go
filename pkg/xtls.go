// MIT License: nXTLS compatibility glue for XTLS API consumers.
// Provides an XTLS-like API surface over nXTLS for legacy and new projects.

package xtls

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	nxtls "github.com/nXTLS/Go"
)

// Flow control mode constants compatible with XTLS conventions.
const (
	RPRXOrigin = "xtls-rprx-origin"
	RPRXDirect = "xtls-rprx-direct"
)

// TLS protocol version constants for compatibility.
const (
	VersionTLS10 = tls.VersionTLS10
	VersionTLS11 = tls.VersionTLS11
	VersionTLS12 = tls.VersionTLS12
	VersionTLS13 = tls.VersionTLS13
)

// Config is a type alias for nXTLS Config, for compatibility.
type Config = nxtls.Config

// Conn wraps nXTLS.Conn to present an XTLS-like API and flow logic.
type Conn struct {
	*nxtls.Conn
	flow      string
	handshook bool
}

// SetFlow sets the flow control mode (origin/direct) for this connection.
func (c *Conn) SetFlow(flow string) {
	c.flow = flow
	switch strings.ToLower(flow) {
	case RPRXDirect:
		c.Conn.SetXTLSMode(nxtls.XTLSModeDirect)
	case RPRXOrigin:
		c.Conn.SetXTLSMode(nxtls.XTLSModeOrigin)
	default:
		c.Conn.SetXTLSMode(nxtls.XTLSModeOrigin)
	}
}

// GetFlow returns the current flow control mode as a string.
func (c *Conn) GetFlow() string {
	return c.flow
}

// Handshake performs the TLS handshake if it has not yet been performed.
func (c *Conn) Handshake() error {
	if c.handshook {
		return nil
	}
	err := c.Conn.Handshake()
	if err == nil {
		c.handshook = true
	}
	return err
}

// Read reads data from the connection, performing handshake if necessary.
func (c *Conn) Read(b []byte) (int, error) {
	if !c.handshook {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

// Write writes data to the connection, performing handshake if necessary.
func (c *Conn) Write(b []byte) (int, error) {
	if !c.handshook {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(b)
}

// Close closes the connection.
func (c *Conn) Close() error {
	return c.Conn.Close()
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the connection.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the connection.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// Underlying returns the inner nXTLS.Conn for advanced use.
func (c *Conn) Underlying() *nxtls.Conn {
	return c.Conn
}

// NewConn creates an XTLS-compatible connection from a net.Conn and config.
func NewConn(conn net.Conn, config *Config) *Conn {
	nconn := nxtls.Client(conn, config)
	return &Conn{
		Conn: nconn,
		flow: RPRXOrigin,
	}
}

// Dial creates a client XTLS-compatible connection to the specified address.
func Dial(network, addr string, config *Config) (*Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, config), nil
}

// DialTimeout is like Dial, but uses a timeout for the connection phase.
func DialTimeout(network, addr string, timeout time.Duration, config *Config) (*Conn, error) {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, config), nil
}

// Listen returns a listener that accepts XTLS-compatible connections.
func Listen(network, addr string, config *Config) (net.Listener, error) {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return &listener{Listener: ln, config: config}, nil
}

// listener implements net.Listener to wrap accepted connections as *xtls.Conn.
type listener struct {
	net.Listener
	config *Config
}

// Accept returns an XTLS-compatible connection.
func (l *listener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewConn(raw, l.config), nil
}

// EnableDebug enables debug on the underlying nXTLS.Conn.
func (c *Conn) EnableDebug(enable bool) {
	c.Conn.EnableXTLSDebug(enable)
}

// ConnectionState returns the TLS connection state as crypto/tls.ConnectionState.
// It maps fields from nXTLS.ConnectionState to crypto/tls.ConnectionState.
func (c *Conn) ConnectionState() tls.ConnectionState {
	nc := c.Conn.ConnectionState()
	return toStdConnectionState(nc)
}

// toStdConnectionState maps nXTLS.ConnectionState to crypto/tls.ConnectionState.
func toStdConnectionState(nc nxtls.ConnectionState) tls.ConnectionState {
	return tls.ConnectionState{
		Version:                     nc.Version,
		HandshakeComplete:           nc.HandshakeComplete,
		DidResume:                   nc.DidResume,
		CipherSuite:                 nc.CipherSuite,
		NegotiatedProtocol:          nc.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  nc.NegotiatedProtocolIsMutual,
		ServerName:                  nc.ServerName,
		PeerCertificates:            nc.PeerCertificates,
		VerifiedChains:              nc.VerifiedChains,
		SignedCertificateTimestamps: nc.SignedCertificateTimestamps,
		OCSPResponse:                nc.OCSPResponse,
		TLSUnique:                   nc.TLSUnique,
	}
}

// OCSPResponse returns the stapled OCSP response from the TLS server, if any.
func (c *Conn) OCSPResponse() []byte {
	return c.Conn.OCSPResponse()
}

// VerifyHostname checks that the peer certificate chain is valid for connecting to the host.
func (c *Conn) VerifyHostname(host string) error {
	return c.Conn.VerifyHostname(host)
}

// ExportKeyingMaterial delegates to nXTLS.ConnectionState if supported.
func (c *Conn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	state := c.Conn.ConnectionState()
	// Check for method existence, otherwise return error.
	type ekmIface interface {
		ExportKeyingMaterial(string, []byte, int) ([]byte, error)
	}
	if ekm, ok := interface{}(&state).(ekmIface); ok {
		return ekm.ExportKeyingMaterial(label, context, length)
	}
	return nil, errors.New("xtls: ExportKeyingMaterial not supported in this build")
}

// Copy copies between two XTLS conns or any io.Reader/io.Writer, using io.Copy.
func Copy(dst io.Writer, src io.Reader) (written int64, err error) {
	return io.Copy(dst, src)
}
