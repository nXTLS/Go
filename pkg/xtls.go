// MIT License: nXTLS compatibility package for XTLS API consumers.
// Provides an XTLS-like API surface for nXTLS users and legacy XTLS consumers.
// You can import this as "github.com/nXTLS/Go/pkg/xtls" and get familiar XTLS APIs
// without copyright risk.

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

// Flow modes compatible with XTLS conventions.
const (
	RPRXOrigin = "xtls-rprx-origin"
	RPRXDirect = "xtls-rprx-direct"
)

// Version constants for drop-in compatibility.
const (
	VersionTLS10 = tls.VersionTLS10
	VersionTLS11 = tls.VersionTLS11
	VersionTLS12 = tls.VersionTLS12
	VersionTLS13 = tls.VersionTLS13
)

// Config is a type alias for nXTLS Config, ensuring compatibility.
type Config = nxtls.Config

// Conn is a wrapper around nXTLS.Conn that provides XTLS-like API and flow logic.
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

// GetFlow gets the current flow control mode as a string.
func (c *Conn) GetFlow() string {
	return c.flow
}

// Handshake performs the TLS handshake (if not yet done).
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

// Read reads data, performing handshake if required.
func (c *Conn) Read(b []byte) (int, error) {
	if !c.handshook {
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

// Write writes data, performing handshake if required.
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

// SetReadDeadline sets the read deadline on the underlying connection.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// Underlying returns the inner nXTLS.Conn.
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

// Dial creates a client XTLS-compatible connection.
func Dial(network, addr string, config *Config) (*Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, config), nil
}

// DialTimeout is like Dial, but uses a timeout.
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

// EnableDebug enables debug on the underlying nXTLS.Conn (if supported).
func (c *Conn) EnableDebug(enable bool) {
	c.Conn.EnableXTLSDebug(enable)
}

// ConnectionState returns TLS connection state.
func (c *Conn) ConnectionState() tls.ConnectionState {
	return c.Conn.ConnectionState()
}

// OCSPResponse returns the stapled OCSP response from the TLS server, if any.
func (c *Conn) OCSPResponse() []byte {
	return c.Conn.OCSPResponse()
}

// VerifyHostname checks that the peer certificate chain is valid for connecting to the host.
func (c *Conn) VerifyHostname(host string) error {
	return c.Conn.VerifyHostname(host)
}

// ExportKeyingMaterial delegates to nXTLS if supported.
func (c *Conn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	if ekm := c.Conn.EKM; ekm != nil {
		return ekm(label, context, length)
	}
	return nil, errors.New("xtls: EKM not supported")
}

// Copy copies between two XTLS conns or any io.Reader/io.Writer, using nXTLS direct protection.
func Copy(dst io.Writer, src io.Reader) (written int64, err error) {
	return io.Copy(dst, src)
}
