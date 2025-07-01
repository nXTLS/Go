// Copyright 2025 nXTLS contributors. MIT License.
// This file defines public types, constants, and helpers for XTLS mode support.
// It is intended to be imported and used by conn.go and related files.

package tls

import (
	"bytes"
	"net"
)

// XTLSMode describes the working mode for XTLS data flow.
type XTLSMode int

const (
	XTLSModeOrigin XTLSMode = iota // Strict monitoring (default)
	XTLSModeDirect                 // Direct, no monitoring after initial phase
)

// XTLS debug/logging helpers

// XTLSDebug outputs XTLS debug info if enabled.
func XTLSDebug(enabled bool, format string, args ...interface{}) {
	if enabled {
		msg := "[XTLS] " + format
		fmt.Printf(msg+"\n", args...)
	}
}

// XTLSAlertPattern is the trailing TLS1.2 alert used in Direct mode detection.
var XTLSAlertPattern = []byte{0x15, 0x03, 0x03, 0x00, 0x1a}

// StripTrailingAlert removes the trailing TLS1.2 alert from the buffer if present.
func StripTrailingAlert(b []byte) []byte {
	if len(b) >= len(XTLSAlertPattern) && bytes.Equal(b[len(b)-len(XTLSAlertPattern):], XTLSAlertPattern) {
		return b[:len(b)-len(XTLSAlertPattern)]
	}
	return b
}

// XTLSConnState holds XTLS-specific runtime state for a connection.
type XTLSConnState struct {
	Initialized    bool // Has XTLS mode detection completed?
	DirectReady    bool // Ready for full direct passthrough?
	OriginFallback bool // Fallback to origin logic on anomaly?
	ReadBypass     bool // All further reads are passthrough?
	WriteBypass    bool // All further writes are passthrough?
	DataTotal      int
	DataCount      int
	FirstPacket    bool
	ExpectLen      int
	MatchCount     int
	FallbackCount  int
	Debug          bool
}

// XTLSConn interface provides extension hooks for XTLS state
type XTLSConn interface {
	SetXTLSMode(mode XTLSMode)
	GetXTLSMode() XTLSMode
	EnableXTLSDebug(enable bool)
}

// EnableXTLSOnConn can be used to enable XTLS mode on a tls.Conn (or compatible)
func EnableXTLSOnConn(conn net.Conn, mode XTLSMode, debug bool) {
	if xtls, ok := conn.(XTLSConn); ok {
		xtls.SetXTLSMode(mode)
		xtls.EnableXTLSDebug(debug)
	}
}
