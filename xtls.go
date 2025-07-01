// Copyright 2025 nXTLS contributors. MIT License.
// This file defines public types, constants, helpers, and state for XTLS mode support
// Intended to be imported and used by conn.go and related files, and is production-ready.

package tls

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"
)

// XTLSMode describes the working mode for XTLS data flow.
type XTLSMode int

const (
	XTLSModeOrigin XTLSMode = iota // Strict monitoring (default, more secure)
	XTLSModeDirect                 // Direct, minimal monitoring, maximum performance
)

func (m XTLSMode) String() string {
	switch m {
	case XTLSModeOrigin:
		return "Origin"
	case XTLSModeDirect:
		return "Direct"
	default:
		return "Unknown"
	}
}

// XTLSAlertPattern is the trailing TLS1.2 alert used in Direct mode detection (21 3 3 0 26).
var XTLSAlertPattern = []byte{0x15, 0x03, 0x03, 0x00, 0x1a}

// StripTrailingAlert removes the trailing TLS1.2 alert from the buffer if present.
func StripTrailingAlert(b []byte) (stripped []byte, removed bool) {
	if len(b) >= len(XTLSAlertPattern) && bytes.Equal(b[len(b)-len(XTLSAlertPattern):], XTLSAlertPattern) {
		return b[:len(b)-len(XTLSAlertPattern)], true
	}
	return b, false
}

// XTLSDebug outputs XTLS debug info if enabled.
func XTLSDebug(enabled bool, format string, args ...interface{}) {
	if enabled {
		msg := "[XTLS] " + format
		fmt.Printf(msg+"\n", args...)
	}
}

// XTLSConnState holds XTLS-specific runtime state for a connection.
// All fields are safe for concurrent read, writes guarded by mutex.
type XTLSConnState struct {
	sync.Mutex

	Initialized    bool // Has XTLS mode detection completed?
	DirectReady    bool // Ready for full direct passthrough?
	OriginFallback bool // Fallback to origin logic on anomaly?
	ReadBypass     bool // All further reads are passthrough?
	WriteBypass    bool // All further writes are passthrough?
	DataTotal      int  // Total data expected (for direct mode transition)
	DataCount      int  // How much data has been processed so far
	FirstPacket    bool // Is this the first data packet?
	ExpectLen      int  // Expected length for direct transition
	MatchCount     int  // For protocol signature matching
	FallbackCount  int  // Number of times fallback triggered
	Debug          bool // Enable debug output

	LastTransition time.Time // For diagnostics
}

// XTLSConn interface provides extension hooks for XTLS state.
type XTLSConn interface {
	SetXTLSMode(mode XTLSMode)
	GetXTLSMode() XTLSMode
	EnableXTLSDebug(enable bool)
	GetXTLSState() *XTLSConnState
}

// EnableXTLSOnConn can be used to enable XTLS mode on a tls.Conn (or compatible).
func EnableXTLSOnConn(conn net.Conn, mode XTLSMode, debug bool) {
	if xtls, ok := conn.(XTLSConn); ok {
		xtls.SetXTLSMode(mode)
		xtls.EnableXTLSDebug(debug)
	}
}

// XTLSModeFromString parses a string to XTLSMode.
func XTLSModeFromString(s string) XTLSMode {
	switch s {
	case "Origin", "origin", "ORIGIN":
		return XTLSModeOrigin
	case "Direct", "direct", "DIRECT":
		return XTLSModeDirect
	default:
		return XTLSModeOrigin // Default to Origin for safety
	}
}

// XTLSStateTransition transitions the connection to a new XTLS state, logs if debug enabled.
func XTLSStateTransition(state *XTLSConnState, field string, val bool) {
	state.Lock()
	defer state.Unlock()
	state.LastTransition = time.Now()
	switch field {
	case "DirectReady":
		state.DirectReady = val
	case "OriginFallback":
		state.OriginFallback = val
	case "ReadBypass":
		state.ReadBypass = val
	case "WriteBypass":
		state.WriteBypass = val
	}
	if state.Debug {
		fmt.Printf("[XTLS] State transition: %s -> %v at %s\n", field, val, state.LastTransition.Format(time.RFC3339))
	}
}

// XTLSDumpState prints the current XTLSConnState (for debugging).
func XTLSDumpState(state *XTLSConnState) {
	state.Lock()
	defer state.Unlock()
	fmt.Printf("[XTLS] Current State: %+v\n", *state)
}
