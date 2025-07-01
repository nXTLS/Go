// Copyright 2025 nXTLS contributors. MIT License.
// Detailed, robust XTLS mode definitions and helpers for Origin/Direct logic.
// This file should be imported by conn.go and related files.

package tls

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// XTLSMode describes the working mode for XTLS data flow.
type XTLSMode int

const (
	XTLSModeOrigin XTLSMode = iota // Full protocol monitoring and fallback
	XTLSModeDirect                 // Minimal monitoring, maximum performance
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

// XTLSAlertPattern is a set of known TLS1.2 alert record patterns that should be stripped in direct mode.
var XTLSAlertPatterns = [][]byte{
	// Standard close_notify (21 3 3 0 2 1 0)
	{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00},
	// Some implementations use larger or different alert records, so match all starting with alert header.
	{0x15, 0x03, 0x03},
}

// IsXTLSAlertRecord checks if a given slice starts with a TLS alert record header (21 3 3 ...).
func IsXTLSAlertRecord(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	return data[0] == 0x15 && data[1] == 0x03 && data[2] == 0x03
}

// FindTrailingAlert returns the index and length of trailing alert record(s) to be stripped for XTLS direct mode.
// It handles variable-length alert records and multiple trailing alerts.
func FindTrailingAlert(data []byte) (idx int, alertLen int) {
	if len(data) < 5 {
		return -1, 0
	}
	i := len(data) - 5
	for i >= 0 {
		if data[i] == 0x15 && data[i+1] == 0x03 && data[i+2] == 0x03 {
			length := int(data[i+3])<<8 | int(data[i+4])
			end := i + 5 + length
			if end == len(data) && length > 0 && length <= 256 {
				return i, 5 + length
			}
		}
		i--
	}
	return -1, 0
}

// StripAllTrailingAlerts strips all trailing alert records for XTLS direct mode.
func StripAllTrailingAlerts(data []byte) ([]byte, int) {
	n := 0
	for {
		idx, alertLen := FindTrailingAlert(data)
		if idx != -1 && idx+alertLen == len(data) {
			data = data[:idx]
			n++
		} else {
			break
		}
	}
	return data, n
}

// XTLSDebug outputs XTLS debug info if enabled.
func XTLSDebug(enabled bool, format string, args ...interface{}) {
	if enabled {
		msg := "[XTLS] " + format
		fmt.Printf(msg+"\n", args...)
	}
}

// XTLSConnState holds XTLS-specific runtime state for a connection.
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

// XTLSWriteDirect safely strips all trailing alert records in direct mode, and prevents
// any close_notify or other alert(s) from being sent to peer, regardless of record size,
// as per best current practice and to mitigate detection risks.
// Returns the number of alert records stripped.
func XTLSWriteDirect(conn net.Conn, data []byte, debug bool) (int, error) {
	// Remove all trailing alert records, regardless of length
	safeData, numAlerts := StripAllTrailingAlerts(data)
	if debug && numAlerts > 0 {
		XTLSDebug(debug, "Stripped %d trailing alert record(s) in direct mode", numAlerts)
	}
	n, err := conn.Write(safeData)
	if err != nil {
		return n, err
	}
	// We report API as if we wrote the full original buffer (for TLS compatibility)
	return n + len(data) - len(safeData), nil
}

// XTLSReadDirect is a passthrough read for direct mode, for completeness.
func XTLSReadDirect(conn net.Conn, b []byte) (int, error) {
	return conn.Read(b)
}

// XTLSProxy copies from src to dst using XTLS direct logic (for tunnels, etc).
func XTLSProxy(dst, src net.Conn, debug bool) (written int64, err error) {
	buf := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			ndata, _ := StripAllTrailingAlerts(buf[:nr])
			nw, ew := dst.Write(ndata)
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
		}
		if er != nil {
			if er != io.EOF {
				XTLSDebug(debug, "Proxy read error: %v", er)
			}
			break
		}
	}
	return written, nil
}
