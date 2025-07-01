// Copyright 2025 nXTLS contributors. MIT License.
// This file provides the detailed and robust XTLS operation modes, helpers, detection,
// and state tracking, written with a modern, idiomatic Go style and fully original implementation.
// All definitions are designed to be directly compatible with conn.go and the nXTLS framework.

package tls

import (
	"fmt"
	"net"
	"sync"
	"time"
	"io"
)

// XTLSMode describes the transmission mode of the XTLS protocol.
type XTLSMode int

const (
	XTLSModeOrigin XTLSMode = iota // Thorough protocol inspection, best for security and compatibility.
	XTLSModeDirect                 // Minimal inspection, maximal performance.
)

// String returns a human-readable string for XTLSMode.
func (mode XTLSMode) String() string {
	switch mode {
	case XTLSModeOrigin:
		return "Origin"
	case XTLSModeDirect:
		return "Direct"
	default:
		return "Unknown"
	}
}

// KnownAlertHeaders represents classic TLS alert record headers for detection.
var KnownAlertHeaders = [][]byte{
	{0x15, 0x03, 0x03}, // TLS1.2 alert
}

// IsAlertRecordHeader reports whether the buffer at pos starts with a known alert header.
func IsAlertRecordHeader(buf []byte, pos int) bool {
	if len(buf)-pos < 5 {
		return false
	}
	for _, header := range KnownAlertHeaders {
		match := true
		for i, b := range header {
			if buf[pos+i] != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// FindAllTrailingAlerts scans from the end and returns a slice excluding all trailing alert records.
func FindAllTrailingAlerts(buf []byte) (head []byte, alertCount int) {
	pos := len(buf)
	for pos >= 5 {
		// look for possible alert record at pos-5
		start := pos - 5
		if !IsAlertRecordHeader(buf, start) {
			break
		}
		length := int(buf[start+3])<<8 | int(buf[start+4])
		if start+5+length != pos || length <= 0 || length > 256 {
			break
		}
		pos = start
		alertCount++
	}
	return buf[:pos], alertCount
}

// RemoveAllTrailingAlerts strips all TLS alert records at the end and returns the main data and strip count.
func RemoveAllTrailingAlerts(data []byte) ([]byte, int) {
	return FindAllTrailingAlerts(data)
}

// XTLSDebug emits formatted debug output if enabled.
func XTLSDebug(enabled bool, format string, v ...interface{}) {
	if enabled {
		fmt.Printf("[XTLS] "+format+"\n", v...)
	}
}

// XTLSConnState tracks XTLS-specific runtime status for one connection.
// All updates must be protected by Lock/Unlock for thread safety.
type XTLSConnState struct {
	sync.Mutex

	Initialized    bool // Has XTLS mode been detected/negotiated?
	DirectReady    bool // Ready to enter full Direct mode bypass?
	OriginFallback bool // Using the fallback Origin logic due to anomaly?
	ReadBypass     bool // Reads are now passthrough (Direct)
	WriteBypass    bool // Writes are now passthrough (Direct)
	DataTotal      int  // For origin/direct transition logic (bytes expected)
	DataCount      int  // Counter for processed bytes
	FirstPacket    bool // For protocol signature detection
	ExpectLen      int  // Expected length for direct transition
	MatchCount     int  // Protocol signature confirmation
	FallbackCount  int  // Fallback trigger counter
	Debug          bool // Enable or disable debug output
	LastTransition time.Time // Timestamp of last state change
}

// XTLSConn defines the interface for connections that support XTLS extensions.
type XTLSConn interface {
	SetXTLSMode(mode XTLSMode)
	GetXTLSMode() XTLSMode
	EnableXTLSDebug(enable bool)
	GetXTLSState() *XTLSConnState
}

// EnableXTLS enables XTLS mode and debug on a compatible connection.
func EnableXTLS(conn net.Conn, mode XTLSMode, debug bool) {
	if x, ok := conn.(XTLSConn); ok {
		x.SetXTLSMode(mode)
		x.EnableXTLSDebug(debug)
	}
}

// ParseXTLSMode converts a string to XTLSMode; defaults to Origin.
func ParseXTLSMode(s string) XTLSMode {
	switch s {
	case "Direct", "direct", "DIRECT":
		return XTLSModeDirect
	case "Origin", "origin", "ORIGIN":
		fallthrough
	default:
		return XTLSModeOrigin
	}
}

// UpdateXTLSState changes a boolean state flag and logs if debug enabled.
func UpdateXTLSState(state *XTLSConnState, field string, value bool) {
	state.Lock()
	defer state.Unlock()
	state.LastTransition = time.Now()
	switch field {
	case "DirectReady":
		state.DirectReady = value
	case "OriginFallback":
		state.OriginFallback = value
	case "ReadBypass":
		state.ReadBypass = value
	case "WriteBypass":
		state.WriteBypass = value
	}
	if state.Debug {
		fmt.Printf("[XTLS] State update: %s = %v at %s\n", field, value, state.LastTransition.Format(time.RFC3339))
	}
}

// DumpXTLSState prints the current state (for diagnostics).
func DumpXTLSState(state *XTLSConnState) {
	state.Lock()
	defer state.Unlock()
	fmt.Printf("[XTLS] Conn State: %+v\n", *state)
}

// XTLSWriteDirect strips all trailing alert records and writes safe data to conn.
// Returns total bytes (including stripped alerts) for API consistency.
func XTLSWriteDirect(conn net.Conn, buf []byte, debug bool) (int, error) {
	main, count := RemoveAllTrailingAlerts(buf)
	if count > 0 && debug {
		XTLSDebug(debug, "Removed %d trailing alert record(s)", count)
	}
	n, err := conn.Write(main)
	if err != nil {
		return n, err
	}
	return n + len(buf) - len(main), nil
}

// XTLSReadDirect is a passthrough read (Direct mode).
func XTLSReadDirect(conn net.Conn, b []byte) (int, error) {
	return conn.Read(b)
}

// XTLSCopyConn copies data from src to dst with XTLS direct mode alert stripping.
func XTLSCopyConn(dst, src net.Conn, debug bool) (written int64, err error) {
	buffer := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buffer)
		if nr > 0 {
			data, _ := RemoveAllTrailingAlerts(buffer[:nr])
			nw, ew := dst.Write(data)
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
		}
		if er != nil {
			if er != io.EOF {
				XTLSDebug(debug, "XTLSCopyConn read error: %v", er)
			}
			break
		}
	}
	return written, nil
}
