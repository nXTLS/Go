// Copyright 2025 nXTLS contributors. MIT License.
// Unit tests for XTLS mode and helper functions.

package tls

import (
	"bytes"
	"testing"
	"time"
)

// Test XTLSMode String() and parsing
func TestXTLSModeStringAndParse(t *testing.T) {
	if XTLSModeOrigin.String() != "Origin" {
		t.Errorf("XTLSModeOrigin.String() = %q, want %q", XTLSModeOrigin.String(), "Origin")
	}
	if XTLSModeDirect.String() != "Direct" {
		t.Errorf("XTLSModeDirect.String() = %q, want %q", XTLSModeDirect.String(), "Direct")
	}
	if XTLSMode(100).String() != "Unknown" {
		t.Errorf("Unknown XTLSMode.String() = %q, want %q", XTLSMode(100).String(), "Unknown")
	}

	if XTLSModeFromString("origin") != XTLSModeOrigin {
		t.Error("XTLSModeFromString(origin) failed")
	}
	if XTLSModeFromString("Direct") != XTLSModeDirect {
		t.Error("XTLSModeFromString(Direct) failed")
	}
	if XTLSModeFromString("notvalid") != XTLSModeOrigin {
		t.Error("XTLSModeFromString(default) should fallback to Origin")
	}
}

// Test alert pattern detection and stripping
func TestXTLSAlertPatternAndStrip(t *testing.T) {
	plain := []byte("hello world")
	withAlert := append(plain, XTLSAlertPattern...)
	result, removed := StripTrailingAlert(withAlert)
	if !removed {
		t.Error("Should detect trailing alert")
	}
	if !bytes.Equal(result, plain) {
		t.Errorf("Stripped buffer mismatch: got %v, want %v", result, plain)
	}
	// No alert case
	noAlert, notRemoved := StripTrailingAlert(plain)
	if notRemoved {
		t.Error("Should NOT detect alert in plain buffer")
	}
	if !bytes.Equal(noAlert, plain) {
		t.Errorf("No alert buffer mismatch: got %v, want %v", noAlert, plain)
	}
}

// Test XTLSConnState concurrency and transitions
func TestXTLSConnStateTransitions(t *testing.T) {
	state := &XTLSConnState{}
	XTLSStateTransition(state, "DirectReady", true)
	if !state.DirectReady {
		t.Error("DirectReady should be true after transition")
	}
	XTLSStateTransition(state, "OriginFallback", true)
	if !state.OriginFallback {
		t.Error("OriginFallback should be true after transition")
	}
	XTLSStateTransition(state, "ReadBypass", true)
	XTLSStateTransition(state, "WriteBypass", false)
	if !state.ReadBypass || state.WriteBypass {
		t.Error("ReadBypass or WriteBypass transition failed")
	}
	// Test last transition time updated
	now := time.Now()
	if state.LastTransition.Before(now.Add(-2 * time.Second)) {
		t.Error("LastTransition not updated properly")
	}
}

// DummyConn implements XTLSConn for testing interfaces
type DummyConn struct {
	mode  XTLSMode
	state *XTLSConnState
	debug bool
}

func (d *DummyConn) SetXTLSMode(mode XTLSMode)      { d.mode = mode }
func (d *DummyConn) GetXTLSMode() XTLSMode          { return d.mode }
func (d *DummyConn) EnableXTLSDebug(enable bool)    { d.debug = enable }
func (d *DummyConn) GetXTLSState() *XTLSConnState   { return d.state }

// Test EnableXTLSOnConn applies settings via interface
func TestEnableXTLSOnConn(t *testing.T) {
	dummy := &DummyConn{state: &XTLSConnState{}}
	EnableXTLSOnConn(dummy, XTLSModeDirect, true)
	if dummy.mode != XTLSModeDirect || !dummy.debug {
		t.Error("EnableXTLSOnConn did not set mode or debug properly")
	}
}

// Test XTLSDebug output (no panic, no check needed)
func TestXTLSDebug(t *testing.T) {
	XTLSDebug(true, "This is a test: %d", 123)
	XTLSDebug(false, "Should not print: %d", 666)
}

// Test XTLSDumpState (no panic, no check needed)
func TestXTLSDumpState(t *testing.T) {
	state := &XTLSConnState{DataTotal: 42, DataCount: 10, Debug: true}
	XTLSDumpState(state)
}
