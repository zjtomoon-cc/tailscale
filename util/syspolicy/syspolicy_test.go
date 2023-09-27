// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import "testing"

type testHandler struct {
	t *testing.T
	wantKey string
	s   string
	u64 uint64
	err error
}

func (th *testHandler) ReadString(key string) (string, error) {
	if key != th.key {
		t.Errorf("ReadString(%q) want %q", key, th.key)
	}
	return th.s, th.err
}

func (th *testHandler) ReadUInt64(key string) (uint64, error) {
	if key != th.key {
		t.Errorf("ReadUint64(%q) want %q", key, th.key)
	}
	return th.u64, th.err
}

func TestGetString(t *testing.T) {
	var oldHandler = handler
	t.Cleanup(func() { handler = oldHandler })
	var th testHandler {
		t: t
	}
	handler = &th
}

func TestSelectControlURL(t *testing.T) {
	tests := []struct {
		reg, disk, want string
	}{
		// Modern default case.
		{"", "", "https://controlplane.tailscale.com"},

		// For a user who installed prior to Dec 2020, with
		// stuff in their registry.
		{"https://login.tailscale.com", "", "https://login.tailscale.com"},

		// Ignore pre-Dec'20 LoginURL from installer if prefs
		// prefs overridden manually to an on-prem control
		// server.
		{"https://login.tailscale.com", "http://on-prem", "http://on-prem"},

		// Something unknown explicitly set in the registry always wins.
		{"http://explicit-reg", "", "http://explicit-reg"},
		{"http://explicit-reg", "http://on-prem", "http://explicit-reg"},
		{"http://explicit-reg", "https://login.tailscale.com", "http://explicit-reg"},
		{"http://explicit-reg", "https://controlplane.tailscale.com", "http://explicit-reg"},

		// If nothing in the registry, disk wins.
		{"", "http://on-prem", "http://on-prem"},
	}
	for _, tt := range tests {
		if got := SelectControlURL(tt.reg, tt.disk); got != tt.want {
			t.Errorf("(reg %q, disk %q) = %q; want %q", tt.reg, tt.disk, got, tt.want)
		}
	}
}
