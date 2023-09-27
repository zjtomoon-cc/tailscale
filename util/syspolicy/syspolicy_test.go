// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// go:build !android

package syspolicy

import (
	"errors"
	"testing"
)

type testHandler struct {
	t     *testing.T
	name  string
	key   Key
	value string
	u64   uint64
	err   error
}

func (th *testHandler) ReadString(key string) (string, error) {
	if key != string(th.key) {
		th.t.Errorf("ReadString(%q) want %q", key, th.key)
	}
	return th.value, th.err
}

func (th *testHandler) ReadUInt64(key string) (uint64, error) {
	if key != string(th.key) {
		th.t.Errorf("ReadUint64(%q) want %q", key, th.key)
	}
	return th.u64, th.err
}

func TestGetString(t *testing.T) {
	tests := []testHandler{
		{
			t:     t,
			name:  "read existing value",
			key:   AdminConsoleVisibility,
			value: "hide",
			err:   nil,
		},
		{
			t:     t,
			name:  "read non-existing value",
			key:   EnableServerMode,
			value: "",
			err:   ErrNoSuchKey,
		},
		{
			t:     t,
			name:  "reading value returns other error",
			key:   NetworkDevicesVisibility,
			value: "",
			err:   errors.New("blah"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler = &tt
			value, err := GetString(tt.key, "")
			if err != nil && tt.err == ErrNoSuchKey {
				t.Fatalf("got %v error instead of handling ErrNoSuchKey", err)
			}
			if value != tt.value {
				t.Fatalf("got value %v instead of expected value %v", value, tt.value)
			}
			if err != tt.err {
				t.Fatalf("got error %v instead of expected error %v", err, tt.err)
			}
		})
	}
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
