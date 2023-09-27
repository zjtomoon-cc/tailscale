// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// go:build !android

package syspolicy

import (
	"errors"
	"testing"
	"time"
)

// testHandler encompasses all data types returned when testing any of the syspolicy
// methods that involve getting a policy value.
// For keys and the corresponding values, check policy_keys.go.
type testHandler struct {
	t                *testing.T
	name             string
	key              Key
	value            string
	u64              uint64
	err              error
	preferenceOption PreferenceOption // used to test GetPreferenceOption
	visibility       Visibility       // used to test GetVisibility
	duration         time.Duration    // used to test GetDuration
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
			if err != tt.err && tt.err != ErrNoSuchKey {
				t.Fatalf("got error %v instead of expected error %v", err, tt.err)
			}
		})
	}
}

func TestGetUint64(t *testing.T) {
	tests := []testHandler{
		{
			t:    t,
			name: "read existing value",
			key:  KeyExpirationNoticeTime,
			u64:  1,
			err:  nil,
		},
		{
			t:    t,
			name: "read non-existing value",
			key:  LogSCMInteractions,
			u64:  0,
			err:  ErrNoSuchKey,
		},
		{
			t:    t,
			name: "reading value returns other error",
			key:  FlushDNSOnSessionUnlock,
			u64:  0,
			err:  errors.New("blah"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler = &tt
			value, err := GetUint64(tt.key, 0)
			if err != nil && tt.err == ErrNoSuchKey {
				t.Fatalf("got %v error instead of handling ErrNoSuchKey", err)
			}
			if value != tt.u64 {
				t.Fatalf("got value %v instead of expected value %v", value, tt.u64)
			}
			if err != tt.err && tt.err != ErrNoSuchKey {
				t.Fatalf("got error %v instead of expected error %v", err, tt.err)
			}
		})
	}
}

func TestGetPreferenceOption(t *testing.T) {
	tests := []testHandler{
		{
			t:                t,
			name:             "always by policy",
			key:              EnableIncomingConnections,
			value:            "always",
			preferenceOption: alwaysByPolicy,
			err:              nil,
		},
		{
			t:                t,
			name:             "never by policy",
			key:              EnableIncomingConnections,
			value:            "never",
			preferenceOption: neverByPolicy,
			err:              nil,
		},
		{
			t:                t,
			name:             "user default",
			key:              EnableIncomingConnections,
			value:            "user-decides",
			preferenceOption: showChoiceByPolicy,
			err:              nil,
		},
		{
			t:                t,
			name:             "read non-existing value",
			key:              EnableIncomingConnections,
			preferenceOption: showChoiceByPolicy,
			err:              ErrNoSuchKey,
		},
		{
			t:                t,
			name:             "other error is returned",
			key:              EnableIncomingConnections,
			value:            "user-decides",
			preferenceOption: showChoiceByPolicy,
			err:              errors.New("blah"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler = &tt
			preference, err := GetPreferenceOption(tt.key)
			if tt.err == ErrNoSuchKey && err != nil {
				t.Fatalf("got %v error instead of handling ErrNoSuchKey", err)
			}

			if preference != tt.preferenceOption {
				t.Fatalf("got preference option %v instead of expected preference option %v", preference, tt.preferenceOption)
			}

			if err != tt.err && tt.err != ErrNoSuchKey {
				t.Fatalf("got error %v instead of expected error %v", err, tt.err)
			}

			if tt.err != nil && tt.preferenceOption != preference {
				t.Fatalf("got preference option %v instead of %v", preference, tt.preferenceOption)
			}
		})
	}
}

func TestGetVisibility(t *testing.T) {
	tests := []testHandler{
		{
			t:          t,
			name:       "hidden by policy",
			key:        AdminConsoleVisibility,
			value:      "hide",
			visibility: hiddenByPolicy,
			err:        nil,
		},
		{
			t:          t,
			name:       "visibility default",
			key:        AdminConsoleVisibility,
			value:      "show",
			visibility: visibleByPolicy,
			err:        nil,
		},
		{
			t:          t,
			name:       "read non-existing value",
			key:        AdminConsoleVisibility,
			value:      "show",
			visibility: visibleByPolicy,
			err:        nil,
		},
		{
			t:          t,
			name:       "other error is returned",
			key:        AdminConsoleVisibility,
			value:      "show",
			visibility: visibleByPolicy,
			err:        errors.New("blah"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler = &tt
			visibility, err := GetVisibility(tt.key)
			if tt.err == ErrNoSuchKey && err != nil {
				t.Fatalf("got %v error instead of handling ErrNoSuchKey", err)
			}

			if visibility != tt.visibility {
				t.Fatalf("got visibility %v instead of expected visibility %v", visibility, tt.visibility)
			}

			if err != tt.err && tt.err != ErrNoSuchKey {
				t.Fatalf("got error %v instead of expected error %v", err, tt.err)
			}

			if tt.err != nil && tt.visibility != visibility {
				t.Fatalf("got visibility %v instead of %v", visibility, tt.visibility)
			}
		})
	}
}

func TestGetDuration(t *testing.T) {
	tests := []testHandler{
		{
			t:        t,
			name:     "read existing value",
			key:      KeyExpirationNoticeTime,
			value:    "2h",
			duration: 2 * time.Hour,
			err:      nil,
		},
		{
			t:        t,
			name:     "read <0 value",
			key:      KeyExpirationNoticeTime,
			value:    "-20",
			duration: 24 * time.Hour,
			err:      nil,
		},
		{
			t:        t,
			name:     "read non-existing value",
			key:      KeyExpirationNoticeTime,
			value:    "",
			duration: 24 * time.Hour,
			err:      ErrNoSuchKey,
		},
		{
			t:        t,
			name:     "other error is returned",
			key:      KeyExpirationNoticeTime,
			value:    "",
			duration: 24 * time.Hour,
			err:      errors.New("blah"),
		},
		{
			t:        t,
			name:     "invalid duration value",
			key:      KeyExpirationNoticeTime,
			value:    "2.0",
			duration: 24 * time.Hour,
			err:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler = &tt
			duration, err := GetDuration(tt.key, 24*time.Hour)
			if tt.err == ErrNoSuchKey && err != nil {
				t.Fatalf("got %v error instead of handling ErrNoSuchKey", err)
			}

			if duration != tt.duration {
				t.Fatalf("got duration %v instead of expected duration %v", duration, duration)
			}

			if err != tt.err && tt.err != ErrNoSuchKey {
				t.Fatalf("got error %v instead of expected error %v", err, tt.err)
			}

			if tt.err != nil && tt.duration != duration {
				t.Fatalf("got duration %v instead of %v", duration, tt.duration)
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
