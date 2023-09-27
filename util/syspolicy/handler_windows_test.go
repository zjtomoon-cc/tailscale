// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"testing"

	"golang.org/x/sys/windows/registry"
	"tailscale.com/util/winutil"
)

const (
	regPolicyBase = `SOFTWARE\Policies\Tailscale`
)

func TestWindowsHandlerReadValues(t *testing.T) {
	if !winutil.IsCurrentProcessElevated() {
		t.Skipf("test requires running as elevated user")
	}
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, regPolicyBase, registry.SET_VALUE)
	if err != nil {
		t.Fatalf("opening %s: %v", regPolicyBase, err)
	}
	defer key.Close()
	t.Cleanup(func() {
		deleteKey(t)
	})
	if err := key.SetStringValue(string(AdminConsoleVisibility), "hide"); err != nil {
		t.Fatalf("error setting string value %v", err)
	}
	if err := key.SetDWordValue(string(LogSCMInteractions), 1); err != nil {
		t.Fatalf("error setting d word value %v", err)
	}
	if err := key.SetQWordValue(string(FlushDNSOnSessionUnlock), 0); err != nil {
		t.Fatalf("error setting q word value %v", err)
	}
	got, err := GetString(AdminConsoleVisibility, "show")
	if err != nil {
		t.Fatalf("Error getting string %v", err)
	}
	if got != "hide" {
		t.Fatalf("Expected hide, got %v", got)
	}
	got, err = GetString(NetworkDevicesVisibility, "show")
	if err == nil {
		t.Fatalf("Expected error value does not exist, got no error")
	}
	result, err := GetUint64(LogSCMInteractions, 0)
	if err != nil {
		t.Fatalf("Error getting uint %v", err)
	}
	if result != 1 {
		t.Fatalf("Expected 1, got %v", result)
	}
	result, err = GetUint64(FlushDNSOnSessionUnlock, 1)
	if err != nil {
		t.Fatalf("Error getting uint %v", err)
	}
	if result != 0 {
		t.Fatalf("Expected 0, got %v", result)
	}
	result, err = GetUint64(KeyExpirationNoticeTime, 1)
	if err == nil {
		t.Fatalf("Expected error value does not exist, got no error")
	}
}

func deleteKey(t *testing.T) {
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, regPolicyBase); err != nil && err != registry.ErrNotExist {
		t.Fatalf("Error deleting registry key %q: %v\n", regPolicyBase, err)
	}
}
