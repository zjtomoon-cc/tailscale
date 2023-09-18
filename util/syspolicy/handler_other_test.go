// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import "testing"

func TestDefaultHandlerReadValues(t *testing.T) {
	got, err := GetString(AdminConsoleVisibility, "show")
	if got != "" || err != ErrNoSuchKey {
		t.Fatalf("got %v err %v", got, err)
	}
	result, err := GetUint64(LogSCMInteractions, 0)
	if result != 0 || err != ErrNoSuchKey {
		t.Fatalf("got %v err %v", result, err)
	}
}
