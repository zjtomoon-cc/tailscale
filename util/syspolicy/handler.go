// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"errors"
	"sync/atomic"
)

var handler atomic.Value

// Handler reads system policies from OS-specific storage.
type Handler interface {
	// ReadString reads the policy settings value string given the key.
	ReadString(key string) (string, error)
	// ReadUInt64 reads the policy settings uint64 value given the key.
	ReadUInt64(key string) (uint64, error)
}

// ErrNoSuchKey is returned when the specified key does not have a value set.
var ErrNoSuchKey = errors.New("no such key")
