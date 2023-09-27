// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"errors"
)

var handler Handler = defaultHandler{}

// Handler reads system policies from OS-specific storage.
type Handler interface {
	// ReadString reads the policy settings value string given the key.
	ReadString(key string) (string, error)
	// ReadUInt64 reads the policy settings uint64 value given the key.
	ReadUInt64(key string) (uint64, error)
}

// ErrNoSuchKey is returned when the specified key does not have a value set.
var ErrNoSuchKey = errors.New("no such key")

// defaultHandler is the catch all syspolicy type for anything that isn't windows or apple.
type defaultHandler struct{}

func (defaultHandler) ReadString(_ string) (string, error) {
	return "", ErrNoSuchKey
}

func (defaultHandler) ReadUInt64(_ string) (uint64, error) {
	return 0, ErrNoSuchKey
}
