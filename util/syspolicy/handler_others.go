// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

// defaultHandler is the catch all syspolicy interface for anything that isn't windows or apple.

type defaultHandler struct{}

func init() {
	handler.Store(Handler(defaultHandler{}))
}

func (defaultHandler) ReadString(_ string) (string, error) {
	return "", ErrNoSuchKey
}

func (defaultHandler) ReadUInt64(_ string) (uint64, error) {
	return 0, ErrNoSuchKey
}
