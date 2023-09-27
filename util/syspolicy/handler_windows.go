// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import "tailscale.com/util/winutil"

type windowsHandler struct{}

func init() {
	handler = windowsHandler{}
}

func (windowsHandler) ReadString(key string) (string, error) {
	return winutil.GetPolicyString(key)
}

func (windowsHandler) ReadUInt64(key string) (uint64, error) {
	return winutil.GetPolicyInteger(key)
}
