// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

type Key string

const (
	// Keys with a string value
	ControlURL Key = "LoginURL"  // default "https://controlplane.tailscale.com"
	LogTarget  Key = "LogTarget" // default: ?

	// Keys with a string value that specifies an option: "always", "never", "user-decides"
	EnableIncomingConnections Key = "AllowIncomingConnections"
	EnableServerMode          Key = "UnattendedMode"

	// Keys with a string value that controls visibility: "show", "hide"
	AdminConsoleVisibility    Key = "AdminConsole"
	NetworkDevicesVisibility  Key = "NetworkDevices"
	TestMenuVisibility        Key = "TestMenu"
	UpdateMenuVisibility      Key = "UpdateMenu"
	RunExitNodeVisibility     Key = "RunExitNode"
	PreferencesMenuVisibility Key = "PreferencesMenu"

	KeyExpirationNoticeTime Key = "KeyExpirationNotice" // default 24 hours

	// Integer Keys that are used on Windows only
	LogSCMInteractions      Key = "LogSCMInteractions"
	FlushDNSOnSessionUnlock Key = "FlushDNSOnSessionUnlock"
)
