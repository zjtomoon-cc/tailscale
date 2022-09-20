// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netutil contains misc shared networking code & types.
package netutil

import (
	"bytes"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"tailscale.com/net/interfaces"
)

// protocolsRequiredForForwarding reports whether IPv4 and/or IPv6 protocols are
// required to forward the specified routes.
// The state param must be specified.
func protocolsRequiredForForwarding(routes []netip.Prefix, state *interfaces.State) (v4, v6 bool) {
	if len(routes) == 0 {
		// Nothing to route, so no need to warn.
		return false, false
	}

	localIPs := make(map[netip.Addr]bool)
	for _, addrs := range state.InterfaceIPs {
		for _, pfx := range addrs {
			localIPs[pfx.Addr()] = true
		}
	}

	for _, r := range routes {
		// It's possible to advertise a route to one of the local
		// machine's local IPs. IP forwarding isn't required for this
		// to work, so we shouldn't warn for such exports.
		if r.IsSingleIP() && localIPs[r.Addr()] {
			continue
		}
		if r.Addr().Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	return v4, v6
}

// CheckIPForwarding reports whether IP forwarding is enabled correctly
// for subnet routing and exit node functionality on any interface.
// The state param can be nil, in which case interfaces.GetState is used.
// The routes should only be advertised routes, and should not contain the
// nodes Tailscale IPs.
// It returns an error if it is unable to determine if IP forwarding is enabled.
// It returns a warning describing configuration issues if IP forwarding is
// non-functional or partly functional.
func CheckIPForwarding(routes []netip.Prefix, state *interfaces.State) (warn, err error) {
	if runtime.GOOS != "linux" {
		switch runtime.GOOS {
		case "dragonfly", "freebsd", "netbsd", "openbsd":
			return fmt.Errorf("Subnet routing and exit nodes only work with additional manual configuration on %v, and is not currently officially supported.", runtime.GOOS), nil
		}
		return nil, nil
	}
	const kbLink = "\nSee https://tailscale.com/kb/1104/enable-ip-forwarding/"
	if state == nil {
		var err error
		state, err = interfaces.GetState()
		if err != nil {
			return nil, err
		}
	}
	wantV4, wantV6 := protocolsRequiredForForwarding(routes, state)
	if !wantV4 && !wantV6 {
		return nil, nil
	}

	v4e, err := ipForwardingEnabledLinux(ipv4, "")
	if err != nil {
		return nil, fmt.Errorf("Couldn't check system's IP forwarding configuration, subnet routing/exit nodes may not work: %w%s", err, kbLink)
	}
	v6e, err := ipForwardingEnabledLinux(ipv6, "")
	if err != nil {
		return nil, fmt.Errorf("Couldn't check system's IP forwarding configuration, subnet routing/exit nodes may not work: %w%s", err, kbLink)
	}

	if v4e && v6e {
		// IP forwarding is enabled systemwide, all is well.
		return nil, nil
	}

	if !wantV4 {
		if !v6e {
			return nil, fmt.Errorf("IPv6 forwarding is disabled, subnet routing/exit nodes may not work.%s", kbLink)
		}
		return nil, nil
	}
	// IP forwarding isn't enabled globally, but it might be enabled
	// on a per-interface basis. Check if it's on for all interfaces,
	// and warn appropriately if it's not.
	// Note: you might be wondering why we check only the state of
	// ipv6.conf.all.forwarding, rather than per-interface forwarding
	// configuration. According to kernel documentation, it seems
	// that to actually forward packets, you need to enable
	// forwarding globally, and the per-interface forwarding
	// setting only alters other things such as how router
	// advertisements are handled. The kernel itself warns that
	// enabling forwarding per-interface and not globally will
	// probably not work, so I feel okay calling those configs
	// broken until we have proof otherwise.
	var (
		anyEnabled bool
		warnings   []string
	)
	if wantV6 && !v6e {
		warnings = append(warnings, "IPv6 forwarding is disabled.")
	}
	for _, iface := range state.Interface {
		if iface.Name == "lo" {
			continue
		}
		v4e, err := ipForwardingEnabledLinux(ipv4, iface.Name)
		if err != nil {
			return nil, fmt.Errorf("Couldn't check system's IP forwarding configuration, subnet routing/exit nodes may not work: %w%s", err, kbLink)
		} else if !v4e {
			warnings = append(warnings, fmt.Sprintf("Traffic received on %s won't be forwarded (%s disabled)", iface.Name, ipForwardSysctlKey(dotFormat, ipv4, iface.Name)))
		} else {
			anyEnabled = true
		}
	}
	if !anyEnabled {
		// IP forwarding is completely disabled, just say that rather
		// than enumerate all the interfaces on the system.
		return fmt.Errorf("IP forwarding is disabled, subnet routing/exit nodes will not work.%s", kbLink), nil
	}
	if len(warnings) > 0 {
		// If partially enabled, enumerate the bits that won't work.
		return fmt.Errorf("%s\nSubnet routes and exit nodes may not work correctly.%s", strings.Join(warnings, "\n"), kbLink), nil
	}

	return nil, nil
}

// CheckReversePathFiltering reports whether reverse path filtering is either
// disabled or set to 'loose' mode for exit node functionality on any
// interface.
//
// The state param can be nil, in which case interfaces.GetState is used.
//
// The routes should only be advertised routes, and should not contain the
// nodes Tailscale IPs.
//
// This function returns an error if it is unable to determine if reverse path
// filtering is enabled, or a warning describing configuration issues if
// reverse path fitering is non-functional or partly functional.
func CheckReversePathFiltering(routes []netip.Prefix, state *interfaces.State) (warn, err error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}
	const kbLink = "" // TODO(andrew): insert one like "\nSee https://tailscale.com/kb/something"

	if state == nil {
		var err error
		state, err = interfaces.GetState()
		if err != nil {
			return nil, err
		}
	}

	// Reverse path filtering as a syscall is only implemented on Linux for IPv4.
	wantV4, _ := protocolsRequiredForForwarding(routes, state)
	if !wantV4 {
		return nil, nil
	}

	// The kernel uses the maximum value for rp_filter between the 'all'
	// setting and each per-interface config, so we need to fetch both.
	allSetting, err := reversePathFilterValueLinux("all")
	if err != nil {
		return nil, fmt.Errorf("Couldn't check system's reverse path filtering configuration: %w%s", err, kbLink)
	}

	const (
		filtOff    = 0
		filtStrict = 1
		filtLoose  = 2
	)

	// Because the kernel use the max rp_filter value, each interface will use 'loose', so we
	// can abort early.
	if allSetting == filtLoose {
		return nil, nil
	}

	var (
		warnings []string
	)
	for _, iface := range state.Interface {
		if iface.Name == "lo" {
			continue
		}

		iSetting, err := reversePathFilterValueLinux(iface.Name)
		if err != nil {
			return nil, fmt.Errorf("Couldn't check system's reverse path filtering configuration: %w%s", err, kbLink)
		}
		// Perform the same max() that the kernel does
		if allSetting > iSetting {
			iSetting = allSetting
		}
		log.Printf("%s: rp_filter=%d", iface.Name, iSetting)

		if iSetting == filtStrict {
			warnings = append(warnings, fmt.Sprintf("Interface %s has strict reverse-path filtering enabled.", iface.Name))
		}
	}
	if len(warnings) > 0 {
		return fmt.Errorf("%s\nTailscale may not work correctly.%s", strings.Join(warnings, "\n"), kbLink), nil
	}

	// All good!
	return nil, nil
}

// ipForwardSysctlKey returns the sysctl key for the given protocol and iface.
// When the dotFormat parameter is true the output is formatted as `net.ipv4.ip_forward`,
// else it is `net/ipv4/ip_forward`
func ipForwardSysctlKey(format sysctlFormat, p protocol, iface string) string {
	if iface == "" {
		if format == dotFormat {
			if p == ipv4 {
				return "net.ipv4.ip_forward"
			}
			return "net.ipv6.conf.all.forwarding"
		}
		if p == ipv4 {
			return "net/ipv4/ip_forward"
		}
		return "net/ipv6/conf/all/forwarding"
	}

	var k string
	if p == ipv4 {
		k = "net/ipv4/conf/%s/forwarding"
	} else {
		k = "net/ipv6/conf/%s/forwarding"
	}
	if format == dotFormat {
		// Swap the delimiters.
		iface = strings.ReplaceAll(iface, ".", "/")
		k = strings.ReplaceAll(k, "/", ".")
	}
	return fmt.Sprintf(k, iface)
}

// rpFilterSysctlKey returns the sysctl key for the given iface.
//
// Format controls whether the output is formatted as
// `net.ipv4.conf.iface.rp_filter` or `net/ipv4/conf/iface/rp_filter`.
func rpFilterSysctlKey(format sysctlFormat, iface string) string {
	// No iface means all interfaces
	if iface == "" {
		iface = "all"
	}

	k := "net/ipv4/conf/%s/rp_filter"
	if format == dotFormat {
		// Swap the delimiters.
		iface = strings.ReplaceAll(iface, ".", "/")
		k = strings.ReplaceAll(k, "/", ".")
	}
	return fmt.Sprintf(k, iface)
}

type sysctlFormat int

const (
	dotFormat sysctlFormat = iota
	slashFormat
)

type protocol int

const (
	ipv4 protocol = iota
	ipv6
)

// ipForwardingEnabledLinux reports whether the IP Forwarding is enabled for the
// given interface.
// The iface param determines which interface to check against, "" means to check
// global config.
// It tries to lookup the value directly from `/proc/sys`, and fallsback to
// using `sysctl` on failure.
func ipForwardingEnabledLinux(p protocol, iface string) (bool, error) {
	k := ipForwardSysctlKey(slashFormat, p, iface)
	bs, err := os.ReadFile(filepath.Join("/proc/sys", k))
	if err != nil {
		// Fallback to using sysctl.
		// Sysctl accepts `/` as separator.
		bs, err = exec.Command("sysctl", "-n", k).Output()
		if err != nil {
			// But in case it doesn't.
			k := ipForwardSysctlKey(dotFormat, p, iface)
			bs, err = exec.Command("sysctl", "-n", k).Output()
			if err != nil {
				return false, fmt.Errorf("couldn't check %s (%v)", k, err)
			}
		}
	}
	on, err := strconv.ParseBool(string(bytes.TrimSpace(bs)))
	if err != nil {
		return false, fmt.Errorf("couldn't parse %s (%v)", k, err)
	}
	return on, nil
}

// reversePathFilterValueLinux reports the reverse path filter setting on Linux
// for the given interface.
//
// The iface param determines which interface to check against; the empty
// string means to check the global config.
//
// This function tries to look up the value directly from `/proc/sys`, and
// falls back to using `sysctl` on failure.
func reversePathFilterValueLinux(iface string) (int, error) {
	k := rpFilterSysctlKey(slashFormat, iface)
	bs, err := os.ReadFile(filepath.Join("/proc/sys", k))
	if err != nil {
		// Fall back to sysctl
		k := rpFilterSysctlKey(dotFormat, iface)
		bs, err = exec.Command("sysctl", "-n", k).Output()
		if err != nil {
			return -1, fmt.Errorf("couldn't check %s (%v)", k, err)
		}
	}
	v, err := strconv.Atoi(string(bytes.TrimSpace(bs)))
	if err != nil {
		return -1, fmt.Errorf("couldn't parse %s (%v)", k, err)
	}
	return v, nil
}
