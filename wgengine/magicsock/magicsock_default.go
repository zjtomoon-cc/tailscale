// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !darwin

package magicsock

import (
	"errors"
	"io"

	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
)

func (c *Conn) listenRawDisco(family string) (io.Closer, error) {
	return nil, errors.New("raw disco listening not supported on this OS")
}

func trySetSocketBuffer(pconn nettype.PacketConn, logf logger.Logf) {
	portableTrySetSocketBuffer(pconn, logf)
}

func trySetDontFragment(pconn nettype.PacketConn, network string) (err error) {
	return errors.New("Setting don't fragment bit not supported on this OS")
}

func tryEnableUDPOffload(pconn nettype.PacketConn) (hasTX bool, hasRX bool) {
	return false, false
}

func getGSOSizeFromControl(control []byte) (int, error) {
	return 0, nil
}

func setGSOSizeInControl(control *[]byte, gso uint16) {}

func errShouldDisableOffload(err error) bool {
	return false
}

const (
	controlMessageSize = 0
)
