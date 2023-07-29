// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin || freebsd || openbsd

package main

import (
	"os"

	"tailscale.com/cmd/tailscaled/childproc"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ssh/tailssh"
	"tailscale.com/types/logger"
)

func init() {
	// Register tailssh with LocalBackend.
	ipnlocal.RegisterNewSSHServer(func(logf logger.Logf, lb *ipnlocal.LocalBackend) (ipnlocal.SSHServer, error) {
		tsd, err := os.Executable()
		if err != nil {
			return nil, err
		}
		return tailssh.New(lb, logf, tsd), nil
	})

	childproc.Add("ssh", tailssh.BeIncubator)
}
