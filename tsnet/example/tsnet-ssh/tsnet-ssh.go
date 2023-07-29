// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The tsnet-ssh server demonstrates how to run Tailscale SSH in-process,
// without running tailscaled.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ssh/tailssh"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

func init() {
	// Register tailssh with LocalBackend.
	ipnlocal.RegisterNewSSHServer(func(logf logger.Logf, lb *ipnlocal.LocalBackend) (ipnlocal.SSHServer, error) {
		self, err := os.Executable()
		if err != nil {
			return nil, err
		}
		return tailssh.New(lb, logf, self), nil
	})
}

func main() {
	if len(os.Args) > 1 {
		sub := os.Args[1]
		if sub == "be-child" {
			if len(os.Args) > 2 && os.Args[2] == "ssh" {
				handleSSH()
				return
			}
		}
		log.Fatal("unexpected args")
	}

	s := &tsnet.Server{
		Logf: log.Printf,
	}
	defer s.Close()
	ctx := context.Background()
	if _, err := s.Up(ctx); err != nil {
		log.Fatal(err)
	}
	lc, _ := s.LocalClient()
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			RunSSH: true,
		},
		RunSSHSet: true,
	}); err != nil {
		log.Fatal(err)
	}
	fmt.Println("tsnet-ssh: ssh server running on port 22")
	select {}
}

func handleSSH() {
	fmt.Println("Hello from tsnet-ssh!")
}
