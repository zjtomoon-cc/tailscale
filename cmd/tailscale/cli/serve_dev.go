// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"slices"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

type execFunc func(ctx context.Context, args []string) error

type commandInfo struct {
	ShortHelp string
	LongHelp  string
}

var serveHelpCommon = strings.TrimSpace(`
<target> can be a port number (e.g., 3000), a partial URL (e.g., localhost:3000), or a
full URL including a path (e.g., http://localhost:3000/foo, https+insecure://localhost:3000/foo).

EXAMPLES
  - Mount a local web server at 127.0.0.1:3000 in the foreground:
    $ tailscale %s localhost:3000

  - Mount a local web server at 127.0.0.1:3000 in the background:
    $ tailscale %s -d localhost:3000
`)

var infoMap = map[string]commandInfo{
	"serve": {
		ShortHelp: "Serve content and local servers on your tailnet",
		LongHelp: strings.Join([]string{
			"Serve enables you to share a local server securely within your tailnet.\n",
			"To share a local server on the internet, use `tailscale funnel`\n\n",
		}, "\n"),
	},
	"funnel": {
		ShortHelp: "Serve content and local servers on the internet",
		LongHelp: strings.Join([]string{
			"Funnel enables you to share a local server on the internet using Tailscale.\n",
			"To share only within your tailnet, use `tailscale serve`\n\n",
		}, "\n"),
	},
}

func buildShortUsage(subcmd string) string {
	return strings.Join([]string{
		subcmd + " <target>",
		subcmd + " set [flags] <source> [off]",
		subcmd + " status [--json]",
		subcmd + " reset",
	}, "\n  ")
}

// newServeDevCommand returns a new "serve" subcommand using e as its environment.
func newServeDevCommand(e *serveEnv, subcmd string) *ffcli.Command {
	if subcmd != "serve" && subcmd != "funnel" {
		log.Fatalf("newServeDevCommand called with unknown subcmd %q", subcmd)
	}

	info := infoMap[subcmd]
	setCmdFlagSet := e.newFlags("serve-set", func(fs *flag.FlagSet) {
		fs.StringVar(&e.servePath, "path", "/", "path to serve the proxy on (default '/')")
		fs.StringVar(&e.servePort, "port", "", "port to serve the proxy on (default '443' for https and '80' for http)")
	})

	return &ffcli.Command{
		Name:      subcmd,
		ShortHelp: info.ShortHelp,
		ShortUsage: strings.Join([]string{
			fmt.Sprintf("%s <target>", subcmd),
			fmt.Sprintf("%s set [flags] <source> [off]", subcmd),
			fmt.Sprintf("%s status [--json]", subcmd),
			fmt.Sprintf("%s reset", subcmd),
		}, "\n  "),
		LongHelp: info.LongHelp + fmt.Sprintf(strings.TrimSpace(serveHelpCommon), subcmd, subcmd),
		Exec:     e.runServeCombined(subcmd == "funnel"),
		FlagSet: e.newFlags("serve-set", func(fs *flag.FlagSet) {
			fs.BoolVar(&e.daemon, "d", false, "run in the background")

		}),
		UsageFunc: usageFunc,
		Subcommands: []*ffcli.Command{
			{
				Name:      "set",
				ShortHelp: "add a new source to serve",
				ShortUsage: strings.Join([]string{
					fmt.Sprintf("%s set <scheme> [flags] <source> [off]", subcmd),
				}, "\n  "),
				LongHelp: strings.TrimSpace(`
The 'set' command allows you to add a new source to serve. You can serve various types
of content, including static files, local web servers, or even simple text.

EXAMPLES
  - expose an HTTPS endpoint proxying HTTP traffic to a local web server
    $ tailscale $subcmd set https localhost:3000

  - expose an HTTP endpoint proxying HTTP traffic to a static directory
    $ tailscale $subcmd set http /home/alice/blog

  - expose an HTTP endpoint proxying TCP traffic to a local TCP server
    $ tailscale $subcmd set tcp --port=2222 localhost:22

  - expose an HTTPS endpoint proxying TCP traffic to a local TCP server
    $ tailscale $subcmd set tls-terminated-tcp localhost:80
`),
				UsageFunc: usageFunc,
				Exec:      func(ctx context.Context, args []string) error { return flag.ErrHelp },
				Subcommands: []*ffcli.Command{
					{
						Name:      "http",
						ShortHelp: "serve over HTTP",
						Exec:      e.runServeSet(subcmd == "funnel", "http"),
						FlagSet:   setCmdFlagSet,
						UsageFunc: usageFunc,
					},
					{
						Name:      "https",
						ShortHelp: "serve over HTTPS",
						Exec:      e.runServeSet(subcmd == "funnel", "https"),
						FlagSet:   setCmdFlagSet,
						UsageFunc: usageFunc,
					},
					{
						Name:      "tcp",
						ShortHelp: "serve TCP connections",
						Exec:      e.runServeSet(subcmd == "funnel", "tcp"),
						FlagSet:   setCmdFlagSet,
						UsageFunc: usageFunc,
					},
					{
						Name:      "tls-terminated-tcp",
						ShortHelp: "serve TLS terminated TCP connections",
						Exec:      e.runServeSet(subcmd == "funnel", "tlsTerminatedTcp"),
						FlagSet:   setCmdFlagSet,
						UsageFunc: usageFunc,
					},
				},
			},
			// {
			// 	Name:      "unset",
			// 	ShortHelp: "remove a source from serve",
			// 	ShortUsage: strings.Join([]string{
			// 		fmt.Sprintf("%s unset [flags]", subcmd),
			// 	}, "\n  "),
			// 	LongHelp:  "The 'unset' command allows you to remove a source from serve.",
			// 	Exec:      e.runServeUnset(subcmd == "funnel", "https"),
			// 	FlagSet:   setCmdFlagSet,
			// 	UsageFunc: usageFunc,
			// },
			{
				Name:      "status",
				Exec:      e.runServeStatus,
				ShortHelp: "view current proxy configuration",
				FlagSet: e.newFlags("serve-status", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.json, "json", false, "output JSON")
				}),
				UsageFunc: usageFunc,
			},
			{
				Name:      "reset",
				ShortHelp: "reset current serve/funnel config",
				Exec:      e.runServeReset,
				FlagSet:   e.newFlags("serve-reset", nil),
				UsageFunc: usageFunc,
			},
		},
	}
}

// runServeCombined is the entry point for the "tailscale {serve,funnel}" commands.
func (e *serveEnv) runServeCombined(funnel bool) execFunc {
	return func(ctx context.Context, args []string) error {
		if len(args) != 1 {
			return flag.ErrHelp
		}

		// TODO(tylersmalley) add support for accepting just a port
		target, err := expandProxyTarget(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid target, expected format is localhost:<port> \n\n")
			return flag.ErrHelp
		}

		ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
		defer cancel()

		st, err := e.getLocalClientStatusWithoutPeers(ctx)
		if err != nil {
			return fmt.Errorf("getting client status: %w", err)
		}

		if funnel {
			// verify node has funnel capabilities
			if err := e.verifyFunnelEnabled(ctx, st, 443); err != nil {
				return fmt.Errorf("error: %w:", err)
			}
		}

		if e.daemon {
			err := e.setServe(ctx, "https", 443, "/", target, funnel)

			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
				return flag.ErrHelp
			}

			return nil
		}

		dnsName := strings.TrimSuffix(st.Self.DNSName, ".")
		hp := ipn.HostPort(dnsName + ":443") // TODO(marwan-at-work): support the 2 other ports

		// In the streaming case, the process stays running in the
		// foreground and prints out connections to the HostPort.
		//
		// The local backend handles updating the ServeConfig as
		// necessary, then restores it to its original state once
		// the process's context is closed or the client turns off
		// Tailscale.
		return e.streamServe(ctx, ipn.ServeStreamRequest{
			Funnel:     funnel,
			HostPort:   hp,
			Source:     target,
			MountPoint: "/", // TODO(marwan-at-work): support multiple mount points
		})
	}
}

// runServeSet is the entry point for "serve set" and "funnel set"
//
// Examples:
//   - tailscale serve set https /home/alice/blog/index.html
//   - tailscale serve set https localhost:3000
//   - tailscale serve set https localhost:3000
//   - tailscale serve set https http://localhost:3000
func (e *serveEnv) runServeSet(funnel bool, srvType string) execFunc {
	return func(ctx context.Context, args []string) error {
		if len(args) == 0 {
			return flag.ErrHelp
		}

		if len(args) < 1 {
			fmt.Fprintf(os.Stderr, "error: invalid number of arguments\n\n")
			return flag.ErrHelp
		}

		srvPort, err := parseFlags(e, srvType)

		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
			return flag.ErrHelp
		}

		turnOff := "off" == args[len(args)-1]
		if turnOff {
			err = e.unsetServe(ctx, srvType, srvPort, e.servePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
				return flag.ErrHelp
			}

			return nil
		}

		if funnel {
			st, err := e.getLocalClientStatusWithoutPeers(ctx)
			if err != nil {
				return fmt.Errorf("getting client status: %w", err)
			}

			// verify node has funnel capabilities
			if err := e.verifyFunnelEnabled(ctx, st, srvPort); err != nil {
				return fmt.Errorf("error: %w:", err)
			}
		}

		err = e.setServe(ctx, srvType, srvPort, e.servePath, args[0], funnel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
			return flag.ErrHelp
		}

		return nil
	}
}

// runServeUnset is the entry point for "serve unset" and "funnel unset"
//
// Examples:
//   - tailscale serve unset
func (e *serveEnv) runServeUnset(funnel bool, srvType string) execFunc {
	return func(ctx context.Context, args []string) error {
		srvPort, err := parseFlags(e, srvType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
			return flag.ErrHelp
		}

		err = e.unsetServe(ctx, srvType, srvPort, e.servePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
			return flag.ErrHelp
		}

		return nil
	}
}

func (e *serveEnv) streamServe(ctx context.Context, req ipn.ServeStreamRequest) error {
	stream, err := e.lc.StreamServe(ctx, req)
	if err != nil {
		return err
	}
	defer stream.Close()

	fmt.Fprintf(os.Stderr, "Serve started on \"https://%s\".\n", strings.TrimSuffix(string(req.HostPort), ":443"))
	fmt.Fprintf(os.Stderr, "Press Ctrl-C to stop.\n\n")
	_, err = io.Copy(os.Stdout, stream)
	return err
}

func (e *serveEnv) setServe(ctx context.Context, srvType string, srvPort uint16, mount string, source string, funnel bool) error {
	if srvType == "https" {
		// Running serve with https requires that the tailnet has enabled
		// https cert provisioning. Send users through an interactive flow
		// to enable this if not already done.
		//
		// TODO(sonia,tailscale/corp#10577): The interactive feature flow
		// is behind a control flag. If the tailnet doesn't have the flag
		// on, enableFeatureInteractive will error. For now, we hide that
		// error and maintain the previous behavior (prior to 2023-08-15)
		// of letting them edit the serve config before enabling certs.
		e.enableFeatureInteractive(ctx, "serve", func(caps []string) bool {
			return slices.Contains(caps, tailcfg.CapabilityHTTPS)
		})
	}

	switch srvType {
	case "https", "http":
		mount, err := cleanMountPoint(mount)
		if err != nil {
			return err
		}
		useTLS := srvType == "https"
		return e.handleWebServe(ctx, srvPort, useTLS, mount, source, funnel)
	case "tcp", "tls-terminated-tcp":
		return e.handleTCPServe(ctx, srvType, srvPort, source, funnel)
	default:
		return fmt.Errorf("invalid type %q", srvType)
	}
}

func (e *serveEnv) unsetServe(ctx context.Context, srcType string, srcPort uint16, mount string) error {
	switch srcType {
	case "https", "http":
		mount, err := cleanMountPoint(mount)
		if err != nil {
			return err
		}
		return e.handleWebServeRemove(ctx, srcPort, mount)
	case "tcp", "tls-terminated-tcp":
		return e.handleTCPServeRemove(ctx, srcPort)
	default:
		return fmt.Errorf("invalid type %q", srcType)
	}
}

func parseFlags(e *serveEnv, srvType string) (srvPort uint16, err error) {
	if e.servePort == "" {
		srvPort, err = getDefaultPort(srvType)
		if err != nil {
			return 0, err
		}
	} else {
		srvPort, err = parseServePort(e.servePort)
		if err != nil {
			return 0, fmt.Errorf("invalid port %q: %w", e.servePort, err)
		}
	}

	return srvPort, nil
}

func getDefaultPort(srvType string) (uint16, error) {
	switch srvType {
	case "http", "tcp":
		return 80, nil
	case "https", "tls-terminated-tcp":
		return 443, nil
	default:
		return 0, fmt.Errorf("invalid type %q", srvType)
	}
}
