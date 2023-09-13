package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"tailscale.com/envknob"
	"tailscale.com/types/logger"
	"tailscale.com/util/linuxfw"
	"tailscale.com/wgengine/router"
)

const (
	postRoutingChain   = "POSTROUTING"
	preroutingChain    = "PREROUTING"
	insertPosition     = 1
	tailscaleInterface = "tailscale0*"
	snat               = "SNAT"
	dnat               = "DNAT"
)

type netfilterRunner interface {
	addIngressDNAT(netip.Addr, netip.Addr) error
	addEgressSNAT(netip.Addr, netip.Addr) error
	addEgressDNAT(netip.Addr) error
}

func newNetFilterRunner() (netfilterRunner, error) {
	var mode linuxfw.FirewallMode
	tableDetector := &router.LinuxFWDetector{}
	switch {
	case envknob.String("TS_DEBUG_FIREWALL_MODE") == "nftables":
		log.Print("envknob TS_DEBUG_FIREWALL_MODE=nftables set")
		mode = linuxfw.FirewallModeNfTables
	case envknob.String("TS_DEBUG_FIREWALL_MODE") == "auto":
		mode = router.ChooseFireWallMode(logger.FromContext(context.Background()), tableDetector)
	case envknob.String("TS_DEBUG_FIREWALL_MODE") == "iptables":
		log.Print("envknob TS_DEBUG_FIREWALL_MODE=iptables set")
		mode = linuxfw.FirewallModeIPTables
	default:
		log.Print("default choosing iptables")
		mode = linuxfw.FirewallModeIPTables
	}
	var nfr netfilterRunner
	var err error
	switch mode {
	case linuxfw.FirewallModeIPTables:
		log.Print("using iptables")
		nfr, err = NewIPTablesRunner(logger.FromContext(context.Background()))
		if err != nil {
			return nil, err
		}
	case linuxfw.FirewallModeNfTables:
		log.Print("using nftables")
		nfr, err = NewNfTablesRunner(logger.FromContext(context.Background()))
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown firewall mode: %v", mode)
	}

	return nfr, nil
}

// implementation of netfilterRunner for nftables

// implementation of netfilterRunner for iptables
// A lot of this is copied from util/linuxfw/iptables_runner.go
type iptablesRunner struct {
	ipt4 *iptables.IPTables
	ipt6 *iptables.IPTables

	v6Available    bool
	v6NATAvailable bool
}

// NewIPTablesRunner constructs a NetfilterRunner that programs iptables rules.
// If the underlying iptables library fails to initialize, that error is
// returned. The runner probes for IPv6 support once at initialization time and
// if not found, no IPv6 rules will be modified for the lifetime of the runner.
func NewIPTablesRunner(logf logger.Logf) (*iptablesRunner, error) {
	ipt4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, err
	}

	supportsV6, supportsV6NAT := false, false
	v6err := linuxfw.CheckIPv6(logf)
	ip6terr := linuxfw.CheckIP6TablesExists()
	switch {
	case v6err != nil:
		logf("disabling tunneled IPv6 due to system IPv6 config: %v", v6err)
	case ip6terr != nil:
		logf("disabling tunneled IPv6 due to missing ip6tables: %v", ip6terr)
	default:
		supportsV6 = true
		supportsV6NAT = supportsV6 && linuxfw.CheckSupportsV6NAT()
		logf("v6nat = %v", supportsV6NAT)
	}

	var ipt6 *iptables.IPTables
	if supportsV6 {
		ipt6, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return nil, err
		}
	}
	return &iptablesRunner{ipt4, ipt6, supportsV6, supportsV6NAT}, nil
}

// getIPTByAddr returns the iptablesInterface with correct IP family
// that we will be using for the given address.
func (i *iptablesRunner) getIPTByAddr(addr netip.Addr) *iptables.IPTables {
	nf := i.ipt4
	if addr.Is6() {
		nf = i.ipt6
	}
	return nf
}

func (i *iptablesRunner) addIngressDNAT(destination netip.Addr, destinationFilter netip.Addr) error {
	if err := i.getIPTByAddr(destination).Insert("nat", preroutingChain, insertPosition, "-d", destinationFilter.String(), "-j", dnat, "--to-destination", destination.String()); err != nil {
		return fmt.Errorf("error adding egress DNAT: %w", err)
	}
	return nil
}

func (i *iptablesRunner) addEgressDNAT(destination netip.Addr) error {
	if err := i.getIPTByAddr(destination).Insert("nat", preroutingChain, insertPosition, "!", "-i", tailscaleInterface, "-j", dnat, "--to-destination", destination.String()); err != nil {
		return fmt.Errorf("error adding egress DNAT: %w", err)
	}
	return nil
}

func (i *iptablesRunner) addEgressSNAT(source, destinationFilter netip.Addr) error {
	if err := (i.getIPTByAddr(source)).Insert("nat", postRoutingChain, insertPosition, "--destination", destinationFilter.String(), "-j", snat, "--to-source", source.String()); err != nil {
		return fmt.Errorf("error adding egress SNAT: %w", err)
	}
	return nil
}

// nftables runner

type nftablesRunner struct {
	conn *nftables.Conn
	nft4 *nftable
	nft6 *nftable

	v6Available    bool
	v6NATAvailable bool
}

type nftable struct {
	Proto nftables.TableFamily
	Nat   *nftables.Table
}

// getNATTables gets the available nftable in nftables runner.
// If the system does not support IPv6 NAT, only the IPv4 nftable
// will be returned.
func (n *nftablesRunner) getNATTables() []*nftable {
	if n.v6NATAvailable && n.v6Available {
		return []*nftable{n.nft4, n.nft6}
	}
	return []*nftable{n.nft4}
}

// NewNfTablesRunner creates a new nftablesRunner without guaranteeing
// the existence of the tables and chains.
func NewNfTablesRunner(logf logger.Logf) (*nftablesRunner, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables connection: %w", err)
	}
	nft4 := &nftable{Proto: nftables.TableFamilyIPv4}

	v6err := linuxfw.CheckIPv6(logf)
	if v6err != nil {
		logf("disabling tunneled IPv6 due to system IPv6 config: %v", v6err)
	}
	supportsV6 := v6err == nil
	supportsV6NAT := supportsV6 && linuxfw.CheckSupportsV6NAT()

	var nft6 *nftable
	if supportsV6 {
		logf("v6nat availability: %v", supportsV6NAT)
		nft6 = &nftable{Proto: nftables.TableFamilyIPv6}
	}

	return &nftablesRunner{
		conn:           conn,
		nft4:           nft4,
		nft6:           nft6,
		v6Available:    supportsV6,
		v6NATAvailable: supportsV6NAT,
	}, nil
}

// getNFTByAddr returns the nftables with correct IP family
// that we will be using for the given address.
func (n *nftablesRunner) getNFTByAddr(addr netip.Addr) *nftable {
	if addr.Is6() {
		return n.nft6
	}
	return n.nft4
}

func (n *nftablesRunner) addIngressDNAT(destination netip.Addr, destinationFilter netip.Addr) error {
	polAccept := nftables.ChainPolicyAccept
	for _, table := range n.getNATTables() {
		nat, err := linuxfw.CreateTableIfNotExist(n.conn, table.Proto, "nat")
		if err != nil {
			return fmt.Errorf("create table: %w", err)
		}
		table.Nat = nat

		// ensure prerouting chain exists
		if err = linuxfw.CreateChainIfNotExist(n.conn, linuxfw.ChainInfo{
			Table:         nat,
			Name:          preroutingChain,
			ChainType:     nftables.ChainTypeNAT,
			ChainHook:     nftables.ChainHookPrerouting,
			ChainPriority: nftables.ChainPriorityNATDest,
			ChainPolicy:   &polAccept,
		}); err != nil {
			return fmt.Errorf("create prerouting chain: %w", err)
		}

		// TODO: create and get in a single operation
		preroutingChain, err := linuxfw.GetChainFromTable(n.conn, nat, preroutingChain)
		if err != nil {
			return fmt.Errorf("error retrieving prerouting chain: %w", err)
		}

		// Insert our rule TODO (irbekrm): add a test that ensures that
		// if this is run multiple times, the newest rule goes on top

		dnatRule := &nftables.Rule{
			Table: nat,
			Chain: preroutingChain,
			Exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       16,
					Len:          4,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     net.ParseIP(destinationFilter.String()).To4(),
				},
				&expr.Immediate{
					Register: 1,
					Data:     net.ParseIP(destination.String()).To4(),
				},
				&expr.NAT{
					Type:       expr.NATTypeDestNAT,
					Family:     unix.NFPROTO_IPV4,
					RegAddrMin: 1,
				},
			},
		}
		n.conn.AddRule(dnatRule)
		n.conn.Flush()

	}

	return nil
}

func (n *nftablesRunner) addEgressDNAT(destination netip.Addr) error {
	polAccept := nftables.ChainPolicyAccept
	for _, table := range n.getNATTables() {
		nat, err := linuxfw.CreateTableIfNotExist(n.conn, table.Proto, "nat")
		if err != nil {
			return fmt.Errorf("create table: %w", err)
		}
		table.Nat = nat

		// ensure prerouting chain exists
		if err = linuxfw.CreateChainIfNotExist(n.conn, linuxfw.ChainInfo{
			Table:         nat,
			Name:          preroutingChain,
			ChainType:     nftables.ChainTypeNAT,
			ChainHook:     nftables.ChainHookPrerouting,
			ChainPriority: nftables.ChainPriorityNATDest,
			ChainPolicy:   &polAccept,
		}); err != nil {
			return fmt.Errorf("create prerouting chain: %w", err)
		}

		// TODO: create and get in a single operation
		preroutingChain, err := linuxfw.GetChainFromTable(n.conn, nat, preroutingChain)
		if err != nil {
			return fmt.Errorf("error retrieving prerouting chain: %w", err)
		}

		// Insert our rule TODO (irbekrm): add a test that ensures that
		// if this is run multiple times, the newest rule goes on top

		dnatRule := &nftables.Rule{
			Table: nat,
			Chain: preroutingChain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     ifname(tailscaleInterface),
				},
				&expr.Immediate{
					Register: 1,
					Data:     net.ParseIP(destination.String()).To4(),
				},
				&expr.NAT{
					Type:       expr.NATTypeDestNAT,
					Family:     unix.NFPROTO_IPV4,
					RegAddrMin: 1,
				},
			},
		}
		// TODO (irbekrm): insert or replace not add
		n.conn.AddRule(dnatRule)
		n.conn.Flush()
	}
	return nil
}

func (n *nftablesRunner) addEgressSNAT(source, destinationFilter netip.Addr) error {
	polAccept := nftables.ChainPolicyAccept
	for _, table := range n.getNATTables() {
		nat, err := linuxfw.CreateTableIfNotExist(n.conn, table.Proto, "nat")
		if err != nil {
			return fmt.Errorf("create table: %w", err)
		}
		table.Nat = nat

		// ensure postrouting chain exists
		if err = linuxfw.CreateChainIfNotExist(n.conn, linuxfw.ChainInfo{
			Table:         nat,
			Name:          postRoutingChain,
			ChainType:     nftables.ChainTypeNAT,
			ChainHook:     nftables.ChainHookPostrouting,
			ChainPriority: nftables.ChainPriorityNATSource,
			ChainPolicy:   &polAccept,
		}); err != nil {
			return fmt.Errorf("create postrouting chain: %w", err)
		}

		// TODO: create and get in a single operation
		postroutingChain, err := linuxfw.GetChainFromTable(n.conn, nat, postRoutingChain)
		if err != nil {
			return fmt.Errorf("error retrieving postrouting chain: %w", err)
		}

		// Insert our rule TODO (irbekrm): add a test that ensures that
		// if this is run multiple times, the newest rule goes on top
		snatRule := &nftables.Rule{
			Table: nat,
			Chain: postroutingChain,
			Exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       16,
					Len:          4,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     net.ParseIP(destinationFilter.String()).To4(),
				},
				&expr.Masq{},
			},
		}
		n.conn.AddRule(snatRule)
		n.conn.Flush()
	}
	return nil
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}
