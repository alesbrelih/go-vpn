package network

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/coreos/go-iptables/iptables"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

const DEFAULT_MTU = 1500

func CreateTUN(ip string, mtu int) (*water.Interface, error) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create TUN interface: err: %w", err)
	}

	slog.Info("TUN Interface created", "interface_name", ifce.Name())

	tun, err := netlink.LinkByName(ifce.Name())
	if err != nil {
		return nil, fmt.Errorf("could not find TUN interface; name: %s: err: %w", ifce.Name(), err)
	}

	err = netlink.LinkSetMTU(tun, mtu)
	if err != nil {
		return nil, fmt.Errorf("could not set TUN MTU: err: %w", err)
	}

	addr, err := netlink.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("could not find IP addr; ip: %s: err: %w", ip, err)
	}

	err = netlink.AddrAdd(tun, addr)
	if err != nil {
		return nil, fmt.Errorf("could not assign IP addr; tun: %+v; addr: %+v; err: %w", tun, addr, err)
	}

	err = netlink.LinkSetUp(tun)
	if err != nil {
		return nil, fmt.Errorf("could not enable tun; tun: %+v; err: %w", tun, err)
	}

	return ifce, nil
}

func AddRoute(link string, address string) error {
	tun, err := netlink.LinkByName(link)
	if err != nil {
		return fmt.Errorf("could not find TUN interface; name: %s: err: %w", link, err)
	}

	route := &netlink.Route{
		LinkIndex: tun.Attrs().Index,
		Dst:       &net.IPNet{IP: net.ParseIP(address), Mask: net.CIDRMask(24, 32)}, // Destination network
	}

	return netlink.RouteAdd(route)
}

func AppendIPTables(table, chain string, rulespec ...string) error {
	iptables, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4), iptables.Timeout(10))
	if err != nil {
		return fmt.Errorf("could not create iptables: err: %w", err)
	}

	return iptables.Append(table, chain, rulespec...)
}
