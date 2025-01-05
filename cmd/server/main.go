package main

import (
	"alesbrelih/go-vpn/cmd/server/handler"
	"alesbrelih/go-vpn/internal/network"
	"flag"
	"log"
	"log/slog"
	"os"
)

func main() {
	// TODO: from args
	tunIP := "10.6.0.3/32"
	port := ":6666"

	logLevelFlag := flag.String("log-level", "WARN", "Set log level. Available options: INFO, WARN(default), ERROR")
	flag.Parse()

	var logLvl slog.Level
	logLvl.UnmarshalText([]byte(*logLevelFlag))
	slog.SetLogLoggerLevel(logLvl)

	// TUN will serve to receive all traffic
	// 1. VPN server gets packets
	// 2. Decodes them
	// 3. Sends them to TUN
	// 4. Machine routing takes over
	ifce, err := network.CreateTUN(tunIP, network.DEFAULT_MTU)
	if err != nil {
		slog.Error("could not create TUN interface", "err", err)
		os.Exit(1)
	}

	// Because we want packets being routed back to this machine that holds the VPN server
	// We need to add postrouting to mask IP from VPN client IP to this machine
	// We can't set TUN0 here because it is not the ending interface.
	// It will hop from TUN0 to ETH1 -> target machine
	err = network.AppendIPTables("nat", "POSTROUTING", "-s", "10.7.0.0/16", "-o", "eth1", "-j", "MASQUERADE")
	if err != nil {
		slog.Error("could not append to nat postrouting", "err", err)
		os.Exit(1)
	}

	// Adding routing for the packet when it comes back as response
	// So the client VPN range 10.7.0.0/24 will get routed to TUN0
	// This will encrypt the package and send it over the wire
	err = network.AddRoute("tun0", "10.7.0.0")
	if err != nil {
		slog.Error("error adding route from client subrange to tun0", "err", err)
		os.Exit(1)
	}

	wg := handler.NewVPNServer(ifce).
		Start(port)

	log.Printf("server started @%s\n", port)

	// this waits forver ATM
	wg.Wait()
}
