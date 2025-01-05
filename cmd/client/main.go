package main

import (
	"alesbrelih/go-vpn/cmd/client/client"
	"alesbrelih/go-vpn/internal/network"
	"flag"
	"log"
	"log/slog"
	"os"
)

func main() {
	// TODO: don't hardcode
	tunIP := "10.7.0.3/32"
	vpnIP := "10.5.0.5:6666"
	targetSubnet := "10.6.0.0"
	// TODO: mask should be dynamic

	logLevelFlag := flag.String("log-level", "WARN", "Set log level. Available options: INFO, WARN(default), ERROR")
	flag.Parse()

	var logLvl slog.Level
	logLvl.UnmarshalText([]byte(*logLevelFlag))
	slog.SetLogLoggerLevel(logLvl)

	// reading from TUN because it operates on layer 3
	// so we can get destination IP, source IP in packet
	// then we can encrypt/package the packet and send it to VPN server
	// VPN server can then decrypt it and send it as FULL packet
	// to target TUN; so it can route it correctly
	// also needed so i can masquerade the IP of client host
	// to client private IP
	ifce, err := network.CreateTUN(tunIP, network.DEFAULT_MTU)
	if err != nil {
		slog.Error("could not create TUN interface", "err", err)
		os.Exit(1)
	}

	err = network.AddRoute(ifce.Name(), targetSubnet)
	if err != nil {
		slog.Error("error setting route", "err", err)
		os.Exit(1)
	}

	wg, err := client.NewVPNClient(ifce).Start(vpnIP)
	if err != nil {
		slog.Error("could not create the client", "err", err)
		os.Exit(1)
	}

	log.Println("client started")

	// this waits forever ATM
	wg.Wait()
}
