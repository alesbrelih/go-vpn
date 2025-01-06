package main

import (
	"alesbrelih/go-vpn/cmd/client/client"
	"alesbrelih/go-vpn/internal/certificates"
	"alesbrelih/go-vpn/internal/network"
	"alesbrelih/go-vpn/resources/ca"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"log/slog"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func main() {
	// TODO: don't hardcode
	tunIP := "10.7.0.3/32"
	vpnIP := "10.5.0.5:6666"
	targetSubnet := "10.6.0.0"
	// TODO: mask should be dynamic

	configFlag := flag.String("config", "", "Path to config file")
	logLevelFlag := flag.String("log-level", "WARN", "Set log level. Available options: INFO, WARN(default), ERROR")
	flag.Parse()

	if *configFlag == "" {
		slog.Error("Config is required. Use -config to specify path to config file")
		os.Exit(1)
	}

	config, err := os.ReadFile(*configFlag)
	if err != nil {
		slog.Error("could not read config", "path", *configFlag, "err", err)
		os.Exit(1)
	}

	cfg := certificates.Config{}
	err = yaml.Unmarshal(config, &cfg)
	if err != nil {
		slog.Error("could not unmarshal config", "config", config)
		os.Exit(1)
	}

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(ca.CertPEM)
	if !ok {
		slog.Error("could not load CA")
		os.Exit(1)
	}

	dir := filepath.Dir(*configFlag)
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, cfg.Cert), filepath.Join(dir, cfg.Key))
	if err != nil {
		slog.Error("could not load 509 key par", "err", err)
		os.Exit(1)
	}

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

	wg, err := client.NewVPNClient(ifce, cert, caCertPool).Start(vpnIP)
	if err != nil {
		slog.Error("could not create the client", "err", err)
		os.Exit(1)
	}

	log.Println("client started")

	// this waits forever ATM
	wg.Wait()
}
