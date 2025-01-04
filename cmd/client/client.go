package main

import (
	"alesbrelih/go-vpn/internal/network"
	"encoding/base64"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	tunIP := "10.7.0.3/32"
	vpnIP := "10.5.0.5:6666"
	targetSubnet := "10.6.0.0"
	// TODO: mask should be dynamic

	var err error

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

	var conn net.Conn
	for {
		conn, err = net.Dial("tcp", vpnIP)
		if err != nil {
			slog.Error("could not establish connection to vpn", "err", err)
			<-time.Tick(3 * time.Second)
		} else {
			break
		}
	}

	slog.Info("successfully added route")

	go func() {
		for {
			data := make([]byte, network.DEFAULT_MTU)
			length, err := ifce.Read(data)
			if err != nil {
				slog.Error("could not read from", "err", err)
			}

			packet := gopacket.NewPacket(data[:length], layers.LayerTypeIPv4, gopacket.Default)

			if packet.ErrorLayer() == nil {
				base64enc := base64.RawStdEncoding.EncodeToString(data[:length])
				base64encLen := len(base64enc)

				l, err := conn.Write([]byte(base64enc))
				if err != nil {
					slog.Error("could not write to vpn server", "err", err)
				} else if l != base64encLen {
					slog.Error("didn't write whole package", "package len", base64encLen, "written", l)
				} else {
					slog.Info("successfully written to VPN server")
				}
			}
		}
	}()

	for {
		data := make([]byte, network.DEFAULT_MTU)
		l, err := conn.Read(data)
		if err != nil {
			slog.Error("could not read from conn", "err", err)
		}

		decoded, err := base64.StdEncoding.DecodeString(string(data[:l]))
		if err != nil {
			slog.Error("could not decode received string", "str", string(data[:l]))
		}

		ifce.Write(decoded)
	}
}
