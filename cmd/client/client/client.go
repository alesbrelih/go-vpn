package client

import (
	"alesbrelih/go-vpn/internal/network"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
)

func NewVPNClient(ifce *water.Interface, cert tls.Certificate, certPool *x509.CertPool) *Client {
	return &Client{
		ifce:     ifce,
		cert:     cert,
		certPool: certPool,
	}
}

type Client struct {
	ifce     *water.Interface
	cert     tls.Certificate
	certPool *x509.CertPool
}

func (c *Client) Start(vpnServerIP string) (*sync.WaitGroup, error) {
	var conn net.Conn
	var err error

	for i := range 5 {
		if i == 4 {
			return nil, fmt.Errorf("vpn server unreachable; ip: %s", vpnServerIP)
		}

		conn, err = tls.Dial("tcp", vpnServerIP, &tls.Config{
			Certificates: []tls.Certificate{c.cert},
			RootCAs:      c.certPool,
		})
		if err != nil {
			slog.Error("could not establish connection to vpn", "err", err)
			<-time.Tick(3 * time.Second)
		} else {
			break
		}

	}

	slog.Info("successfully added route")

	wg := &sync.WaitGroup{}

	go c.readLocalTUN(conn)

	go c.writeVPNResponseToLocalTUN(conn)

	wg.Add(2)

	return wg, nil
}

func (c *Client) readLocalTUN(conn net.Conn) {
	for {
		data := make([]byte, network.DEFAULT_MTU)
		length, err := c.ifce.Read(data)
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
}

func (c *Client) writeVPNResponseToLocalTUN(conn net.Conn) {
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

		l, err = c.ifce.Write(decoded)
		if err != nil {
			slog.Error("could not write VPN response to ifce", "err", err)
		} else if l != len(decoded) {
			slog.Error("did not write whole VPN response to ifce", "l", l, "decoded len", len(decoded))
		}
	}
}
