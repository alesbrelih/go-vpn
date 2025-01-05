package handler

import (
	"alesbrelih/go-vpn/internal/network"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
)

type connections struct {
	sync.Mutex
	connections map[string]net.Conn
}

func (c *connections) Add(srcIP string, conn net.Conn) {
	c.connections[srcIP] = conn
}

func (c *connections) Get(ip string) (net.Conn, bool) {
	conn, ok := c.connections[ip]
	return conn, ok
}

func NewConnections() *connections {
	return &connections{
		connections: make(map[string]net.Conn),
	}
}

type server struct {
	ifce        *water.Interface
	connections *connections
}

func NewVPNServer(ifce *water.Interface) *server {
	return &server{
		ifce:        ifce,
		connections: NewConnections(),
	}
}

func (s *server) Start(port string) *sync.WaitGroup {
	go s.startVPNListener(port)
	go s.startTUNListener()

	wg := &sync.WaitGroup{}

	wg.Add(2)

	return wg
}

func (s *server) startVPNListener(port string) {
	listener, err := net.Listen("tcp", port)
	if err != nil {
		// TODO: return error
		panic(fmt.Sprintf("could not open listener @%s", port))
	}

	slog.Info("started", "port", port)

	for {
		conn, err := listener.Accept()
		slog.Info("connection", "local", conn.LocalAddr().String(), "remote", conn.RemoteAddr().String())

		if err != nil {
			panic(fmt.Sprintf("could not open listener @%s", port))
		}

		go func() {
			if err := s.handleConnection(conn); err != nil {
				slog.Error(
					"error handling connection",
					"error", err,
				)
			}
		}()
	}
}

func (s *server) handleConnection(conn net.Conn) error {
	for {
		data := make([]byte, 1024)

		l, err := conn.Read(data)
		if err != nil {
			return fmt.Errorf("error reading from conn: %w", err)
		}

		// TODO: decrypt
		msg, err := base64.RawStdEncoding.DecodeString(string(data[:l]))
		if err != nil {
			return fmt.Errorf("could not decode message: %s; err: %w", string(data[:l]), err)
		}

		packet := gopacket.NewPacket(msg, layers.LayerTypeIPv4, gopacket.Default)
		if packet.ErrorLayer() == nil {
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)

				// TODO: move to handshake or even have an option to generate user config
				s.connections.Add(ip.SrcIP.String(), conn)

			}
		}

		_, err = s.ifce.Write(msg)
		if err != nil {
			return fmt.Errorf("could not write to tun0 err: %w", err)
		} else {
			slog.Info("successfully sent package", "msg", msg)
		}
	}
}

func (s *server) startTUNListener() {
	for {
		data := make([]byte, network.DEFAULT_MTU)

		length, err := s.ifce.Read(data)
		if err != nil {
			slog.Error("error reading from ifce", "err", err)
		}

		packet := gopacket.NewPacket(data[:length], layers.LayerTypeIPv4, gopacket.Default)
		if packet.ErrorLayer() == nil {
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)

				if conn, ok := s.connections.Get(ip.DstIP.String()); ok {
					base64Enc := base64.StdEncoding.EncodeToString(data[:length])

					l, err := conn.Write([]byte(base64Enc))
					if err != nil {
						slog.Error("error writing msg back to the connection", "msg", base64Enc)
					} else if len(base64Enc) != l {
						slog.Error("didn't write whole message", "written", l, "msg length", len(base64Enc))
					} else {
						slog.Info("successfully responded back to conn")
					}
				}

			}
		}

	}
}
