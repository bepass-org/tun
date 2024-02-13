package netstack

import (
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"sync"
)

// NetStack is the structure used to store the connection pool and the gvisor network stack
type NetStack struct {
	pool  *ConnPool
	stack *stack.Stack
	iface *TunInterface
	sync.Mutex
}

type StackSettings struct {
	TunName     string
	MaxInflight int
}

// NewStack registers a new GVisor Network Stack
func NewStack(settings StackSettings, connPool *ConnPool) (*NetStack, error) {
	ns := NetStack{pool: connPool}
	if _, err := ns.new(settings); err != nil {
		return nil, err
	}
	return &ns, nil
}

// GetStack returns the current Gvisor stack.Stack object
func (s *NetStack) GetStack() *stack.Stack {
	return s.stack
}

// SetConnPool is used to change the current connPool. It must be used after switching Bepass agents
func (s *NetStack) SetConnPool(connPool *ConnPool) {
	s.Lock()
	s.pool = connPool
	s.Unlock()
}

// NewTunDevice creates a new userland network stack (using Gvisor) that listen on a tun interface.
func (s *NetStack) new(stackSettings StackSettings) (*stack.Stack, error) {

	// Create a new gvisor userland network stack.
	ns := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		HandleLocal: false,
	})

	s.stack = ns

	// Gvisor Hack: Disable ICMP handling.
	ns.SetICMPLimit(0)
	ns.SetICMPBurst(0)

	// Forward TCP connections
	tcpHandler := tcp.NewForwarder(ns, 0, stackSettings.MaxInflight, func(request *tcp.ForwarderRequest) {
		tcpConn := TCPConn{
			EndpointID: request.ID(),
			Request:    request,
		}
		s.Lock()
		defer s.Unlock()
		if s.pool == nil || s.pool.Closed() {
			return // If connPool is closed, ignore packet.
		}

		if err := s.pool.Add(TunConn{
			tcp.ProtocolNumber,
			tcpConn,
		}); err != nil {
			logrus.Error(err)
		}
	})

	// Forward UDP connections
	udpHandler := udp.NewForwarder(ns, func(request *udp.ForwarderRequest) {

		udpConn := UDPConn{
			EndpointID: request.ID(),
			Request:    request,
		}

		s.Lock()
		defer s.Unlock()

		if s.pool == nil || s.pool.Closed() {
			return // If connPool is closed, ignore packet.
		}

		if err := s.pool.Add(TunConn{
			udp.ProtocolNumber,
			udpConn,
		}); err != nil {
			logrus.Error(err)
		}
	})

	// Register forwarders
	ns.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpHandler.HandlePacket)
	ns.SetTransportProtocolHandler(udp.ProtocolNumber, udpHandler.HandlePacket)

	iface, err := NewTunDevice(stackSettings.TunName)
	if err != nil {
		return nil, fmt.Errorf("unable to create tun interface '%s' (tun.NewTunDevice %v), make sure you've created the tun interface and that it's not in use", stackSettings.TunName, err)
	}
	s.iface = iface

	// Create a new NIC
	if err := ns.CreateNIC(1, iface.LinkEP); err != nil {
		return nil, errors.New(err.String())
	}

	// Start a endpoint that will reply to ICMP echo queries
	if err := icmpResponder(s); err != nil {
		return nil, err
	}

	// Allow all routes by default

	ns.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         1,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         1,
		},
	})

	// Enable forwarding
	ns.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, false)
	ns.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, false)

	// Enable TCP SACK
	nsacks := tcpip.TCPSACKEnabled(false)
	ns.SetTransportProtocolOption(tcp.ProtocolNumber, &nsacks)

	// Disable SYN-Cookies, as this can mess with nmap scans
	synCookies := tcpip.TCPAlwaysUseSynCookies(false)
	ns.SetTransportProtocolOption(tcp.ProtocolNumber, &synCookies)

	// Allow packets from all sources/destinations
	ns.SetPromiscuousMode(1, true)
	ns.SetSpoofing(1, true)

	return ns, nil
}

func (s *NetStack) Interface() *TunInterface {
	return s.iface
}

func (s *NetStack) Close() {
	if s.stack != nil {
		s.stack.Destroy()
	}
	if s.iface != nil {
		err := s.iface.Close()
		if err != nil {
			logrus.Warn("NetStack.Close() => iface close err: ", err)
		}
	}
}
