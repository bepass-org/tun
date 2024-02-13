package netstack

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type TunConn struct {
	Protocol tcpip.TransportProtocolNumber
	Handler  interface{}
}

// IsTCP check if the current TunConn is TCP
func (t TunConn) IsTCP() bool {
	return t.Protocol == tcp.ProtocolNumber
}

// GetTCP returns the handler as a TCPConn
func (t TunConn) GetTCP() TCPConn {
	return t.Handler.(TCPConn)
}

// IsUDP check if the current TunConn is UDP
func (t TunConn) IsUDP() bool {
	return t.Protocol == udp.ProtocolNumber
}

// GetUDP returns the handler as a UDPConn
func (t TunConn) GetUDP() UDPConn {
	return t.Handler.(UDPConn)
}

// IsICMP check if the current TunConn is ICMP
func (t TunConn) IsICMP() bool {
	return t.Protocol == icmp.ProtocolNumber4
}

// GetICMP returns the handler as a ICMPConn
func (t TunConn) GetICMP() ICMPConn {
	return t.Handler.(ICMPConn)
}

// Terminate is call when connections need to be terminated. For now, this is only useful for TCP connections
func (t TunConn) Terminate(reset bool) {
	if t.IsTCP() {
		t.GetTCP().Request.Complete(reset)
	}
}

// TCPConn represents a TCP Forwarder connection
type TCPConn struct {
	EndpointID stack.TransportEndpointID
	Request    *tcp.ForwarderRequest
}

// UDPConn represents a UDP Forwarder connection
type UDPConn struct {
	EndpointID stack.TransportEndpointID
	Request    *udp.ForwarderRequest
}

// ICMPConn represents a ICMP Packet Buffer
type ICMPConn struct {
	Request stack.PacketBufferPtr
}
