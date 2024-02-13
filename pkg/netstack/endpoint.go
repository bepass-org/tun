package netstack

import (
	"github.com/bepass-org/tun/internal/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.LinkEndpoint = (*WintunEndpoint)(nil)

type WintunEndpoint struct {
	tunDev     tun.Device
	dispatcher stack.NetworkDispatcher
	mtu        uint32
}

func NewWintunEndpoint(dev tun.Device, mtu uint32) *WintunEndpoint {
	return &WintunEndpoint{
		tunDev: dev,
		mtu:    mtu,
	}
}

// MTU implements stack.LinkEndpoint.
func (m *WintunEndpoint) MTU() uint32 {
	return m.mtu
}

// Capabilities implements stack.LinkEndpoint.
func (m *WintunEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

// MaxHeaderLength implements stack.LinkEndpoint.
func (m *WintunEndpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress implements stack.LinkEndpoint.
func (m *WintunEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

// Attach implements stack.LinkEndpoint.
func (m *WintunEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	m.dispatcher = dispatcher
	go m.dispatchLoop()
}

func (m *WintunEndpoint) dispatchLoop() {
	var packetSizes [1]int
	for {
		packetBuf := make([][]byte, 1)
		packetBuf[0] = make([]byte, m.mtu)
		n, err := m.tunDev.Read(packetBuf, packetSizes[:], 0)
		if n == 0 || err != nil {
			break
		}

		if !m.IsAttached() {
			continue
		}

		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packetBuf[0][:packetSizes[0]]),
		})

		switch header.IPVersion(packetBuf[0]) {
		case header.IPv4Version:
			m.dispatcher.DeliverNetworkPacket(header.IPv4ProtocolNumber, pkb)
		case header.IPv6Version:
			m.dispatcher.DeliverNetworkPacket(header.IPv6ProtocolNumber, pkb)
		default:
			pkb.DecRef() // Release the packet buffer if it's not IPv4 or IPv6
		}
	}
}

// IsAttached implements stack.LinkEndpoint.
func (m *WintunEndpoint) IsAttached() bool {
	return m.dispatcher != nil
}

// WritePackets writes outbound packets
func (m *WintunEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	var n int
	for _, packet := range pkts.AsSlice() {
		packetData := packet.AsSlices()
		if len(packetData) == 0 {
			continue // Skip empty packets
		}

		written, err := m.tunDev.Write(packetData, 0)
		if err != nil {
			return n, &tcpip.ErrAborted{}
		}
		n += written
	}
	return n, nil
}

// Wait implements stack.LinkEndpoint.Wait.
func (m *WintunEndpoint) Wait() {}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*WintunEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (*WintunEndpoint) AddHeader(pkt stack.PacketBufferPtr) {
}

// WriteRawPacket implements stack.LinkEndpoint.
func (*WintunEndpoint) WriteRawPacket(stack.PacketBufferPtr) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (*WintunEndpoint) ParseHeader(stack.PacketBufferPtr) bool { return true }
