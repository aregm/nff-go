// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/packet"
)

type dhcpState struct {
	lastDHCPPacketTypeSent layers.DHCPMsgType
	dhcpTransactionId      uint32
}

const (
	requestInterval = 10 * time.Second
	DHCPServerPort  = 67
	DHCPClientPort  = 68
	BroadcastIPv4   = uint32(0xffffffff)
)

var (
	rnd          = rand.New(rand.NewSource(time.Now().UnixNano()))
	BroadcastMAC = [common.EtherAddrLen]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	dhcpOptions  = []layers.DHCPOption{
		layers.NewDHCPOption(layers.DHCPOptParamsRequest,
			[]byte{
				byte(layers.DHCPOptSubnetMask),
				byte(layers.DHCPOptBroadcastAddr),
				byte(layers.DHCPOptTimeOffset),
				byte(layers.DHCPOptRouter),
				byte(layers.DHCPOptDomainName),
				byte(layers.DHCPOptDNS),
				byte(layers.DHCPOptDomainSearch),
				byte(layers.DHCPOptHostname),
				byte(layers.DHCPOptInterfaceMTU),
			},
		),
	}
	dhcpRequestPacket = layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		ClientIP: net.IP{
			0, 0, 0, 0,
		},
		YourClientIP: net.IP{
			0, 0, 0, 0,
		},
		NextServerIP: net.IP{
			0, 0, 0, 0,
		},
		RelayAgentIP: net.IP{
			0, 0, 0, 0,
		},
	}
)

func StartDHCPClient() {
	go func() {
		sendDHCPRequests()
	}()
}

func sendDHCPRequests() {
	// Endless loop of sending DHCP requests
	for {
		for i := range Natconfig.PortPairs {
			pp := &Natconfig.PortPairs[i]
			if !pp.PublicPort.Subnet.addressAcquired {
				pp.PublicPort.sendDHCPDiscoverRequest()
			}
			if !pp.PublicPort.Subnet6.addressAcquired {
				pp.PublicPort.setLinkLocalIPv6KNIAddress(pp.PublicPort.Subnet6.llAddr, SingleIPMask)
				pp.PublicPort.sendDHCPv6SolicitRequest()
			}
			if !pp.PrivatePort.Subnet.addressAcquired {
				pp.PrivatePort.sendDHCPDiscoverRequest()
			}
			if !pp.PrivatePort.Subnet6.addressAcquired {
				pp.PrivatePort.setLinkLocalIPv6KNIAddress(pp.PrivatePort.Subnet6.llAddr, SingleIPMask)
				pp.PrivatePort.sendDHCPv6SolicitRequest()
			}
		}
		time.Sleep(requestInterval)
	}
}

func getDHCPOption(dhcp *layers.DHCPv4, optionType layers.DHCPOpt) *layers.DHCPOption {
	for i := range dhcp.Options {
		if dhcp.Options[i].Type == optionType {
			return &dhcp.Options[i]
		}
	}
	return nil
}

func (port *ipPort) composeAndSendDHCPPacket(packetType layers.DHCPMsgType, options []layers.DHCPOption) {
	hwa := make([]byte, common.EtherAddrLen)
	copy(hwa, port.SrcMACAddress[:])

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Make local copy for modifications
	dhcp := dhcpRequestPacket
	dhcp.Xid = port.Subnet.ds.dhcpTransactionId
	dhcp.ClientHWAddr = hwa
	options = append(options,
		layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(packetType)}),
		layers.NewDHCPOption(layers.DHCPOptHostname, []byte(Natconfig.HostName)))
	dhcp.Options = options
	err := gopacket.SerializeLayers(buf, opts, &dhcp)
	if err != nil {
		common.LogFatal(common.No, err)
	}

	// Convert gopacket data structure into NFF-Go packet and send it
	pkt, err := packet.NewPacket()
	if err != nil {
		println(err)
	}
	payloadBuffer := buf.Bytes()
	packet.InitEmptyIPv4UDPPacket(pkt, uint(len(payloadBuffer)))

	// Fill up L2
	pkt.Ether.SAddr = port.SrcMACAddress
	pkt.Ether.DAddr = BroadcastMAC

	// Fill up L3
	pkt.GetIPv4NoCheck().SrcAddr = uint32(0)
	pkt.GetIPv4NoCheck().DstAddr = BroadcastIPv4

	// Fill up L4
	pkt.GetUDPNoCheck().SrcPort = packet.SwapBytesUint16(DHCPClientPort)
	pkt.GetUDPNoCheck().DstPort = packet.SwapBytesUint16(DHCPServerPort)

	payload, _ := pkt.GetPacketPayload()
	copy(payload, payloadBuffer)

	if port.Vlan != 0 {
		pkt.AddVLANTag(port.Vlan)
	}

	setIPv4UDPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
	port.dumpPacket(pkt, dirSEND)
	pkt.SendPacket(port.Index)

	port.Subnet.ds.lastDHCPPacketTypeSent = packetType
}

func (port *ipPort) sendDHCPDiscoverRequest() {
	port.Subnet.ds.dhcpTransactionId = rnd.Uint32()
	port.composeAndSendDHCPPacket(layers.DHCPMsgTypeDiscover, dhcpOptions)
}

func (port *ipPort) sendDHCPRequestRequest(serverIP, clientIP []byte) {
	port.composeAndSendDHCPPacket(layers.DHCPMsgTypeRequest, append(dhcpOptions,
		layers.NewDHCPOption(layers.DHCPOptServerID, serverIP),
		layers.NewDHCPOption(layers.DHCPOptRequestIP, clientIP)))
}

func (port *ipPort) handleDHCP(pkt *packet.Packet) bool {
	if port.Subnet.addressAcquired {
		// Port already has address, ignore this traffic
		return false
	}

	// Check that this is DHCP offer or acknowledgement traffic
	if pkt.GetUDPNoCheck().DstPort != packet.SwapBytesUint16(DHCPClientPort) ||
		pkt.GetUDPNoCheck().SrcPort != packet.SwapBytesUint16(DHCPServerPort) {
		return false
	}

	var dhcp layers.DHCPv4
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeDHCPv4, &dhcp)
	payload, _ := pkt.GetPacketPayload()
	decoded := []gopacket.LayerType{}
	err := parser.DecodeLayers(payload, &decoded)

	if err != nil || len(decoded) != 1 || decoded[0] != layers.LayerTypeDHCPv4 {
		println("Warning! Failed to parse DHCP packet", err)
		return false
	}

	dhcpMessageType := getDHCPOption(&dhcp, layers.DHCPOptMessageType)
	if dhcpMessageType == nil {
		println("Warning! DHCP packet without message type received")
		return false
	}

	if port.Subnet.ds.lastDHCPPacketTypeSent == layers.DHCPMsgTypeDiscover &&
		dhcpMessageType.Data[0] == byte(layers.DHCPMsgTypeOffer) {
		port.handleDHCPOffer(pkt, &dhcp)
	} else if port.Subnet.ds.lastDHCPPacketTypeSent == layers.DHCPMsgTypeRequest &&
		dhcpMessageType.Data[0] == byte(layers.DHCPMsgTypeAck) {
		port.handleDHCPAck(pkt, &dhcp)
	} else {
		println("Warning! Received some bad response from DHCP server. Trying again with discover request.")
		port.Subnet.addressAcquired = false
		port.Subnet.ds = dhcpState{}
	}
	return true
}

func (port *ipPort) handleDHCPOffer(pkt *packet.Packet, dhcp *layers.DHCPv4) {
	port.sendDHCPRequestRequest(dhcp.NextServerIP, dhcp.YourClientIP)
}

func (port *ipPort) handleDHCPAck(pkt *packet.Packet, dhcp *layers.DHCPv4) {
	maskOption := getDHCPOption(dhcp, layers.DHCPOptSubnetMask)
	if maskOption == nil {
		println("Warning! Received a DHCP response without subnet mask! Trying again with discover request.")
		port.Subnet.addressAcquired = false
		port.Subnet.ds = dhcpState{}
		return
	}
	port.Subnet.Addr, _ = convertIPv4(dhcp.YourClientIP.To4())
	port.Subnet.Mask, _ = convertIPv4(maskOption.Data)
	port.Subnet.addressAcquired = true
	println("Successfully acquired IP address:", port.Subnet.String(), "on port", port.Index)

	// Set address on KNI interface if present
	port.setLinkLocalIPv4KNIAddress(port.Subnet.Addr, port.Subnet.Mask)
}
