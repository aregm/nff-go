// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/packet"
)

type dhcpv6State struct {
	lastDHCPv6PacketTypeSent layers.DHCPv6MsgType
	dhcpv6TransactionId      [3]byte
}

const (
	DHCPv6ClientPort = 546
	DHCPv6ServerPort = 547
)

var (
	BroadcastIPv6 = [common.IPv6AddrLen]uint8{
		0xff, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x02,
	}
	SingleIPMask = [common.IPv6AddrLen]uint8{
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
	}
	SingleIPNetMask = net.CIDRMask(128, 128)
	hardwareTypeId  = []byte{0, 3}
)

func getDHCPv6Option(options layers.DHCPv6Options, optionType layers.DHCPv6Opt) *layers.DHCPv6Option {
	for i := range options {
		if options[i].Code == optionType {
			return &options[i]
		}
	}
	return nil
}

func (port *ipPort) composeAndSendDHCPv6Packet(packetType layers.DHCPv6MsgType, options []layers.DHCPv6Option) {
	dhcpv6 := &layers.DHCPv6{
		MsgType: packetType,
	}
	copy(dhcpv6.TransactionID, port.Subnet6.ds.dhcpv6TransactionId[:])

	dhcpv6.Options = append(dhcpv6.Options, options...)
	// Add client ID and FQDN options
	clientID := &layers.DHCPv6DUID{
		Type:         layers.DHCPv6DUIDTypeLL,
		HardwareType: hardwareTypeId,
	}
	clientID.LinkLayerAddress = make([]byte, len(port.SrcMACAddress))
	copy(clientID.LinkLayerAddress, port.SrcMACAddress[:])
	fqdn := DHCPv6FQDN{
		DomainName: Natconfig.HostName,
	}
	dhcpv6.Options = append(dhcpv6.Options,
		layers.NewDHCPv6Option(layers.DHCPv6OptClientID, clientID.Encode()),
		layers.NewDHCPv6Option(DHCPv6OptFQDNOptionCode, fqdn.Encode()))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, dhcpv6)
	if err != nil {
		common.LogFatal(common.No, err)
	}

	// Convert gopacket data structure into NFF-Go packet and send it
	pkt, err := packet.NewPacket()
	if err != nil {
		println(err)
	}
	payloadBuffer := buf.Bytes()
	packet.InitEmptyIPv6UDPPacket(pkt, uint(len(payloadBuffer)))

	// Fill up L2
	pkt.Ether.SAddr = port.SrcMACAddress
	packet.CalculateIPv6BroadcastMACForDstMulticastIP(&pkt.Ether.DAddr, BroadcastIPv6)

	// Fill up L3
	ipv6 := pkt.GetIPv6NoCheck()
	ipv6.SrcAddr = port.Subnet6.llAddr
	ipv6.DstAddr = BroadcastIPv6
	ipv6.HopLimits = 1

	// Fill up L4
	udp := pkt.GetUDPNoCheck()
	udp.SrcPort = packet.SwapBytesUint16(DHCPv6ClientPort)
	udp.DstPort = packet.SwapBytesUint16(DHCPv6ServerPort)

	// Fill up L7
	payload, _ := pkt.GetPacketPayload()
	copy(payload, payloadBuffer)

	if port.Vlan != 0 {
		pkt.AddVLANTag(port.Vlan)
	}

	setIPv6UDPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
	port.dumpPacket(pkt, dirSEND)
	pkt.SendPacket(port.Index)

	port.Subnet6.ds.lastDHCPv6PacketTypeSent = packetType
}

func (port *ipPort) checkDHCPv6ServerAnswerAndGetIANA(dhcpv6 *layers.DHCPv6) *layers.DHCPv6Option {
	statusOption := getDHCPv6Option(dhcpv6.Options, layers.DHCPv6OptStatusCode)
	if statusOption == nil {
		println("Warning! Received a DHCPv6 reply without status! Trying again with discover request.")
		port.Subnet6.addressAcquired = false
		port.Subnet6.ds = dhcpv6State{}
		return nil
	}

	status := DHCPv6ServerStatusCode{}
	err := status.DecodeFromBytes(statusOption.Data)
	if err != nil {
		println("Warning! Bad reply from server. Cannot decode status option: ", err)
		port.Subnet6.addressAcquired = false
		port.Subnet6.ds = dhcpv6State{}
		return nil
	}

	if layers.DHCPv6StatusCode(status.StatusCode) != layers.DHCPv6StatusCodeSuccess {
		println("Warning! Server returned status", layers.DHCPv6StatusCode(status.StatusCode).String(), status.StatusMessage)
		port.Subnet6.addressAcquired = false
		port.Subnet6.ds = dhcpv6State{}
		return nil
	}

	// Ignore multiple IA_NA options in DHCP server reply. Use the first one.
	ianaOption := getDHCPv6Option(dhcpv6.Options, layers.DHCPv6OptIANA)
	if ianaOption == nil {
		println("Warning! Received a DHCPv6 reply without IANA! Trying again with discover request.")
		port.Subnet6.addressAcquired = false
		port.Subnet6.ds = dhcpv6State{}
		return nil
	}

	return ianaOption
}

func (port *ipPort) sendDHCPv6SolicitRequest() {
	// Create new transaction ID
	port.Subnet6.ds.dhcpv6TransactionId = [3]byte{
		uint8(rnd.Uint32()),
		uint8(rnd.Uint32()),
		uint8(rnd.Uint32()),
	}
	iana := DHCPv6IANA{
		IAID:    rnd.Uint32(),
		Options: layers.DHCPv6Options{},
	}
	port.composeAndSendDHCPv6Packet(layers.DHCPv6MsgTypeSolicit,
		[]layers.DHCPv6Option{layers.NewDHCPv6Option(layers.DHCPv6OptIANA, iana.Encode())})
}

func (port *ipPort) handleDHCPv6Advertise(pkt *packet.Packet, dhcpv6 *layers.DHCPv6) {
	// Send request packet
	ianaOption := port.checkDHCPv6ServerAnswerAndGetIANA(dhcpv6)
	if ianaOption == nil {
		println("Warning! No IANA option in server Advertise packet!")
		port.Subnet6.addressAcquired = false
		port.Subnet6.ds = dhcpv6State{}
		return
	}
	options := []layers.DHCPv6Option{*ianaOption}
	serverID := getDHCPv6Option(dhcpv6.Options, layers.DHCPv6OptServerID)
	if serverID != nil {
		options = append(options, *serverID)
	}
	port.composeAndSendDHCPv6Packet(layers.DHCPv6MsgTypeRequest, options)
}

func (port *ipPort) handleDHCPv6(pkt *packet.Packet) bool {
	if port.Subnet6.addressAcquired {
		// Port already has address, ignore this traffic
		return false
	}

	// Check that this is DHCP offer or acknowledgement traffic
	if pkt.GetUDPNoCheck().DstPort != packet.SwapBytesUint16(DHCPv6ClientPort) ||
		pkt.GetUDPNoCheck().SrcPort != packet.SwapBytesUint16(DHCPv6ServerPort) {
		return false
	}

	var dhcpv6 layers.DHCPv6
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeDHCPv6, &dhcpv6)
	payload, _ := pkt.GetPacketPayload()
	decoded := []gopacket.LayerType{}
	err := parser.DecodeLayers(payload, &decoded)

	if err != nil || len(decoded) != 1 || decoded[0] != layers.LayerTypeDHCPv6 {
		println("Warning! Failed to parse DHCPv6 packet", err)
		return false
	}

	if port.Subnet6.ds.lastDHCPv6PacketTypeSent == layers.DHCPv6MsgTypeSolicit && dhcpv6.MsgType == layers.DHCPv6MsgTypeAdverstise {
		port.handleDHCPv6Advertise(pkt, &dhcpv6)
	} else if port.Subnet6.ds.lastDHCPv6PacketTypeSent == layers.DHCPv6MsgTypeRequest && dhcpv6.MsgType == layers.DHCPv6MsgTypeReply {
		port.handleDHCPv6Reply(pkt, &dhcpv6)
	} else {
		println("Warning! Received some bad response from DHCPv6 server", dhcpv6.MsgType.String())
		port.Subnet6.addressAcquired = false
		port.Subnet6.ds = dhcpv6State{}
	}
	return true
}

func (port *ipPort) handleDHCPv6Reply(pkt *packet.Packet, dhcpv6 *layers.DHCPv6) {
	ianaOption := port.checkDHCPv6ServerAnswerAndGetIANA(dhcpv6)
	if ianaOption == nil {
		println("Warning! No IANA option in server Reply packet!")
		port.Subnet6.addressAcquired = false
		port.Subnet6.ds = dhcpv6State{}
		return
	}

	var iana DHCPv6IANA
	err := iana.DecodeFromBytes(ianaOption.Data)
	if err != nil {
		println("Warning! Bad reply from server. Cannot decode IANA option: ", err)
		port.Subnet6.addressAcquired = false
		port.Subnet6.ds = dhcpv6State{}
		return
	}

	// Ignore multiple addresses in DHCP server reply. Use the first one.
	addressOption := getDHCPv6Option(iana.Options, layers.DHCPv6OptIAAddr)
	if addressOption == nil {
		println("Warning! Received a DHCPv6 reply with IANA which contains no address! Trying again with discover request.")
		port.Subnet6.addressAcquired = false
		port.Subnet6.ds = dhcpv6State{}
		return
	}

	var ia DHCPv6IAAddress
	err = ia.DecodeFromBytes(addressOption.Data)
	if err != nil {
		println("Warning! Bad reply from server. Cannot decode IA Address option: ", err)
		port.Subnet6.addressAcquired = false
		port.Subnet6.ds = dhcpv6State{}
		return
	}

	copy(port.Subnet6.Addr[:], ia.Address.To16())
	packet.CalculateIPv6MulticastAddrForDstIP(&port.Subnet6.multicastAddr, port.Subnet6.Addr)
	port.Subnet6.Mask = SingleIPMask
	port.Subnet6.addressAcquired = true
	println("Successfully acquired IP address:", port.Subnet6.String(), "on port", port.Index)

	// Set address on KNI interface if present
	port.setLinkLocalIPv6KNIAddress(port.Subnet6.Addr, port.Subnet6.Mask)
}

type DHCPv6FQDNFlags byte

const (
	DHCPv6OptFQDNOptionCode                layers.DHCPv6Opt = 39
	DHCPv6FQDNOptionServerUpdateForwardDNS DHCPv6FQDNFlags  = 1
	DHCPv6FQDNOptionServerOverride         DHCPv6FQDNFlags  = 2
	DHCPv6FQDNOptionServerNoDNSUpdate      DHCPv6FQDNFlags  = 4
)

// FQDN option encoded according to RFC 4704
type DHCPv6FQDN struct {
	Flags      DHCPv6FQDNFlags
	DomainName string
}

func (fqdn *DHCPv6FQDN) Encode() []byte {
	encoded := []byte{
		byte(fqdn.Flags),
	}
	names := strings.Split(fqdn.DomainName, ".")
	for i := range names {
		b := []byte(names[i])
		encoded = append(encoded, byte(len(b)))
		encoded = append(encoded, b...)
	}
	encoded = append(encoded, byte(0))
	return encoded
}

func (fqdn *DHCPv6FQDN) DecodeFromBytes(data []byte) error {
	datalength := len(data)
	if datalength < 2 {
		return errors.New("Not enough bytes to decode: " + string(len(data)))
	}

	fqdn.Flags = DHCPv6FQDNFlags(data[0])

	index := 2
	fqdn.DomainName = ""
	length := int(data[index-1])
	for length != 0 {
		if datalength-index < length+1 {
			return errors.New("Option encoded incorrectly, not enough bytes to decode")
		}
		fqdn.DomainName += string(data[index : index+length])
		index += length + 1
		length = int(data[index-1])
	}
	return nil
}

// Server status code option
type DHCPv6ServerStatusCode struct {
	StatusCode    uint16
	StatusMessage string
}

func (sc *DHCPv6ServerStatusCode) Encode() []byte {
	messageBytes := []byte(sc.StatusMessage)
	length := 2 + len(messageBytes)
	data := make([]byte, length)
	binary.BigEndian.PutUint16(data[0:2], uint16(sc.StatusCode))
	copy(data[2:], messageBytes)
	return data
}

func (sc *DHCPv6ServerStatusCode) DecodeFromBytes(data []byte) error {
	if len(data) < 2 {
		return errors.New("Not enough bytes to decode: " + string(len(data)))
	}

	sc.StatusCode = binary.BigEndian.Uint16(data[:2])
	sc.StatusMessage = string(data[2:])
	return nil
}

// Returns length of data portion of option (excluding IANA code 3 and
// option length)
func OptionsLen(options layers.DHCPv6Options) int {
	n := 0
	for _, o := range options {
		n += int(o.Length) + 4
	}
	return n
}

// Identity Association for Non-temporary Addresses Option
type DHCPv6IANA struct {
	IAID    uint32
	T1, T2  uint32
	Options layers.DHCPv6Options
}

func (iana *DHCPv6IANA) Encode() []byte {
	data := make([]byte, 12+OptionsLen(iana.Options))
	binary.BigEndian.PutUint32(data[0:4], iana.IAID)
	binary.BigEndian.PutUint32(data[4:8], iana.T1)
	binary.BigEndian.PutUint32(data[8:12], iana.T2)
	offset := 12

	for _, o := range iana.Options {
		// TODO: use (*DHCPv6Option) encode here
		binary.BigEndian.PutUint16(data[offset:offset+2], uint16(o.Code))
		binary.BigEndian.PutUint16(data[offset+2:offset+4], o.Length)
		copy(data[offset+4:], o.Data)
		offset += int(o.Length) + 4
	}
	return data
}

func (iana *DHCPv6IANA) DecodeFromBytes(data []byte) error {
	if len(data) < 12 {
		return errors.New("Not enough bytes to decode: " + string(len(data)))
	}

	iana.IAID = binary.BigEndian.Uint32(data[:4])
	iana.T1 = binary.BigEndian.Uint32(data[4:8])
	iana.T2 = binary.BigEndian.Uint32(data[8:12])
	iana.Options = iana.Options[:0]
	offset := 12

	stop := len(data)
	for offset < stop {
		// TODO: use (*DHCPv6Option) decode here
		o := layers.DHCPv6Option{}
		o.Code = layers.DHCPv6Opt(binary.BigEndian.Uint16(data[offset : offset+2]))
		o.Length = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		o.Data = data[offset+4 : offset+4+int(o.Length)]
		iana.Options = append(iana.Options, o)
		offset += int(o.Length) + 4
	}
	return nil
}

// IA Address Option
type DHCPv6IAAddress struct {
	Address           net.IP
	PreferredLifetime uint32
	ValidLifetime     uint32
	Options           layers.DHCPv6Options
}

func (ia *DHCPv6IAAddress) Encode() []byte {
	data := make([]byte, 16+4+4+OptionsLen(ia.Options))
	copy(data[:16], ia.Address.To16())
	binary.BigEndian.PutUint32(data[16:20], ia.PreferredLifetime)
	binary.BigEndian.PutUint32(data[20:24], ia.ValidLifetime)
	offset := 24

	for _, o := range ia.Options {
		// TODO: use (*DHCPv6Option) encode here
		binary.BigEndian.PutUint16(data[offset:offset+2], uint16(o.Code))
		binary.BigEndian.PutUint16(data[offset+2:offset+4], o.Length)
		copy(data[offset+4:], o.Data)
		offset += int(o.Length) + 4
	}
	return data
}

func (ia *DHCPv6IAAddress) DecodeFromBytes(data []byte) error {
	if len(data) < 24 {
		return errors.New("Not enough bytes to decode: " + string(len(data)))
	}

	ia.Address = net.IP(data[:16])
	ia.PreferredLifetime = binary.BigEndian.Uint32(data[16:20])
	ia.ValidLifetime = binary.BigEndian.Uint32(data[20:24])
	ia.Options = ia.Options[:0]
	offset := 24

	stop := len(data)
	for offset < stop {
		// TODO: use (*DHCPv6Option) decode here
		o := layers.DHCPv6Option{}
		o.Code = layers.DHCPv6Opt(binary.BigEndian.Uint16(data[offset : offset+2]))
		o.Length = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		o.Data = data[offset+4 : offset+4+int(o.Length)]
		ia.Options = append(ia.Options, o)
		offset += int(o.Length) + 4
	}
	return nil
}
