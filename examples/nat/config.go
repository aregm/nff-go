// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/flow"
)

type terminationDirection uint8
type interfaceType int

const (
	flowDrop   = 0
	flowBack   = 1
	flowOut    = 2
	totalFlows = 3

	pri2pub terminationDirection = 0x0f
	pub2pri terminationDirection = 0xf0

	iPUBLIC  interfaceType = 0
	iPRIVATE interfaceType = 1

	connectionTimeout time.Duration = 1 * time.Minute
	portReuseTimeout  time.Duration = 1 * time.Second
)

type ipv4Subnet struct {
	Addr uint32
	Mask uint32
}

type macAddress [common.EtherAddrLen]uint8

type portMapEntry struct {
	lastused             time.Time
	addr                 uint32
	finCount             uint8
	terminationDirection terminationDirection
}

// Type describing a network port
type ipv4Port struct {
	Index         uint8      `json:"index"`
	DstMACAddress macAddress `json:"dst-mac"`
	Subnet        ipv4Subnet `json:"subnet"`
	Vlan          uint16     `json:"vlan-tag"`
	SrcMACAddress macAddress
	// ARP lookup table
	ArpTable sync.Map
}

// Config for one port pair.
type portPair struct {
	PrivatePort ipv4Port `json:"private-port"`
	PublicPort  ipv4Port `json:"public-port"`
	// Main lookup table which contains entries for private to public translation
	pri2pubTable []sync.Map
	// Main lookup table which contains entries for public to private translation
	pub2priTable []sync.Map
	// Synchronization point for lookup table modifications
	mutex sync.Mutex
	// Map of allocated IP ports on public interface
	portmap [][]portMapEntry
	// Port that was allocated last
	lastport int
	// Maximum allowed port number
	maxport int
}

// Config for NAT.
type Config struct {
	PortPairs []portPair `json:"port-pairs"`
}

// Type used to pass handler index to translation functions.
type pairIndex struct {
	index int
}

var (
	// Natconfig is a config file.
	Natconfig *Config
	// CalculateChecksum is a flag whether checksums should be
	// calculated for modified packets.
	CalculateChecksum bool
	// HWTXChecksum is a flag whether checksums calculation should be
	// offloaded to HW.
	HWTXChecksum bool

	// Debug variables
	debugDump = false
	debugDrop = false
	// Controls whether debug dump files are separate for private and
	// public interface or both traces are dumped in the same file.
	dumptogether = false
	fdump        []*os.File
	dumpsync     []sync.Mutex
	fdrop        []*os.File
	dropsync     []sync.Mutex
)

func (pi pairIndex) Copy() interface{} {
	return pairIndex{
		index: pi.index,
	}
}

func (pi pairIndex) Delete() {
}

func convertIPv4(in []byte) (uint32, error) {
	if in == nil || len(in) > 4 {
		return 0, errors.New("Only IPv4 addresses are supported now")
	}

	addr := (uint32(in[0]) << 24) | (uint32(in[1]) << 16) |
		(uint32(in[2]) << 8) | uint32(in[3])

	return addr, nil
}

// UnmarshalJSON parses ipv 4 subnet details.
func (out *ipv4Subnet) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	if ip, ipnet, err := net.ParseCIDR(s); err == nil {
		if out.Addr, err = convertIPv4(ip.To4()); err != nil {
			return err
		}
		if out.Mask, err = convertIPv4(ipnet.Mask); err != nil {
			return err
		}
		return nil
	}

	if ip := net.ParseIP(s); ip != nil {
		var err error
		if out.Addr, err = convertIPv4(ip.To4()); err != nil {
			return err
		}
		out.Mask = 0xffffffff
		return nil
	}
	return errors.New("Failed to parse address " + s)
}

// UnmarshalJSON parses MAC address.
func (out *macAddress) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	hw, err := net.ParseMAC(s)
	if err != nil {
		return err
	}

	copy(out[:], hw)
	return nil
}

// ReadConfig function reads and parses config file
func ReadConfig(fileName string) error {
	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(file)

	err = decoder.Decode(&Natconfig)
	if err != nil {
		return err
	}

	for i := range Natconfig.PortPairs {
		pp := &Natconfig.PortPairs[i]
		if pp.PrivatePort.Vlan == 0 && pp.PublicPort.Vlan != 0 {
			return errors.New("Private port with index " +
				strconv.Itoa(int(pp.PrivatePort.Index)) +
				" has zero vlan tag while public port with index " +
				strconv.Itoa(int(pp.PublicPort.Index)) +
				" has non-zero vlan tag. Transition between VLAN-enabled and VLAN-disabled networks is not supported yet.")
		} else if pp.PrivatePort.Vlan != 0 && pp.PublicPort.Vlan == 0 {
			return errors.New("Private port with index " +
				strconv.Itoa(int(pp.PrivatePort.Index)) +
				" has non-zero vlan tag while public port with index " +
				strconv.Itoa(int(pp.PublicPort.Index)) +
				" has zero vlan tag. Transition between VLAN-enabled and VLAN-disabled networks is not supported yet.")
		}
	}

	return nil
}

// Reads MAC addresses for local interfaces into pair ports.
func (pp *portPair) initLocalMACs() {
	pp.PublicPort.SrcMACAddress = flow.GetPortMACAddress(pp.PublicPort.Index)
	pp.PrivatePort.SrcMACAddress = flow.GetPortMACAddress(pp.PrivatePort.Index)
}

func (pp *portPair) allocatePortMap() {
	pp.maxport = portEnd
	pp.portmap = make([][]portMapEntry, common.UDPNumber+1)
	pp.portmap[common.ICMPNumber] = make([]portMapEntry, pp.maxport)
	pp.portmap[common.TCPNumber] = make([]portMapEntry, pp.maxport)
	pp.portmap[common.UDPNumber] = make([]portMapEntry, pp.maxport)
	pp.lastport = portStart
}

func (pp *portPair) allocateLookupMap() {
	pp.pri2pubTable = make([]sync.Map, common.UDPNumber+1)
	pp.pub2priTable = make([]sync.Map, common.UDPNumber+1)
}

// InitFlows initializes flow graph for all interface pairs.
func InitFlows() {
	for i := range Natconfig.PortPairs {
		pp := &Natconfig.PortPairs[i]

		// Init port pairs state
		pp.initLocalMACs()
		pp.allocatePortMap()
		pp.allocateLookupMap()

		// Handler context with handler index
		context := new(pairIndex)
		context.index = i

		// Initialize public to private flow
		publicToPrivate, err := flow.SetReceiver(pp.PublicPort.Index)
		if err != nil {
			log.Fatal(err)
		}
		fromPublic, err := flow.SetSplitter(publicToPrivate, PublicToPrivateTranslation,
			totalFlows, context)
		if err != nil {
			log.Fatal(err)
		}
		err = flow.SetStopper(fromPublic[flowDrop])
		if err != nil {
			log.Fatal(err)
		}

		// Initialize private to public flow
		privateToPublic, err := flow.SetReceiver(pp.PrivatePort.Index)
		if err != nil {
			log.Fatal(err)
		}
		fromPrivate, err := flow.SetSplitter(privateToPublic, PrivateToPublicTranslation,
			totalFlows, context)
		if err != nil {
			log.Fatal(err)
		}
		err = flow.SetStopper(fromPrivate[flowDrop])
		if err != nil {
			log.Fatal(err)
		}

		// ARP packets from public go back to public
		toPublic, err := flow.SetMerger(fromPublic[flowBack], fromPrivate[flowOut])
		if err != nil {
			log.Fatal(err)
		}
		// ARP packets from private go back to private
		toPrivate, err := flow.SetMerger(fromPrivate[flowBack], fromPublic[flowOut])
		if err != nil {
			log.Fatal(err)
		}

		err = flow.SetSender(toPrivate, pp.PrivatePort.Index)
		if err != nil {
			log.Fatal(err)
		}
		err = flow.SetSender(toPublic, pp.PublicPort.Index)
		if err != nil {
			log.Fatal(err)
		}
	}

	asize := len(Natconfig.PortPairs)
	if !dumptogether {
		asize *= 2
	}
	if debugDump {
		fdump = make([]*os.File, asize)
		dumpsync = make([]sync.Mutex, asize)
	}
	if debugDrop {
		fdrop = make([]*os.File, asize)
		dropsync = make([]sync.Mutex, asize)
	}
}
