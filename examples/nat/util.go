// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"fmt"
	"log"
	"os"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/packet"
)

func (t *Tuple) String() string {
	return fmt.Sprintf("addr = %d.%d.%d.%d:%d",
		(t.addr>>24)&0xff,
		(t.addr>>16)&0xff,
		(t.addr>>8)&0xff,
		t.addr&0xff,
		t.port)
}

func StringIPv4Int(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(addr>>24)&0xff,
		(addr>>16)&0xff,
		(addr>>8)&0xff,
		addr&0xff)
}

func StringIPv4Array(addr [common.IPv4AddrLen]uint8) string {
	return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
}

func StringMAC(mac [common.EtherAddrLen]uint8) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func swapAddrIPv4(pkt *packet.Packet) {
	ipv4 := pkt.GetIPv4NoCheck()

	pkt.Ether.SAddr, pkt.Ether.DAddr = pkt.Ether.DAddr, pkt.Ether.SAddr
	ipv4.SrcAddr, ipv4.DstAddr = ipv4.DstAddr, ipv4.SrcAddr
}

func startTrace(name string, aindex, index int, isPrivate interfaceType) *os.File {
	var fname string
	if !dumptogether {
		if isPrivate != 0 {
			fname = fmt.Sprintf("%dpriv%s.pcap", index, name)
		} else {
			fname = fmt.Sprintf("%dpub%s.pcap", index, name)
		}
	} else {
		fname = fmt.Sprintf("%d%s.pcap", index, name)
	}

	file, err := os.Create(fname)
	if err != nil {
		log.Fatal(err)
	}
	packet.WritePcapGlobalHdr(file)
	return file
}

func dumpPacket(pkt *packet.Packet, index int, isPrivate interfaceType) {
	if debugDump {
		aindex := index
		if !dumptogether {
			aindex = index*2 + int(isPrivate)
		}

		dumpsync[aindex].Lock()
		if fdump[aindex] == nil {
			fdump[aindex] = startTrace("dump", aindex, index, isPrivate)
		}

		err := pkt.WritePcapOnePacket(fdump[aindex])
		if err != nil {
			log.Fatal(err)
		}
		dumpsync[aindex].Unlock()
	}
}

func dumpDrop(pkt *packet.Packet, index int, isPrivate interfaceType) {
	if debugDrop {
		aindex := index
		if !dumptogether {
			aindex = index*2 + int(isPrivate)
		}
		dropsync[aindex].Lock()
		if fdrop[aindex] == nil {
			fdrop[aindex] = startTrace("drop", aindex, index, isPrivate)
		}
		err := pkt.WritePcapOnePacket(fdrop[aindex])
		if err != nil {
			log.Fatal(err)
		}
		dropsync[aindex].Unlock()
	}
}

// CloseAllDumpFiles closes all debug dump files.
func CloseAllDumpFiles() {
	if debugDump {
		debugDump = false
		for i := range fdump {
			if fdump[i] != nil {
				fdump[i].Close()
			}
		}
	}
	if debugDrop {
		debugDrop = false
		for i := range fdrop {
			if fdump[i] != nil {
				fdump[i].Close()
			}
		}
	}
}
