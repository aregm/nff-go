// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"fmt"
	"os"

	"github.com/intel-go/yanff/packet"
)

func (t *Tuple) String() string {
	return fmt.Sprintf("addr = %d.%d.%d.%d:%d",
		(t.addr>>24)&0xff,
		(t.addr>>16)&0xff,
		(t.addr>>8)&0xff,
		t.addr&0xff,
		t.port)
}

func swapAddrIPv4(pkt *packet.Packet) {
	ipv4 := pkt.GetIPv4NoCheck()

	pkt.Ether.SAddr, pkt.Ether.DAddr = pkt.Ether.DAddr, pkt.Ether.SAddr
	ipv4.SrcAddr, ipv4.DstAddr = ipv4.DstAddr, ipv4.SrcAddr
}

func dumpInput(pkt *packet.Packet, index int) {
	if debugDump {
		dumpsync[index].Lock()
		// Dump input packet
		if fdump[index] == nil {
			fdump[index], _ = os.Create(fmt.Sprintf("%ddump.pcap", index))
			packet.WritePcapGlobalHdr(fdump[index])
			pkt.WritePcapOnePacket(fdump[index])
		}

		pkt.WritePcapOnePacket(fdump[index])
		dumpsync[index].Unlock()
	}
}

func dumpOutput(pkt *packet.Packet, index int) {
	if debugDump {
		dumpsync[index].Lock()
		pkt.WritePcapOnePacket(fdump[index])
		dumpsync[index].Unlock()
	}
}

func dumpDrop(pkt *packet.Packet, index int) {
	if debugDrop {
		dropsync[index].Lock()
		// Dump droped input packet
		if fdrop[index] == nil {
			fdrop[index], _ = os.Create(fmt.Sprintf("%ddrop.pcap", index))
			packet.WritePcapGlobalHdr(fdrop[index])
			pkt.WritePcapOnePacket(fdrop[index])
		}

		pkt.WritePcapOnePacket(fdrop[index])
		dropsync[index].Unlock()
	}
}

func CloseAllDumpFiles() {
	for i := range fdump {
		if fdump[i] != nil {
			fdump[i].Close()
		}
	}
	for i := range fdrop {
		if fdump[i] != nil {
			fdump[i].Close()
		}
	}
}
