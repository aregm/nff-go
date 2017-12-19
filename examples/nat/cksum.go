// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/packet"
	"unsafe"
)

func setIPv4UDPChecksum(pkt *packet.Packet, calculateChecksum, hWTXChecksum bool) {
	if calculateChecksum {
		l3 := pkt.GetIPv4NoCheck()
		l4 := pkt.GetUDPForIPv4NoCheck()
		if hWTXChecksum {
			l3.HdrChecksum = 0
			l4.DgramCksum = packet.SwapBytesUint16(packet.CalculatePseudoHdrIPv4UDPCksum(l3, l4))
			l2len := uint32(common.EtherLen)
			if pkt.Ether.EtherType == common.VLANNumber {
				l2len += common.VLANLen
			}
			pkt.SetTXIPv4UDPOLFlags(l2len, common.IPv4MinLen)
		} else {
			l3.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(l3))
			l4.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(l3, l4,
				unsafe.Pointer(uintptr(unsafe.Pointer(l4))+uintptr(common.UDPLen))))
		}
	}
}

func setIPv4TCPChecksum(pkt *packet.Packet, calculateChecksum, hWTXChecksum bool) {
	if calculateChecksum {
		l3 := pkt.GetIPv4NoCheck()
		l4 := pkt.GetTCPForIPv4NoCheck()
		if hWTXChecksum {
			l3.HdrChecksum = 0
			l4.Cksum = packet.SwapBytesUint16(packet.CalculatePseudoHdrIPv4TCPCksum(l3))
			l2len := uint32(common.EtherLen)
			if pkt.Ether.EtherType == common.VLANNumber {
				l2len += common.VLANLen
			}
			pkt.SetTXIPv4TCPOLFlags(l2len, common.IPv4MinLen)
		} else {
			l3.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(l3))
			l4.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(l3, l4,
				unsafe.Pointer(uintptr(unsafe.Pointer(l4))+common.TCPMinLen)))
		}
	}
}

func setIPv4ICMPChecksum(pkt *packet.Packet, calculateChecksum, hWTXChecksum bool) {
	if CalculateChecksum {
		l3 := pkt.GetIPv4NoCheck()
		if HWTXChecksum {
			l3.HdrChecksum = 0
			l2len := uint32(common.EtherLen)
			if pkt.Ether.EtherType == common.VLANNumber {
				l2len += common.VLANLen
			}
			pkt.SetTXIPv4OLFlags(l2len, common.IPv4MinLen)
		} else {
			l3.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(l3))
		}
		l4 := pkt.GetICMPForIPv4NoCheck()
		l4.Cksum = 0
		l4.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(l3, l4, pkt.Data))
	}
}
