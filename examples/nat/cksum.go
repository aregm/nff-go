// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/packet"
	"unsafe"
)

func setIPv4UDPChecksum(l3 *packet.IPv4Hdr, l4 *packet.UDPHdr,
	CalculateChecksum, HWTXChecksum bool) {
	if CalculateChecksum {
		if HWTXChecksum {
			l3.HdrChecksum = 0
			l4.DgramCksum = packet.SwapBytesUint16(packet.CalculatePseudoHdrIPv4UDPCksum(l3, l4))
		} else {
			l3.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(l3))
			l4.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(l3, l4,
				unsafe.Pointer(uintptr(unsafe.Pointer(l4)) + uintptr(common.UDPLen))))
		}
	}
}

func setIPv4TCPChecksum(l3 *packet.IPv4Hdr, l4 *packet.TCPHdr,
	CalculateChecksum, HWTXChecksum bool) {
	if CalculateChecksum {
		if HWTXChecksum {
			l3.HdrChecksum = 0
			l4.Cksum = packet.SwapBytesUint16(packet.CalculatePseudoHdrIPv4TCPCksum(l3))
		} else {
			l3.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(l3))
			l4.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(l3, l4,
				unsafe.Pointer(uintptr(unsafe.Pointer(l4)) + uintptr(l4.DataOff&0xf0)>>2)))
		}
	}
}

func setIPv4ICMPChecksum(l3 *packet.IPv4Hdr, l4 *packet.ICMPHdr, CalculateChecksum, HWTXChecksum bool) {
	if CalculateChecksum {
		l3.HdrChecksum = 0
		l4.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(l3, l4))
	}
}
