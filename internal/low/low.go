// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package low

// Libraries below are DPDK libraries. PMD drivers and some basic DPDK
// libraries have to be specified between --whole-archive and
// --start-group options because PMD driver libraries have to be
// linked entirely and dependencies for them have to be resolved
// circularly. Don't add any more libraries inside of --whole-archive
// group of libraries unless they are really necessary there because
// it increases executable size and build time.

/*
#include "low.h"
*/
import "C"

import (
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/intel-go/nff-go/asm"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/types"
)

var (
	CountersEnabledInFramework bool = bool(C.counters_enabled_in_framework)
	UseInterlockedCounters     bool = bool(C.use_interlocked_counters)
	AnalyzePacketSizes         bool = bool(C.analyze_packet_sizes)
)

var ringName = 1

// DirectStop frees mbufs.
func DirectStop(pktsForFreeNumber int, buf []uintptr) {
	C.directStop(C.int(pktsForFreeNumber), (**C.struct_rte_mbuf)(unsafe.Pointer(&(buf[0]))))
}

// DirectSend sends one mbuf.
func DirectSend(m *Mbuf, port uint16) bool {
	return bool(C.directSend((*C.struct_rte_mbuf)(m), C.uint16_t(port)))
}

// Ring is a ring buffer for pointers
type Ring C.struct_nff_go_ring
type Rings []*Ring

// Mbuf is a message buffer.
type Mbuf C.struct_rte_mbuf

// Mempool is a pool of objects.
type Mempool C.struct_rte_mempool

type Port C.struct_cPort

var mbufNumberT uint
var mbufCacheSizeT uint

type mempoolPair struct {
	mempool *C.struct_rte_mempool
	name    string
}

var usedMempools []mempoolPair

func GetPort(n uint16) *Port {
	p := new(Port)
	p.PortId = C.uint16_t(n)
	p.QueuesNumber = 1
	return p
}

func CheckRSSPacketCount(p *Port, queue int16) int64 {
	return int64(C.checkRSSPacketCount((*C.struct_cPort)(p), (C.int16_t(queue))))
}

// GetPortMACAddress gets MAC address of given port.
func GetPortMACAddress(port uint16) [types.EtherAddrLen]uint8 {
	var mac [types.EtherAddrLen]uint8
	var cmac C.struct_rte_ether_addr

	C.rte_eth_macaddr_get(C.uint16_t(port), &cmac)
	for i := range mac {
		mac[i] = uint8(cmac.addr_bytes[i])
	}
	return mac
}

// GetPortByName gets the port id from device name. The device name should be
// specified as below:
//
// - PCIe address (Domain:Bus:Device.Function), for example- 0000:2:00.0
// - SoC device name, for example- fsl-gmac0
// - vdev dpdk name, for example- net_[pcap0|null0|tap0]
func GetPortByName(name string) (uint16, error) {
	var port C.uint16_t
	ret := C.rte_eth_dev_get_port_by_name(C.CString(name), &port)
	switch ret {
	case 0:
		return uint16(port), nil
	case -C.ENODEV, -C.EINVAL:
		msg := common.LogError(common.Debug,
			"GetPortByName cannot find device: no such device")
		return 0, common.WrapWithNFError(nil, msg, common.BadArgument)
	default:
		msg := common.LogError(common.Debug, "GetPortByName got an unknown error")
		return 0, common.WrapWithNFError(nil, msg, common.Fail)
	}
}

// GetNameByPort gets the device name from port id. The device name is specified as below:
//
// - PCIe address (Domain:Bus:Device.Function), for example- 0000:02:00.0
// - SoC device name, for example- fsl-gmac0
// - vdev dpdk name, for example- net_[pcap0|null0|tun0|tap0]
func GetNameByPort(port uint16) (string, error) {
	s := make([]C.char, C.RTE_ETH_NAME_MAX_LEN)
	ret := C.rte_eth_dev_get_name_by_port(C.uint16_t(port), &s[0])
	switch ret {
	case 0:
		return C.GoString(&s[0]), nil
	case -C.EINVAL:
		msg := common.LogError(common.Debug, "GetNameByPort cannot find port")
		return "", common.WrapWithNFError(nil, msg, common.BadArgument)
	default:
		msg := common.LogError(common.Debug, "GetNameByPort got an unknown error")
		return "", common.WrapWithNFError(nil, msg, common.Fail)
	}
}

// GetPacketDataStartPointer returns the pointer to the
// beginning of packet.
func GetPacketDataStartPointer(mb *Mbuf) uintptr {
	return uintptr(mb.buf_addr) + uintptr(mb.data_off)
}

var packetStructSize int

// SetPacketStructSize sets the size of the packet.
func SetPacketStructSize(t int) error {
	if t > C.RTE_PKTMBUF_HEADROOM {
		msg := common.LogError(common.Initialization, "Packet structure can't be placed inside mbuf.",
			"Increase CONFIG_RTE_PKTMBUF_HEADROOM in dpdk/config/common_base and rebuild dpdk.")
		return common.WrapWithNFError(nil, msg, common.PktMbufHeadRoomTooSmall)
	}
	minPacketHeadroom := 64
	if C.RTE_PKTMBUF_HEADROOM-t < minPacketHeadroom {
		common.LogWarning(common.Initialization, "Packet will have only", C.RTE_PKTMBUF_HEADROOM-t,
			"bytes for prepend something, increase CONFIG_RTE_PKTMBUF_HEADROOM in dpdk/config/common_base and rebuild dpdk.")
	}
	packetStructSize = t
	return nil
}

// PrependMbuf prepends length bytes to mbuf data area.
// TODO 4 following functions support only not chained mbufs now
// Heavily based on DPDK rte_pktmbuf_prepend
func PrependMbuf(mb *Mbuf, length uint) bool {
	if C.uint16_t(length) > mb.data_off-C.uint16_t(packetStructSize) {
		return false
	}
	mb.data_off -= C.uint16_t(length)
	mb.data_len += C.uint16_t(length)
	mb.pkt_len += C.uint32_t(length)
	return true
}

// AppendMbuf appends length bytes to mbuf.
// Heavily based on DPDK rte_pktmbuf_append
func AppendMbuf(mb *Mbuf, length uint) bool {
	if C.uint16_t(length) > mb.buf_len-mb.data_off-mb.data_len {
		return false
	}
	mb.data_len += C.uint16_t(length)
	mb.pkt_len += C.uint32_t(length)
	return true
}

// AdjMbuf removes length bytes at mbuf beginning.
// Heavily based on DPDK rte_pktmbuf_adj
func AdjMbuf(m *Mbuf, length uint) bool {
	if C.uint16_t(length) > m.data_len {
		return false
	}
	m.data_off += C.uint16_t(length)
	m.data_len -= C.uint16_t(length)
	m.pkt_len -= C.uint32_t(length)
	return true
}

// TrimMbuf removes length bytes at the mbuf end.
// Heavily based on DPDK rte_pktmbuf_trim
func TrimMbuf(m *Mbuf, length uint) bool {
	if C.uint16_t(length) > m.data_len {
		return false
	}
	m.data_len -= C.uint16_t(length)
	m.pkt_len -= C.uint32_t(length)
	return true
}

func setMbufLen(mb *Mbuf, l2len, l3len uint32) {
	// Assign l2_len:7 and l3_len:9 fields in rte_mbuf
	mb.anon5[0] = uint8((l2len & 0x7f) | ((l3len & 1) << 7))
	mb.anon5[1] = uint8(l3len >> 1)
	mb.anon5[2] = 0
	mb.anon5[3] = 0
	mb.anon5[4] = 0
	mb.anon5[5] = 0
	mb.anon5[6] = 0
	mb.anon5[7] = 0
}

// SetTXIPv4OLFlags sets mbuf flags for IPv4 header
// checksum calculation hardware offloading.
func SetTXIPv4OLFlags(mb *Mbuf, l2len, l3len uint32) {
	// PKT_TX_IP_CKSUM | PKT_TX_IPV4
	mb.ol_flags = (1 << 54) | (1 << 55)
	setMbufLen(mb, l2len, l3len)
}

// SetTXIPv4UDPOLFlags sets mbuf flags for IPv4 and UDP
// headers checksum calculation hardware offloading.
func SetTXIPv4UDPOLFlags(mb *Mbuf, l2len, l3len uint32) {
	// PKT_TX_UDP_CKSUM | PKT_TX_IP_CKSUM | PKT_TX_IPV4
	mb.ol_flags = (3 << 52) | (1 << 54) | (1 << 55)
	setMbufLen(mb, l2len, l3len)
}

// SetTXIPv4TCPOLFlags sets mbuf flags for IPv4 and TCP
// headers checksum calculation hardware offloading.
func SetTXIPv4TCPOLFlags(mb *Mbuf, l2len, l3len uint32) {
	// PKT_TX_TCP_CKSUM | PKT_TX_IP_CKSUM | PKT_TX_IPV4
	mb.ol_flags = (1 << 52) | (1 << 54) | (1 << 55)
	setMbufLen(mb, l2len, l3len)
}

// SetTXIPv6UDPOLFlags sets mbuf flags for IPv6 UDP header
// checksum calculation hardware offloading.
func SetTXIPv6UDPOLFlags(mb *Mbuf, l2len, l3len uint32) {
	// PKT_TX_UDP_CKSUM | PKT_TX_IPV6
	mb.ol_flags = (3 << 52) | (1 << 56)
	setMbufLen(mb, l2len, l3len)
}

// SetTXIPv6TCPOLFlags sets mbuf flags for IPv6 TCP
// header checksum calculation hardware offloading.
func SetTXIPv6TCPOLFlags(mb *Mbuf, l2len, l3len uint32) {
	// PKT_TX_TCP_CKSUM | PKT_TX_IPV4
	mb.ol_flags = (1 << 52) | (1 << 56)
	setMbufLen(mb, l2len, l3len)
}

// These constants are used by packet package to parse protocol headers
const (
	RtePtypeL2Ether = C.RTE_PTYPE_L2_ETHER
	RtePtypeL3Ipv4  = C.RTE_PTYPE_L3_IPV4
	RtePtypeL3Ipv6  = C.RTE_PTYPE_L3_IPV6
	RtePtypeL4Tcp   = C.RTE_PTYPE_L4_TCP
	RtePtypeL4Udp   = C.RTE_PTYPE_L4_UDP
)

// These constants are used by packet package for longest prefix match lookup
const (
	RteLpmValidExtEntryBitmask = C.RTE_LPM_VALID_EXT_ENTRY_BITMASK
	RteLpmTbl8GroupNumEntries  = C.RTE_LPM_TBL8_GROUP_NUM_ENTRIES
	RteLpmLookupSuccess        = C.RTE_LPM_LOOKUP_SUCCESS
)

// Lookup ring with given name.
func LookupRing(name string) *Ring {
	return (*Ring)(unsafe.Pointer(C.nff_go_ring_lookup(C.CString(name))))
}

// CreateRing creates ring with given name and count.
func CreateRing(count uint) *Ring {
	name := strconv.Itoa(ringName)
	ringName++

	// Flag 0x0000 means ring default mode which is Multiple Consumer / Multiple Producer
	return (*Ring)(unsafe.Pointer(C.nff_go_ring_create(C.CString(name), C.uint(count), C.SOCKET_ID_ANY, 0x0000)))
}

// CreateRings creates ring with given name and count.
func CreateRings(count uint, inIndexNumber int32) Rings {
	rings := make(Rings, inIndexNumber, inIndexNumber)
	for i := int32(0); i < inIndexNumber; i++ {
		rings[i] = CreateRing(count)
	}
	return rings
}

// EnqueueBurst enqueues data to ring buffer.
func (ring *Ring) EnqueueBurst(buffer []uintptr, count uint) uint {
	return nffgoRingMpEnqueueBurst((*C.struct_nff_go_ring)(ring), buffer, count)
}

// DequeueBurst dequeues data from ring buffer.
func (ring *Ring) DequeueBurst(buffer []uintptr, count uint) uint {
	return nffgoRingMcDequeueBurst((*C.struct_nff_go_ring)(ring), buffer, count)
}

// Heavily based on DPDK ENQUEUE_PTRS
// in C version it is a macros with do-while(0). I suppose that we don't need while(0) now because it is a function.
func enqueuePtrs(r *C.struct_nff_go_ring, prodHead C.uint32_t, mask C.uint32_t, n uint, objTable []uintptr /*const*/) {
	var size C.uint32_t = r.DPDK_ring.size
	var idx C.uint32_t = prodHead & mask
	var i uint
	if idx+C.uint32_t(n) < size { //likely
		for i = 0; i < (n & (^(uint(0x3)))); i, idx = i+4, idx+4 {
			*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset))) = objTable[i]
			*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+1)*r.offset))) = objTable[i+1]
			*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+2)*r.offset))) = objTable[i+2]
			*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+3)*r.offset))) = objTable[i+3]
		}
		switch n & 0x3 {
		case 3:
			{
				*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset))) = objTable[i]
				*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+1)*r.offset))) = objTable[i+1]
				*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+2)*r.offset))) = objTable[i+2]
			}
		case 2:
			{
				*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset))) = objTable[i]
				*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+1)*r.offset))) = objTable[i+1]
			}
		case 1:
			{
				*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset))) = objTable[i]
			}
		}
	} else {
		for i = 0; idx < size; i, idx = i+1, idx+1 {
			*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset))) = objTable[i]
		}
		for idx = 0; i < n; i, idx = i+1, idx+1 {
			*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset))) = objTable[i]
		}
	}
}

// Heavily based on DPDK DEQUEUE_PTRS
// in C version it is a macros with do-while(0). I suppose that we don't need while(0) now because it is a function.
func dequeuePtrs(r *C.struct_nff_go_ring, consHead C.uint32_t, mask C.uint32_t, n uint, objTable []uintptr) {
	var idx C.uint32_t = consHead & mask
	var size C.uint32_t = r.DPDK_ring.size
	var i uint
	if idx+C.uint32_t(n) < size { //likely
		for i = 0; i < (n & (^(uint(0x3)))); i, idx = i+4, idx+4 {
			objTable[i] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset)))
			objTable[i+1] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+1)*r.offset)))
			objTable[i+2] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+2)*r.offset)))
			objTable[i+3] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+3)*r.offset)))
		}
		switch n & 0x3 {
		case 3:
			{
				objTable[i] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset)))
				objTable[i+1] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+1)*r.offset)))
				objTable[i+2] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+2)*r.offset)))
			}
		case 2:
			{
				objTable[i] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset)))
				objTable[i+1] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+1)*r.offset)))
			}
		case 1:
			{
				objTable[i] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset)))
			}
		}
	} else {
		for i = 0; idx < size; i, idx = i+1, idx+1 {
			objTable[i] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset)))
		}
		for idx = 0; i < n; i, idx = i+1, idx+1 {
			objTable[i] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset)))
		}
	}
}

// Heavily based on DPDK mp_do_enqueue
func nffgoRingMpDoEnqueue(r *C.struct_nff_go_ring, objTable []uintptr, n uint) uint {
	var prodHead, prodNext C.uint32_t
	var consTail, freeEntries C.uint32_t
	var max = n //max should be const but can't
	var success = false
	var mask C.uint32_t = r.DPDK_ring.mask

	// move prod.head atomically
	for success == false { //unlikely
		// Reset n to the initial burst count
		n = max

		prodHead = r.DPDK_ring.prod.head
		consTail = r.DPDK_ring.cons.tail
		// The subtraction is done between two unsigned 32bits value
		// (the result is always modulo 32 bits even if we have
		// prodHead > consTail). So 'freeEntries' is always between 0
		// and size(ring)-1.
		freeEntries = (mask + consTail - prodHead)

		// check that we have enough room in ring
		if C.uint32_t(n) > freeEntries { //unlikely
			// No free entry available
			if freeEntries == 0 { //unlikely
				return 0
			}
			n = uint(freeEntries)
		}

		prodNext = prodHead + C.uint32_t(n)
		// I suppose we shouldn't write inline asm here but improve standart library instead.
		success = atomic.CompareAndSwapUint32((*uint32)(unsafe.Pointer(&r.DPDK_ring.prod.head)), uint32(prodHead), uint32(prodNext))
	}

	// write entries in ring
	enqueuePtrs(r, prodHead, mask, n, objTable)
	// TODO GO use atomicLoad instead of barrier. rte_smp_wmb(); it is rte_compiler_barrier in x86
	asm.RteCompilerWmb()

	// If there are other enqueues in progress that preceded us,
	// we need to wait for them to complete
	for r.DPDK_ring.prod.tail != prodHead { //unlikely
		C.rte_pause()
	}
	r.DPDK_ring.prod.tail = prodNext
	return n
}

// Heavily based on DPDK mc_do_dequeue
func nffgoRingMcDoDequeue(r *C.struct_nff_go_ring, objTable []uintptr, n uint) uint {
	var consHead, prodTail C.uint32_t
	var consNext, entries C.uint32_t
	var max = n // max should be const but can't
	var success = false
	var mask C.uint32_t = r.DPDK_ring.mask

	// move cons.head atomically
	for success == false { //unlikely
		// Restore n as it may change every loop
		n = max

		consHead = r.DPDK_ring.cons.head
		prodTail = r.DPDK_ring.prod.tail
		// The subtraction is done between two unsigned 32bits value
		// (the result is always modulo 32 bits even if we have
		// consHead > prodTail). So 'entries' is always between 0
		// and size(ring)-1.
		entries = (prodTail - consHead)

		// Set the actual entries for dequeue
		if C.uint32_t(n) > entries {
			if entries == 0 { //unlikely
				return 0
			}
			n = uint(entries)
		}
		consNext = consHead + C.uint32_t(n)
		// I suppose we shouldn't write inline asm here but improve standard library instead.
		success = atomic.CompareAndSwapUint32((*uint32)(unsafe.Pointer(&r.DPDK_ring.cons.head)), uint32(consHead), uint32(consNext))
		//success = C.rte_atomic32_cmpset(&r.C_ring.cons.head, consHead, consNext)
	}

	// copy in table
	dequeuePtrs(r, consHead, mask, n, objTable)
	// TODO rte_smp_rmb(); it is rte_compiler_barrier in x86
	asm.RteCompilerRmb()

	// If there are other dequeues in progress that preceded us,
	// we need to wait for them to complete
	for r.DPDK_ring.cons.tail != consHead { //unlikely
		C.rte_pause()
	}
	r.DPDK_ring.cons.tail = consNext
	return n
}

// Heavily based on DPDK mp_enqueue_burst
func nffgoRingMpEnqueueBurst(r *C.struct_nff_go_ring, objTable []uintptr, n uint) uint {
	return nffgoRingMpDoEnqueue(r, objTable, n)
}

// Heavily based on DPDK mc_dequeue_burst
func nffgoRingMcDequeueBurst(r *C.struct_nff_go_ring, objTable []uintptr, n uint) uint {
	return nffgoRingMcDoDequeue(r, objTable, n)
}

// GetRingCount gets number of objects in ring.
func (ring *Ring) GetRingCount() uint32 {
	return uint32((ring.DPDK_ring.prod.tail - ring.DPDK_ring.cons.tail) & ring.DPDK_ring.mask)
}

// ReceiveRSS - get packets from port and enqueue on a Ring.
func ReceiveRSS(port uint16, inIndex []int32, OUT Rings, flag *int32, coreID int, race *int32, stats *common.RXTXStats) {
	if C.rte_eth_dev_socket_id(C.uint16_t(port)) != C.int(C.rte_lcore_to_socket_id(C.uint(coreID))) {
		common.LogWarning(common.Initialization, "Receive port", port, "is on remote NUMA node to polling thread - not optimal performance.")
	}
	C.receiveRSS(C.uint16_t(port), (*C.int32_t)(unsafe.Pointer(&(inIndex[0]))), C.extractDPDKRings((**C.struct_nff_go_ring)(unsafe.Pointer(&(OUT[0]))), C.int32_t(len(OUT))),
		(*C.int)(unsafe.Pointer(flag)), C.int(coreID), (*C.int)(unsafe.Pointer(race)), (*C.RXTXStats)(unsafe.Pointer(stats)))
}

func SrKNI(port uint16, flag *int32, coreID int, recv bool, OUT Rings, send bool, IN Rings, stats *common.RXTXStats) {
	var nOut *C.struct_rte_ring
	var nIn **C.struct_rte_ring
	if OUT != nil {
		nOut = OUT[0].DPDK_ring
	}
	if IN != nil {
		nIn = C.extractDPDKRings((**C.struct_nff_go_ring)(unsafe.Pointer(&(IN[0]))), C.int32_t(len(IN)))
	}
	C.nff_go_KNI(C.uint16_t(port), (*C.int)(unsafe.Pointer(flag)), C.int(coreID),
		C.bool(recv), nOut, C.bool(send), nIn, C.int32_t(len(IN)), (*C.RXTXStats)(unsafe.Pointer(stats)))
}

// Send - dequeue packets and send.
func Send(port uint16, IN Rings, unrestrictedClones bool, flag *int32, coreID int, stats *common.RXTXStats,
	sendThreadIndex, totalSendTreads int) {
	if C.rte_eth_dev_socket_id(C.uint16_t(port)) != C.int(C.rte_lcore_to_socket_id(C.uint(coreID))) {
		common.LogWarning(common.Initialization, "Send port", port, "is on remote NUMA node to polling thread - not optimal performance.")
	}
	C.nff_go_send(C.uint16_t(port),
		C.extractDPDKRings((**C.struct_nff_go_ring)(unsafe.Pointer(&(IN[0]))), C.int32_t(len(IN))),
		C.int32_t(len(IN)),
		C.bool(unrestrictedClones),
		(*C.int)(unsafe.Pointer(flag)), C.int(coreID),
		(*C.RXTXStats)(unsafe.Pointer(stats)),
		C.int32_t(sendThreadIndex),
		C.int32_t(totalSendTreads))
}

// Stop - dequeue and free packets.
func Stop(IN Rings, flag *int32, coreID int, stats *common.RXTXStats) {
	C.nff_go_stop(C.extractDPDKRings((**C.struct_nff_go_ring)(unsafe.Pointer(&(IN[0]))), C.int32_t(len(IN))), C.int(len(IN)), (*C.int)(unsafe.Pointer(flag)), C.int(coreID), (*C.RXTXStats)(unsafe.Pointer(stats)))
}

// InitDPDKArguments allocates and initializes arguments for dpdk.
func InitDPDKArguments(args []string) (C.int, **C.char) {
	DPDKArgs := append([]string{}, os.Args[0])
	DPDKArgs = append(DPDKArgs, "--log-level="+common.GetDPDKLogLevel())
	DPDKArgs = append(DPDKArgs, args...)

	argv := C.makeArgv(C.int(len(DPDKArgs)))
	for i, arg := range DPDKArgs {
		C.handleArgv(argv, C.CString(arg), C.int(i))
	}
	return C.int(len(DPDKArgs)), argv
}

// InitDPDK initializes the Environment Abstraction Layer (EAL) in DPDK.
func InitDPDK(argc C.int, argv **C.char, burstSize uint, mbufNumber uint, mbufCacheSize uint, needKNI int,
	NoPacketHeadChange bool, needChainedReassembly bool, needChainedJumbo bool, needMemoryJumbo bool) error {
	if needChainedReassembly && needChainedJumbo || needChainedReassembly && needMemoryJumbo || needChainedJumbo && needMemoryJumbo {
		return common.WrapWithNFError(nil, "Memory jumbo, chained jumbo or IP reassembly is unsupported together\n", common.FailToInitDPDK)
	}
	ret := C.eal_init(argc, argv, C.uint32_t(burstSize), C.int32_t(needKNI),
		C.bool(NoPacketHeadChange), C.bool(needChainedReassembly), C.bool(needChainedJumbo), C.bool(needMemoryJumbo))
	if ret < 0 {
		return common.WrapWithNFError(nil, "Error with EAL initialization\n", common.FailToInitDPDK)
	}
	if ret > 0 {
		return common.WrapWithNFError(nil, "rte_eal_init can't parse all parameters\n", common.FailToInitDPDK)
	}
	mbufNumberT = mbufNumber
	mbufCacheSizeT = mbufCacheSize
	return nil
}

func StopDPDK() {
	C.rte_eal_cleanup()
}

func FreeMempools() {
	for i := range usedMempools {
		C.rte_mempool_free(usedMempools[i].mempool)
	}
	usedMempools = nil
}

func StopPort(port uint16) {
	C.rte_eth_dev_stop(C.uint16_t(port))
}

func FreeKNI(port uint16) error {
	if C.free_kni(C.uint16_t(port)) < 0 {
		return common.WrapWithNFError(nil, "Problem with KNI releasing\n", common.FailToReleaseKNI)
	}
	return nil
}

const (
	RteMaxEthPorts = C.RTE_MAX_ETHPORTS
)

func GetNextPort(port uint16) uint16 {
	return uint16(C.rte_eth_find_next_owned_by(C.uint16_t(port), C.RTE_ETH_DEV_NO_OWNER))
}

// GetPortsNumber gets total number of available Ethernet devices.
func GetPortsNumber() int {
	return int(C.rte_eth_dev_count())
}

func CheckPortRSS(port uint16) int32 {
	return int32(C.check_max_port_rx_queues(C.uint16_t(port)))
}

func CheckPortMaxTXQueues(port uint16) int32 {
	return int32(C.check_max_port_tx_queues(C.uint16_t(port)))
}

// CreatePort initializes a new port using global settings and parameters.
func CreatePort(port uint16, willReceive bool, promiscuous bool, hwtxchecksum,
	hwrxpacketstimestamp bool, inIndex int32, tXQueuesNumberPerPort int) error {
	var mempools **C.struct_rte_mempool
	if willReceive {
		m := CreateMempools("receive", inIndex)
		mempools = (**C.struct_rte_mempool)(unsafe.Pointer(&(m[0])))
	} else {
		mempools = nil
	}
	if C.port_init(C.uint16_t(port), C.bool(willReceive), mempools,
		C._Bool(promiscuous), C._Bool(hwtxchecksum), C._Bool(hwrxpacketstimestamp), C.int32_t(inIndex), C.int32_t(tXQueuesNumberPerPort)) != 0 {
		msg := common.LogError(common.Initialization, "Cannot init port ", port, "!")
		return common.WrapWithNFError(nil, msg, common.FailToInitPort)
	}
	return nil
}

// CreateMempool creates and returns a new memory pool.
func CreateMempool(name string) *Mempool {
	nameC := 1
	tName := name
	for i := range usedMempools {
		if usedMempools[i].name == tName {
			tName = name + strconv.Itoa(nameC)
			nameC++
		}
	}
	mempool := C.createMempool(C.uint32_t(mbufNumberT), C.uint32_t(mbufCacheSizeT))
	usedMempools = append(usedMempools, mempoolPair{mempool, tName})
	return (*Mempool)(mempool)
}

func CreateMempools(name string, inIndex int32) []*Mempool {
	m := make([]*Mempool, inIndex, inIndex)
	for i := int32(0); i < inIndex; i++ {
		m[i] = CreateMempool(name)
	}
	return m
}

// SetAffinity sets cpu affinity mask.
func SetAffinity(coreID int) error {
	// go tool trace shows that each proc executes different goroutine. However it is expected behavior
	// (golang issue #20853) and each goroutine is locked to one OS thread.
	runtime.LockOSThread()

	var cpuset C.cpu_set_t
	C.initCPUSet(C.int(coreID), &cpuset)
	_, _, errno := syscall.RawSyscall(syscall.SYS_SCHED_SETAFFINITY, uintptr(0), unsafe.Sizeof(cpuset), uintptr(unsafe.Pointer(&cpuset)))
	if errno != 0 {
		return common.WrapWithNFError(nil, errno.Error(), common.SetAffinityErr)
	}
	return nil
}

// AllocateMbufs allocates n mbufs.
func AllocateMbufs(mb []uintptr, mempool *Mempool, n uint) error {
	if err := C.allocateMbufs((*C.struct_rte_mempool)(mempool), (**C.struct_rte_mbuf)(unsafe.Pointer(&mb[0])), C.unsigned(n)); err != 0 {
		msg := common.LogError(common.Debug, "AllocateMbufs cannot allocate mbuf, dpdk returned: ", err)
		return common.WrapWithNFError(nil, msg, common.AllocMbufErr)
	}
	return nil
}

// AllocateMbuf allocates one mbuf.
func AllocateMbuf(mb *uintptr, mempool *Mempool) error {
	if err := C.allocateMbufs((*C.struct_rte_mempool)(mempool), (**C.struct_rte_mbuf)(unsafe.Pointer(mb)), 1); err != 0 {
		msg := common.LogError(common.Debug, "AllocateMbuf cannot allocate mbuf, dpdk returned: ", err)
		return common.WrapWithNFError(nil, msg, common.AllocMbufErr)
	}
	return nil
}

// WriteDataToMbuf copies data to mbuf.
func WriteDataToMbuf(mb *Mbuf, data []byte) {
	d := unsafe.Pointer(GetPacketDataStartPointer(mb))
	slice := (*[types.MaxLength]byte)(d)[:len(data)] // copy requires slice
	//TODO need to investigate maybe we need to use C function C.rte_memcpy here
	copy(slice, data)
}

// GetRawPacketBytesMbuf returns raw data from packet.
func GetRawPacketBytesMbuf(mb *Mbuf) []byte {
	dataLen := uintptr(mb.data_len)
	dataPtr := uintptr(mb.buf_addr) + uintptr(mb.data_off)
	return (*[1 << 30]byte)(unsafe.Pointer(dataPtr))[:dataLen]
}

// GetPktLenMbuf returns amount of data in a given chain of Mbufs - whole packet
func GetPktLenMbuf(mb *Mbuf) uint {
	return uint(mb.pkt_len)
}

// GetDataLenMbuf returns amount of data in a given Mbuf - one segment if scattered
func GetDataLenMbuf(mb *Mbuf) uint {
	return uint(mb.data_len)
}

// Statistics print statistics about current
// speed of stop ring, recv/send speed and drops.
func Statistics(N float32) {
	C.statistics(C.float(N))
}

// PortStatistics print statistics about NIC port.
func PortStatistics(port uint16) {
	C.portStatistics(C.uint16_t(port))
}

// ReportMempoolsState prints used and free space of mempools.
func ReportMempoolsState() {
	for _, m := range usedMempools {
		use := C.getMempoolSpace(m.mempool)
		common.LogDebug(common.Verbose, "Mempool usage", m.name, use, "from", mbufNumberT)
		if float32(mbufNumberT-uint(use))/float32(mbufNumberT)*100 < 10 {
			common.LogDrop(common.Debug, m.name, "mempool has less than 10% free space. This can lead to dropping packets while receive.")
		}
	}
}

// CreateKni creates a KNI device
func CreateKni(portId uint16, core uint, name string) error {
	mempool := (*C.struct_rte_mempool)(CreateMempool("KNI"))
	if C.create_kni(C.uint16_t(portId), C.uint32_t(core), C.CString(name), mempool) != 0 {
		return common.WrapWithNFError(nil, "Error with KNI allocation\n", common.FailToCreateKNI)
	}
	return nil
}

// CreateLPM creates LPM table
// We can't reuse any structures like rte_lpm or rte_lpm_tbl_entry due to
// CGO problems with bitfields (uint24 compile time error).
// We we pass pointers via "unsafe.Pointer" and "void*"
// C function will return pointers to correct rte_lpm fields to tbl24 and tbl8,
// so we shouldn't worry about rte_lpm changings. However we use indexing
// while lookup, so we will need to check our sizes if DPDK changes rte_lpm_tbl_entry struct size
func CreateLPM(name string, socket uint8, maxRules uint32, numberTbl8 uint32, tbl24 unsafe.Pointer, tbl8 unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.lpm_create(C.CString(name), C.int(socket), C.uint32_t(maxRules), C.uint32_t(numberTbl8),
		(**[1]C.uint32_t)(tbl24), (**[1]C.uint32_t)(tbl8)))
}

// AddLPMRule adds one rule to LPM table
func AddLPMRule(lpm unsafe.Pointer, ip types.IPv4Address, depth uint8, nextHop types.IPv4Address) int {
	return int(C.lpm_add(lpm, C.uint32_t(ip), C.uint8_t(depth), C.uint32_t(nextHop)))
}

// DeleteLPMRule removes one rule from LPM table
func DeleteLPMRule(lpm unsafe.Pointer, ip types.IPv4Address, depth uint8) int {
	return int(C.lpm_delete(lpm, C.uint32_t(ip), C.uint8_t(depth)))
}

// FreeLPM frees lpm structure
func FreeLPM(lpm unsafe.Pointer) {
	C.lpm_free(lpm)
}

func BoolToInt(value bool) uint8 {
	return *((*uint8)(unsafe.Pointer(&value)))
}

func IntArrayToBool(value *[32]uint8) *[32]bool {
	return (*[32]bool)(unsafe.Pointer(value))
}

func CheckHWTXChecksumCapability(port uint16) bool {
	return bool(C.check_hwtxchecksum_capability(C.uint16_t(port)))
}

func CheckHWRXPacketsTimestamp(port uint16) bool {
	return bool(C.check_hwrxpackets_timestamp_capability(C.uint16_t(port)))
}

func InitDevice(device string) int {
	return int(C.initDevice(C.CString(device)))
}

func ReceiveOS(socket int, OUT *Ring, flag *int32, coreID int, stats *common.RXTXStats) {
	m := CreateMempool("receiveOS")
	C.receiveOS(C.int(socket), OUT.DPDK_ring, (*C.struct_rte_mempool)(unsafe.Pointer(m)),
		(*C.int)(unsafe.Pointer(flag)), C.int(coreID), (*C.RXTXStats)(unsafe.Pointer(stats)))
}

func SendOS(socket int, IN Rings, flag *int32, coreID int, stats *common.RXTXStats) {
	C.sendOS(C.int(socket), C.extractDPDKRings((**C.struct_nff_go_ring)(unsafe.Pointer(&(IN[0]))),
		C.int32_t(len(IN))), C.int32_t(len(IN)), (*C.int)(unsafe.Pointer(flag)), C.int(coreID),
		(*C.RXTXStats)(unsafe.Pointer(stats)))
}

func SetCountersEnabledInApplication(enabled bool) {
	C.counters_enabled_in_application = C.bool(true)
}

func SetNextMbuf(next *Mbuf, prev *Mbuf) {
	prev.next = (*C.struct_rte_mbuf)(next)
}

func GetPacketOffloadFlags(mb *Mbuf) uint64 {
	return uint64(mb.ol_flags)
}

func GetPacketTimestamp(mb *Mbuf) uint64 {
	return uint64(mb.timestamp)
}

type XDPSocket *C.struct_xsk_socket_info

func InitXDP(device string, queue int) XDPSocket {
	return C.initXDP(C.CString(device), C.int(queue))
}

func ReceiveXDP(socket XDPSocket, OUT *Ring, flag *int32, coreID int, stats *common.RXTXStats) {
	m := CreateMempool("receiveXDP")
	C.receiveXDP(socket, OUT.DPDK_ring, (*C.struct_rte_mempool)(unsafe.Pointer(m)),
		(*C.int)(unsafe.Pointer(flag)), C.int(coreID), (*C.RXTXStats)(unsafe.Pointer(stats)))
}

func SendXDP(socket XDPSocket, IN Rings, flag *int32, coreID int, stats *common.RXTXStats) {
	C.sendXDP(socket, C.extractDPDKRings((**C.struct_nff_go_ring)(unsafe.Pointer(&(IN[0]))),
		C.int32_t(len(IN))), C.int32_t(len(IN)), (*C.int)(unsafe.Pointer(flag)), C.int(coreID),
		(*C.RXTXStats)(unsafe.Pointer(stats)))
}
