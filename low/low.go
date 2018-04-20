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
#cgo LDFLAGS: -lrte_distributor -lrte_reorder -lrte_kni -lrte_pipeline -lrte_table -lrte_port -lrte_timer -lrte_jobstats -lrte_lpm -lrte_power -lrte_acl -lrte_meter -lrte_sched -lrte_vhost -lrte_ip_frag -lrte_cfgfile -Wl,--whole-archive -Wl,--start-group -lrte_kvargs -lrte_mbuf -lrte_hash -lrte_ethdev -lrte_mempool -lrte_ring -lrte_mempool_ring -lrte_eal -lrte_cmdline -lrte_net -lrte_bus_pci -lrte_pci -lrte_bus_vdev -lrte_pmd_bond -lrte_pmd_vmxnet3_uio -lrte_pmd_virtio -lrte_pmd_cxgbe -lrte_pmd_enic -lrte_pmd_i40e -lrte_pmd_fm10k -lrte_pmd_ixgbe -lrte_pmd_e1000 -lrte_pmd_ring -lrte_pmd_af_packet -lrte_pmd_null -Wl,--end-group -Wl,--no-whole-archive -lrt -lm -ldl -lnuma
#include "low.h"
*/
import "C"

import (
	"encoding/hex"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/intel-go/nff-go/asm"
	"github.com/intel-go/nff-go/common"
)

// DirectStop frees mbufs.
func DirectStop(pktsForFreeNumber int, buf []uintptr) {
	C.directStop(C.int(pktsForFreeNumber), (**C.struct_rte_mbuf)(unsafe.Pointer(&(buf[0]))))
}

// DirectSend sends one mbuf.
func DirectSend(m *Mbuf, port uint8) bool {
	return bool(C.directSend((*C.struct_rte_mbuf)(m), C.uint8_t(port)))
}

// Ring is a ring buffer for pointers
type Ring C.struct_nff_go_ring

// Mbuf is a message buffer.
type Mbuf C.struct_rte_mbuf

// Mempool is a pool of objects.
type Mempool C.struct_rte_mempool

type Port C.struct_cPort

var mbufNumberT uint
var mbufCacheSizeT uint
var usedMempools []*C.struct_rte_mempool

func GetPort(n uint16) *Port {
	p := new(Port)
	p.PortId = C.uint16_t(n)
	p.QueuesNumber = 1
	return p
}

func CheckRSSPacketCount(p *Port) int {
	return int(C.checkRSSPacketCount((*C.struct_cPort)(p)))
}

func DecreaseRSS(p *Port) {
	C.changeRSSReta((*C.struct_cPort)(p), false)
}

func IncreaseRSS(p *Port) bool {
	return bool(C.changeRSSReta((*C.struct_cPort)(p), true))
}

// GetPortMACAddress gets MAC address of given port.
func GetPortMACAddress(port uint16) [common.EtherAddrLen]uint8 {
	var mac [common.EtherAddrLen]uint8
	var cmac C.struct_ether_addr

	C.rte_eth_macaddr_get(C.uint16_t(port), &cmac)
	for i := range mac {
		mac[i] = uint8(cmac.addr_bytes[i])
	}
	return mac
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
	mb.anon4[0] = uint8((l2len & 0x7f) | ((l3len & 1) << 7))
	mb.anon4[1] = uint8(l3len >> 1)
	mb.anon4[2] = 0
	mb.anon4[3] = 0
	mb.anon4[4] = 0
	mb.anon4[5] = 0
	mb.anon4[6] = 0
	mb.anon4[7] = 0
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

// CreateRing creates ring with given name and count.
func CreateRing(name string, count uint) *Ring {
	var ring *Ring
	// Flag 0x0000 means ring default mode which is Multiple Consumer / Multiple Producer
	ring = (*Ring)(unsafe.Pointer(C.nff_go_ring_create(C.CString(name), C.uint(count), C.SOCKET_ID_ANY, 0x0000)))

	return ring
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

// Receive - get packets and enqueue on a Ring.
func Receive(port uint16, queue int16, OUT *Ring, flag *int32, coreID int) {
	t := C.rte_eth_dev_socket_id(C.uint16_t(port))
	if t != C.int(C.rte_lcore_to_socket_id(C.uint(coreID))) {
		common.LogWarning(common.Initialization, "Receive port", port, "is on remote NUMA node to polling thread - not optimal performance.")
	}
	C.nff_go_recv(C.uint16_t(port), C.int16_t(queue), OUT.DPDK_ring, (*C.int)(unsafe.Pointer(flag)), C.int(coreID))
}

// Send - dequeue packets and send.
func Send(port uint16, queue int16, IN *Ring, flag *int32, coreID int) {
	t := C.rte_eth_dev_socket_id(C.uint16_t(port))
	if t != C.int(C.rte_lcore_to_socket_id(C.uint(coreID))) {
		common.LogWarning(common.Initialization, "Send port", port, "is on remote NUMA node to polling thread - not optimal performance.")
	}
	C.nff_go_send(C.uint16_t(port), C.int16_t(queue), IN.DPDK_ring, (*C.int)(unsafe.Pointer(flag)), C.int(coreID))
}

// Stop - dequeue and free packets.
func Stop(IN *Ring, flag *int32, coreID int) {
	C.nff_go_stop(IN.DPDK_ring, (*C.int)(unsafe.Pointer(flag)), C.int(coreID))
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
func InitDPDK(argc C.int, argv **C.char, burstSize uint, mbufNumber uint, mbufCacheSize uint, needKNI int) {
	C.eal_init(argc, argv, C.uint32_t(burstSize), C.int32_t(needKNI))

	mbufNumberT = mbufNumber
	mbufCacheSizeT = mbufCacheSize
}

func StopDPDK() {
	C.rte_eal_cleanup()
}

func FreeMempools() {
	for i := range usedMempools {
		C.rte_mempool_free(usedMempools[i])
	}
	usedMempools = nil
}

func StopPort(port uint8) {
	C.rte_eth_dev_stop(C.uint16_t(port))
}

// GetPortsNumber gets total number of available Ethernet devices.
func GetPortsNumber() int {
	return int(C.rte_eth_dev_count())
}

// CreatePort initializes a new port using global settings and parameters.
func CreatePort(port uint8, willReceive bool, sendQueuesNumber uint16, hwtxchecksum bool) error {
	addr := make([]byte, C.ETHER_ADDR_LEN)
	var mempool *C.struct_rte_mempool
	if willReceive {
		mempool = C.createMempool(C.uint32_t(mbufNumberT), C.uint32_t(mbufCacheSizeT))
		usedMempools = append(usedMempools, mempool)
	} else {
		mempool = nil
	}
	if C.port_init(C.uint8_t(port), C.bool(willReceive), C.uint16_t(sendQueuesNumber),
		mempool, (*C.struct_ether_addr)(unsafe.Pointer(&(addr[0]))), C._Bool(hwtxchecksum)) != 0 {
		msg := common.LogError(common.Initialization, "Cannot init port ", port, "!")
		return common.WrapWithNFError(nil, msg, common.FailToInitPort)
	}
	t := hex.Dump(addr)
	common.LogDebug(common.Initialization, "Port", port, "MAC address:", t[10:27])
	return nil
}

// CreateMempool creates and returns a new memory pool.
func CreateMempool() *Mempool {
	var mempool *C.struct_rte_mempool
	mempool = C.createMempool(C.uint32_t(mbufNumberT), C.uint32_t(mbufCacheSizeT))
	usedMempools = append(usedMempools, mempool)
	return (*Mempool)(mempool)
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
	slice := (*[common.MaxLength]byte)(d)[:len(data)] // copy requires slice
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

// ReportMempoolsState prints used and free space of mempools.
func ReportMempoolsState() {
	for i, m := range usedMempools {
		use := C.getMempoolSpace(m)
		common.LogDebug(common.Debug, "Mempool N", i, "used", use, "from", mbufNumberT)
		if float32(mbufNumberT-uint(use))/float32(mbufNumberT)*100 < 10 {
			common.LogDrop(common.Debug, "Mempool N", i, "has less than 10% free space. This can lead to dropping packets while receive.")
		}
	}
}

// CreateKni creates a KNI device
func CreateKni(portId uint16, core uint8, name string) {
	mempool := C.createMempool(C.uint32_t(mbufNumberT), C.uint32_t(mbufCacheSizeT))
	usedMempools = append(usedMempools, mempool)
	C.create_kni(C.uint16_t(portId), C.uint8_t(core), C.CString(name), mempool)
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
func AddLPMRule(lpm unsafe.Pointer, ip uint32, depth uint8, nextHop uint32) int {
	return int(C.lpm_add(lpm, C.uint32_t(ip), C.uint8_t(depth), C.uint32_t(nextHop)))
}

// DeleteLPMRule removes one rule from LPM table
func DeleteLPMRule(lpm unsafe.Pointer, ip uint32, depth uint8) int {
	return int(C.lpm_delete(lpm, C.uint32_t(ip), C.uint8_t(depth)))
}

// FreeLPM frees lpm structure
func FreeLPM(lpm unsafe.Pointer) {
	C.lpm_free(lpm)
}
