// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package low

/*
#include "yanff_queue.h"

extern void eal_init(int argc, char **argv, uint32_t burstSize);
extern void yanff_recv(uint8_t port, uint16_t queue, struct rte_ring *, uint8_t coreID);
extern void yanff_send(uint8_t port, uint16_t queue, struct rte_ring *, uint8_t coreID);
extern void yanff_stop(struct rte_ring *);
extern void initCPUSet(uint8_t coreID, cpu_set_t* cpuset);
extern int port_init(uint8_t port, uint16_t receiveQueuesNumber, uint16_t sendQueuesNumber, struct rte_mempool *mbuf_pool,
    struct ether_addr *addr, bool hwtxchecksum);
extern struct rte_mempool * createMempool(uint32_t num_mbuf, uint32_t mbuf_cache_size);
extern int directStop(int pktsForFreeNumber, struct rte_mbuf ** buf);
extern char ** makeArgv(int n);
extern void handleArgv(char **, char* s, int i);
extern int allocateMbufs(struct rte_mempool *mempool, struct rte_mbuf **bufs, unsigned count);
extern void statistics(float N);
extern int getMempoolSpace(struct rte_mempool * m);
*/
import "C"

import (
	"encoding/hex"
	"math"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/intel-go/yanff/asm"
	"github.com/intel-go/yanff/common"
)

// DirectStop frees mbufs.
func DirectStop(pktsForFreeNumber int, buf []uintptr) {
	C.directStop(C.int(pktsForFreeNumber), (**C.struct_rte_mbuf)(unsafe.Pointer(&(buf[0]))))
}

// Queue is a ring buffer queue.
type Queue C.struct_yanff_queue

// Mbuf is a message buffer.
type Mbuf C.struct_rte_mbuf

// Mempool is a pool of objects.
type Mempool C.struct_rte_mempool

var mbufNumberT uint
var mbufCacheSizeT uint
var usedMempools []*C.struct_rte_mempool

// GetPortMACAddress gets MAC address of given port.
func GetPortMACAddress(port uint8) [common.EtherAddrLen]uint8 {
	var mac [common.EtherAddrLen]uint8
	var cmac C.struct_ether_addr

	C.rte_eth_macaddr_get(C.uint8_t(port), &cmac)
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
func SetPacketStructSize(t int) {
	if t > C.RTE_PKTMBUF_HEADROOM {
		common.LogError(common.Initialization, "Packet structure can't be placed inside mbuf.",
			"Increase CONFIG_RTE_PKTMBUF_HEADROOM in dpdk/config/common_base and rebuild dpdk.")
	}
	minPacketHeadroom := 64
	if C.RTE_PKTMBUF_HEADROOM-t < minPacketHeadroom {
		common.LogWarning(common.Initialization, "Packet will have only", C.RTE_PKTMBUF_HEADROOM-t,
			"bytes for prepend something, increase CONFIG_RTE_PKTMBUF_HEADROOM in dpdk/config/common_base and rebuild dpdk.")
	}
	packetStructSize = t
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

// SetTXIPv4OLFlags sets mbuf flags for IPv4 header
// checksum calculation offloading.
func SetTXIPv4OLFlags(mb *Mbuf, l2len, l3len uint32) {
	// PKT_TX_IP_CKSUM | PKT_TX_IPV4
	mb.ol_flags = (1 << 54) | (1 << 55)
	mb.anon3[0] = uint8((l2len & 0x7f) | ((l3len & 1) << 7))
	mb.anon3[1] = uint8(l3len >> 1)
	mb.anon3[2] = 0
	mb.anon3[3] = 0
	mb.anon3[4] = 0
	mb.anon3[5] = 0
	mb.anon3[6] = 0
	mb.anon3[7] = 0
}

// SetTXIPv4UDPOLFlags sets mbuf flags for IPv4 and UDP
// headers checksum calculation offloading.
func SetTXIPv4UDPOLFlags(mb *Mbuf, l2len, l3len uint32) {
	// PKT_TX_UDP_CKSUM | PKT_TX_IP_CKSUM | PKT_TX_IPV4
	mb.ol_flags = (3 << 52) | (1 << 54) | (1 << 55)
	mb.anon3[0] = uint8((l2len & 0x7f) | ((l3len & 1) << 7))
	mb.anon3[1] = uint8(l3len >> 1)
	mb.anon3[2] = 0
	mb.anon3[3] = 0
	mb.anon3[4] = 0
	mb.anon3[5] = 0
	mb.anon3[6] = 0
	mb.anon3[7] = 0
}

// SetTXIPv4TCPOLFlags sets mbuf flags for IPv4 and TCP
// headers checksum calculation offloading.
func SetTXIPv4TCPOLFlags(mb *Mbuf, l2len, l3len uint32) {
	// PKT_TX_TCP_CKSUM | PKT_TX_IP_CKSUM | PKT_TX_IPV4
	mb.ol_flags = (1 << 52) | (1 << 54) | (1 << 55)
	mb.anon3[0] = uint8((l2len & 0x7f) | ((l3len & 1) << 7))
	mb.anon3[1] = uint8(l3len >> 1)
	mb.anon3[2] = 0
	mb.anon3[3] = 0
	mb.anon3[4] = 0
	mb.anon3[5] = 0
	mb.anon3[6] = 0
	mb.anon3[7] = 0
}

// SetTXIPv6UDPOLFlags sets mbuf flags for IPv6 UDP header
// checksum calculation offloading.
func SetTXIPv6UDPOLFlags(mb *Mbuf, l2len, l3len uint32) {
	// PKT_TX_UDP_CKSUM | PKT_TX_IPV6
	mb.ol_flags = (3 << 52) | (1 << 56)
	mb.anon3[0] = uint8((l2len & 0x7f) | ((l3len & 1) << 7))
	mb.anon3[1] = uint8(l3len >> 1)
	mb.anon3[2] = 0
	mb.anon3[3] = 0
	mb.anon3[4] = 0
	mb.anon3[5] = 0
	mb.anon3[6] = 0
	mb.anon3[7] = 0
}

// SetTXIPv6TCPOLFlags sets mbuf flags for IPv6 TCP
// header checksum calculation offloading.
func SetTXIPv6TCPOLFlags(mb *Mbuf, l2len, l3len uint32) {
	// PKT_TX_TCP_CKSUM | PKT_TX_IPV4
	mb.ol_flags = (1 << 52) | (1 << 56)
	mb.anon3[0] = uint8((l2len & 0x7f) | ((l3len & 1) << 7))
	mb.anon3[1] = uint8(l3len >> 1)
	mb.anon3[2] = 0
	mb.anon3[3] = 0
	mb.anon3[4] = 0
	mb.anon3[5] = 0
	mb.anon3[6] = 0
	mb.anon3[7] = 0
}

// These constants are used by packet package to parse protocol headers
const (
	RtePtypeL2Ether = C.RTE_PTYPE_L2_ETHER
	RtePtypeL3Ipv4  = C.RTE_PTYPE_L3_IPV4
	RtePtypeL3Ipv6  = C.RTE_PTYPE_L3_IPV6
	RtePtypeL4Tcp   = C.RTE_PTYPE_L4_TCP
	RtePtypeL4Udp   = C.RTE_PTYPE_L4_UDP
)

// CreateQueue creates queue with given name and count.
func CreateQueue(name string, count uint) *Queue {
	var queue *Queue
	// Flag 0x0000 means ring default mode which is Multiple Consumer / Multiple Producer
	queue = (*Queue)(unsafe.Pointer(C.yanff_queue_create(C.CString(name), C.uint(count), C.SOCKET_ID_ANY, 0x0000)))

	return queue
}

// EnqueueBurst enqueues data to ring buffer.
func (queue *Queue) EnqueueBurst(buffer []uintptr, count uint) uint {
	return yanffRingMpEnqueueBurst(queue.ring, buffer, count)
}

// DequeueBurst dequeues data from ring buffer.
func (queue *Queue) DequeueBurst(buffer []uintptr, count uint) uint {
	return yanffRingMcDequeueBurst(queue.ring, buffer, count)
}

// Heavily based on DPDK ENQUEUE_PTRS
// in C version it is a macros with do-while(0). I suppose that we don't need while(0) now because it is a function.
func enqueuePtrs(r *C.struct_yanff_ring, prodHead C.uint32_t, mask C.uint32_t, n uint, objTable []uintptr /*const*/) {
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
func dequeuePtrs(r *C.struct_yanff_ring, consHead C.uint32_t, mask C.uint32_t, n uint, objTable []uintptr) {
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
func yanffRingMpDoEnqueue(r *C.struct_yanff_ring, objTable []uintptr, n uint) uint {
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
func yanffRingMcDoDequeue(r *C.struct_yanff_ring, objTable []uintptr, n uint) uint {
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
func yanffRingMpEnqueueBurst(r *C.struct_yanff_ring, objTable []uintptr, n uint) uint {
	return yanffRingMpDoEnqueue(r, objTable, n)
}

// Heavily based on DPDK mc_dequeue_burst
func yanffRingMcDequeueBurst(r *C.struct_yanff_ring, objTable []uintptr, n uint) uint {
	return yanffRingMcDoDequeue(r, objTable, n)
}

// GetQueueCount gets number of objects in queue.
func (queue *Queue) GetQueueCount() uint32 {
	return uint32((queue.ring.DPDK_ring.prod.tail - queue.ring.DPDK_ring.cons.tail) & queue.ring.DPDK_ring.mask)
}

// Receive - get packets and enqueue on a Queue.
func Receive(port uint8, queue uint16, OUT *Queue, coreID uint8) {
	t := C.rte_eth_dev_socket_id(C.uint8_t(port))
	if t > 0 && t != C.int(C.rte_lcore_to_socket_id(C.uint(coreID))) {
		common.LogWarning(common.Initialization, "Receive port", port, "is on remote NUMA node to polling thread - not optimal performance.")
	}
	C.yanff_recv(C.uint8_t(port), C.uint16_t(queue), OUT.ring.DPDK_ring, C.uint8_t(coreID))
}

// Send - dequeue packets and send.
func Send(port uint8, queue uint16, IN *Queue, coreID uint8) {
	t := C.rte_eth_dev_socket_id(C.uint8_t(port))
	if t > 0 && t != C.int(C.rte_lcore_to_socket_id(C.uint(coreID))) {
		common.LogWarning(common.Initialization, "Send port", port, "is on remote NUMA node to polling thread - not optimal performance.")
	}
	C.yanff_send(C.uint8_t(port), C.uint16_t(queue), IN.ring.DPDK_ring, C.uint8_t(coreID))
}

// Stop - dequeue and free packets.
func Stop(IN *Queue) {
	C.yanff_stop(IN.ring.DPDK_ring)
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
func InitDPDK(argc C.int, argv **C.char, burstSize uint, mbufNumber uint, mbufCacheSize uint) {
	C.eal_init(argc, argv, C.uint32_t(burstSize))

	mbufNumberT = mbufNumber
	mbufCacheSizeT = mbufCacheSize
}

// GetPortsNumber gets total number of available Ethernet devices.
func GetPortsNumber() int {
	return int(C.rte_eth_dev_count())
}

// CreatePort initializes a new port using global settings and parameters.
func CreatePort(port uint8, receiveQueuesNumber uint16, sendQueuesNumber uint16, hwtxchecksum bool) {
	addr := make([]byte, C.ETHER_ADDR_LEN)
	var mempool *C.struct_rte_mempool
	if receiveQueuesNumber != 0 {
		mempool = C.createMempool(C.uint32_t(mbufNumberT), C.uint32_t(mbufCacheSizeT))
		usedMempools = append(usedMempools, mempool)
	} else {
		mempool = nil
	}
	if C.port_init(C.uint8_t(port), C.uint16_t(receiveQueuesNumber), C.uint16_t(sendQueuesNumber),
		mempool, (*C.struct_ether_addr)(unsafe.Pointer(&(addr[0]))), C._Bool(hwtxchecksum)) != 0 {
		common.LogError(common.Initialization, "Cannot init port ", port, "!")
	}
	t := hex.Dump(addr)
	common.LogDebug(common.Initialization, "Port", port, "MAC address:", t[10:27])
}

// CreateMempool creates and returns a new memory pool.
func CreateMempool() *Mempool {
	var mempool *C.struct_rte_mempool
	mempool = C.createMempool(C.uint32_t(mbufNumberT), C.uint32_t(mbufCacheSizeT))
	usedMempools = append(usedMempools, mempool)
	return (*Mempool)(mempool)
}

// SetAffinity sets cpu affinity mask.
func SetAffinity(coreID uint8) {
	// go tool trace shows that each proc executes different goroutine. However it is expected behavior
	// (golang issue #20853) and each goroutine is locked to one OS thread.
	runtime.LockOSThread()

	var cpuset C.cpu_set_t
	C.initCPUSet(C.uint8_t(coreID), &cpuset)
	syscall.RawSyscall(syscall.SYS_SCHED_SETAFFINITY, uintptr(0), unsafe.Sizeof(cpuset), uintptr(unsafe.Pointer(&cpuset)))
}

// AllocateMbufs allocates a bulk of mbufs.
func AllocateMbufs(mb []uintptr, mempool *Mempool) {
	err := C.allocateMbufs((*C.struct_rte_mempool)(mempool), (**C.struct_rte_mbuf)(unsafe.Pointer(&mb[0])), C.unsigned(len(mb)))
	if err != 0 {
		common.LogError(common.Debug, "AllocateMbufs cannot allocate mbuf")
	}
}

// WriteDataToMbuf copies data to mbuf.
func WriteDataToMbuf(mb *Mbuf, data []byte) {
	d := unsafe.Pointer(GetPacketDataStartPointer(mb))
	slice := (*[math.MaxInt32]byte)(d)[:len(data)] // copy requires slice
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
