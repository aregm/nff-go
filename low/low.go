// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package low

/*
#cgo CFLAGS: -std=gnu11 -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2 -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3,RTE_CPUFLAG_SSE4_1,RTE_CPUFLAG_SSE4_2,RTE_CPUFLAG_PCLMULQDQ,RTE_CPUFLAG_AVX,RTE_CPUFLAG_RDRAND,RTE_CPUFLAG_FSGSBASE,RTE_CPUFLAG_F16C,RTE_CPUFLAG_AVX2 -include rte_config.h -O3
#cgo LDFLAGS: -W -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wl,--no-as-needed -Wl,-export-dynamic -Wl,--whole-archive -lrte_distributor -lrte_reorder -lrte_kni -lrte_pipeline -lrte_table -lrte_port -lrte_timer -lrte_hash -lrte_jobstats -lrte_lpm -lrte_power -lrte_acl -lrte_meter -lrte_sched -lrte_vhost -Wl,--start-group -lrte_kvargs -lrte_mbuf -lrte_ip_frag -lrte_ethdev -lrte_mempool -lrte_ring -lrte_eal -lrte_cmdline -lrte_cfgfile -lrte_pmd_bond -lrte_pmd_vmxnet3_uio -lrte_net -lrte_pmd_virtio -lrte_pmd_cxgbe -lrte_pmd_enic -lrte_pmd_i40e -lrte_pmd_fm10k -lrte_pmd_ixgbe -lrte_pmd_e1000 -lrte_pmd_ring -lrte_pmd_af_packet -lrte_pmd_null -lrt -lm -ldl -Wl,--end-group -Wl,--no-whole-archive

#include "yanff_queue.h"

extern void eal_init(int argc, char **argv, uint32_t burstSize);
extern void recv(uint8_t port, uint16_t queue, struct rte_ring *, uint8_t coreId);
extern void send(uint8_t port, uint16_t queue, struct rte_ring *, uint8_t coreId);
extern void stop(struct rte_ring *);
extern void initCPUSet(uint8_t coreId, cpu_set_t* cpuset);
extern int port_init(uint8_t port, uint16_t receiveQueuesNumber, uint16_t sendQueuesNumber, struct rte_mempool *mbuf_pool, struct ether_addr *addr);
extern struct rte_mempool * createMempool(int portsNumber, uint32_t num_mbuf, uint32_t mbuf_cache_size);
extern int directStop(int pkts_for_free_number, struct rte_mbuf ** buf);
extern char ** makeArgv(int n);
extern void handleArgv(char **, char* s, int i);
extern int allocateMbufs(struct rte_mempool *mempool, struct rte_mbuf **bufs, unsigned count);
*/
import "C"

import (
	"encoding/hex"
	"flag"
	"github.com/intel-go/yanff/asm"
	"github.com/intel-go/yanff/common"
	"math"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

func DirectStop(pkts_for_free_number int, buf []uintptr) {
	C.directStop(C.int(pkts_for_free_number), (**C.struct_rte_mbuf)(unsafe.Pointer(&(buf[0]))))
}

type Queue C.struct_yanff_queue
type Mbuf C.struct_rte_mbuf

// TODO need to investigate more elegant way to return variables from C part
var mainMempool *C.struct_rte_mempool

func GetPacketDataStartPointer(mb *Mbuf) uintptr {
	return uintptr(mb.buf_addr) + uintptr(mb.data_off)
}

var packetStructSize int

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

// Heavily based on DPDK rte_pktmbuf_append
func AppendMbuf(mb *Mbuf, length uint) bool {
	if C.uint16_t(length) > mb.buf_len-mb.data_off-mb.data_len {
		return false
	}
	mb.data_len += C.uint16_t(length)
	mb.pkt_len += C.uint32_t(length)
	return true
}

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

// Heavily based on DPDK rte_pktmbuf_trim
func TrimMbuf(m *Mbuf, length uint) bool {
	if C.uint16_t(length) > m.data_len {
		return false
	}
	m.data_len -= C.uint16_t(length)
	m.pkt_len -= C.uint32_t(length)
	return true
}

// These constants are used by packet package to parse protocol headers
const (
	RTE_PTYPE_L2_ETHER = C.RTE_PTYPE_L2_ETHER
	RTE_PTYPE_L3_IPV4  = C.RTE_PTYPE_L3_IPV4
	RTE_PTYPE_L3_IPV6  = C.RTE_PTYPE_L3_IPV6
	RTE_PTYPE_L4_TCP   = C.RTE_PTYPE_L4_TCP
	RTE_PTYPE_L4_UDP   = C.RTE_PTYPE_L4_UDP
)

func CreateQueue(name string, count uint) *Queue {
	var queue *Queue
	// Flag 0x0000 means ring default mode which is Multiple Consumer / Multiple Producer
	queue = (*Queue)(unsafe.Pointer(C.yanff_queue_create(C.CString(name), C.uint(count), C.SOCKET_ID_ANY, 0x0000)))

	return queue
}

func (self *Queue) EnqueueBurst(buffer []uintptr, count uint) uint {
	return yanff_ring_mp_enqueue_burst(self.ring, buffer, count)
}

func (self *Queue) DequeueBurst(buffer []uintptr, count uint) uint {
	return yanff_ring_mc_dequeue_burst(self.ring, buffer, count)
}

// Heavily based on DPDK ENQUEUE_PTRS
// in C version it is a macros with do-while(0). I suppose that we don't need while(0) now because it is a function.
func _ENQUEUE_PTRS(r *C.struct_yanff_ring, prod_head C.uint32_t, mask C.uint32_t, n uint, obj_table []uintptr /*const*/) {
	var size C.uint32_t = r.DPDK_ring.prod.size
	var idx C.uint32_t = prod_head & mask
	var i uint
	if idx+C.uint32_t(n) < size { //likely
		for i = 0; i < (n & (^(uint(0x3)))); i, idx = i+4, idx+4 {
			*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset))) = obj_table[i]
			*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+1)*r.offset))) = obj_table[i+1]
			*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+2)*r.offset))) = obj_table[i+2]
			*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+3)*r.offset))) = obj_table[i+3]
		}
		switch n & 0x3 {
		case 3:
			{
				*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset))) = obj_table[i]
				*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+1)*r.offset))) = obj_table[i+1]
				*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+2)*r.offset))) = obj_table[i+2]
			}
		case 2:
			{
				*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset))) = obj_table[i]
				*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+1)*r.offset))) = obj_table[i+1]
			}
		case 1:
			{
				*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset))) = obj_table[i]
			}
		}
	} else {
		for i = 0; idx < size; i, idx = i+1, idx+1 {
			*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset))) = obj_table[i]
		}
		for idx = 0; i < n; i, idx = i+1, idx+1 {
			*(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset))) = obj_table[i]
		}
	}
}

// Heavily based on DPDK DEQUEUE_PTRS
// in C version it is a macros with do-while(0). I suppose that we don't need while(0) now because it is a function.
func _DEQUEUE_PTRS(r *C.struct_yanff_ring, cons_head C.uint32_t, mask C.uint32_t, n uint, obj_table []uintptr) {
	var idx C.uint32_t = cons_head & mask
	var size C.uint32_t = r.DPDK_ring.cons.size
	var i uint
	if idx+C.uint32_t(n) < size { //likely
		for i = 0; i < (n & (^(uint(0x3)))); i, idx = i+4, idx+4 {
			obj_table[i] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset)))
			obj_table[i+1] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+1)*r.offset)))
			obj_table[i+2] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+2)*r.offset)))
			obj_table[i+3] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+3)*r.offset)))
		}
		switch n & 0x3 {
		case 3:
			{
				obj_table[i] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset)))
				obj_table[i+1] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+1)*r.offset)))
				obj_table[i+2] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+2)*r.offset)))
			}
		case 2:
			{
				obj_table[i] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset)))
				obj_table[i+1] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx+1)*r.offset)))
			}
		case 1:
			{
				obj_table[i] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset)))
			}
		}
	} else {
		for i = 0; idx < size; i, idx = i+1, idx+1 {
			obj_table[i] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset)))
		}
		for idx = 0; i < n; i, idx = i+1, idx+1 {
			obj_table[i] = *(*uintptr)(unsafe.Pointer(uintptr(r.internal_DPDK_ring) + uintptr((idx)*r.offset)))
		}
	}
}

// Heavily based on DPDK mp_do_enqueue
func yanff_ring_mp_do_enqueue(r *C.struct_yanff_ring, obj_table []uintptr, n uint) uint {
	var prod_head, prod_next C.uint32_t
	var cons_tail, free_entries C.uint32_t
	var max uint = n //max should be const but can't
	var success bool = false
	var rep uint = 0
	var mask C.uint32_t = r.DPDK_ring.prod.mask

	// move prod.head atomically
	for success == false { //unlikely
		// Reset n to the initial burst count
		n = max

		prod_head = r.DPDK_ring.prod.head
		cons_tail = r.DPDK_ring.cons.tail
		// The subtraction is done between two unsigned 32bits value
		// (the result is always modulo 32 bits even if we have
		// prod_head > cons_tail). So 'free_entries' is always between 0
		// and size(ring)-1.
		free_entries = (mask + cons_tail - prod_head)

		// check that we have enough room in ring
		if C.uint32_t(n) > free_entries { //unlikely
			// No free entry available
			if free_entries == 0 { //unlikely
				return 0
			}
			n = uint(free_entries)
		}

		prod_next = prod_head + C.uint32_t(n)
		// I suppose we shouldn't write inline asm here but improve standart library instead.
		success = atomic.CompareAndSwapUint32((*uint32)(unsafe.Pointer(&r.DPDK_ring.prod.head)), uint32(prod_head), uint32(prod_next))
	}

	// write entries in ring
	_ENQUEUE_PTRS(r, prod_head, mask, n, obj_table)
	// TODO GO use atomicLoad instead of barrier. rte_smp_wmb(); it is rte_compiler_barrier in x86
	asm.Rte_compiler_wmb()

	// If there are other enqueues in progress that preceded us,
	// we need to wait for them to complete
	for r.DPDK_ring.prod.tail != prod_head { //unlikely
		C.rte_pause()
		rep++
		// Set RTE_RING_PAUSE_REP_COUNT to avoid spin too long waiting
		// for other thread finish. It gives pre-empted thread a chance
		// to proceed and finish with ring dequeue operation.
		if (C.RTE_RING_PAUSE_REP_COUNT != 0) && (rep == C.RTE_RING_PAUSE_REP_COUNT) {
			rep = 0
			// TODO C variant has sched_yield here we can use "runtime.Gosched()" or "C.sched_yield()"
			time.Sleep(time.Millisecond)
		}
	}
	r.DPDK_ring.prod.tail = prod_next
	return n
}

// Heavily based on DPDK mc_do_dequeue
func yanff_ring_mc_do_dequeue(r *C.struct_yanff_ring, obj_table []uintptr, n uint) uint {
	var cons_head, prod_tail C.uint32_t
	var cons_next, entries C.uint32_t
	var max uint = n // max should be const but can't
	var success bool = false
	var rep uint = 0
	var mask C.uint32_t = r.DPDK_ring.prod.mask

	// move cons.head atomically
	for success == false { //unlikely
		// Restore n as it may change every loop
		n = max

		cons_head = r.DPDK_ring.cons.head
		prod_tail = r.DPDK_ring.prod.tail
		// The subtraction is done between two unsigned 32bits value
		// (the result is always modulo 32 bits even if we have
		// cons_head > prod_tail). So 'entries' is always between 0
		// and size(ring)-1.
		entries = (prod_tail - cons_head)

		// Set the actual entries for dequeue
		if C.uint32_t(n) > entries {
			if entries == 0 { //unlikely
				return 0
			}
			n = uint(entries)
		}
		cons_next = cons_head + C.uint32_t(n)
		// I suppose we shouldn't write inline asm here but improve standard library instead.
		success = atomic.CompareAndSwapUint32((*uint32)(unsafe.Pointer(&r.DPDK_ring.cons.head)), uint32(cons_head), uint32(cons_next))
		//success = C.rte_atomic32_cmpset(&r.C_ring.cons.head, cons_head, cons_next)
	}

	// copy in table
	_DEQUEUE_PTRS(r, cons_head, mask, n, obj_table)
	// TODO rte_smp_rmb(); it is rte_compiler_barrier in x86
	asm.Rte_compiler_rmb()

	// If there are other dequeues in progress that preceded us,
	// we need to wait for them to complete
	for r.DPDK_ring.cons.tail != cons_head { //unlikely
		C.rte_pause()
		rep++

		// Set RTE_RING_PAUSE_REP_COUNT to avoid spin too long waiting
		// for other thread finish. It gives pre-empted thread a chance
		// to proceed and finish with ring dequeue operation.
		if (C.RTE_RING_PAUSE_REP_COUNT != 0) && (rep == C.RTE_RING_PAUSE_REP_COUNT) {
			rep = 0
			// TODO C variant has sched_yield here. We can use "runtime.Gosched()" or "C.sched_yield()"
			time.Sleep(time.Millisecond)
		}
	}
	r.DPDK_ring.cons.tail = cons_next
	return n
}

// Heavilly based on DPDK mp_enqueue_burst
func yanff_ring_mp_enqueue_burst(r *C.struct_yanff_ring, obj_table []uintptr, n uint) uint {
	return yanff_ring_mp_do_enqueue(r, obj_table, n)
}

// Heavilly based on DPDK mc_dequeue_burst
func yanff_ring_mc_dequeue_burst(r *C.struct_yanff_ring, obj_table []uintptr, n uint) uint {
	return yanff_ring_mc_do_dequeue(r, obj_table, n)
}

func (self *Queue) GetQueueCount() uint32 {
	return uint32((self.ring.DPDK_ring.prod.tail - self.ring.DPDK_ring.cons.tail) & self.ring.DPDK_ring.prod.mask)
}

func Receive(port uint8, queue uint16, OUT *Queue, coreId uint8) {
	t := C.rte_eth_dev_socket_id(C.uint8_t(port))
	if t > 0 && t != C.int(C.rte_lcore_to_socket_id(C.uint(coreId))) {
		common.LogWarning(common.Initialization, "Receive port", port, "is on remote NUMA node to polling thread - not optimal performance.")
	}
	C.recv(C.uint8_t(port), C.uint16_t(queue), OUT.ring.DPDK_ring, C.uint8_t(coreId))
}

func Send(port uint8, queue uint16, IN *Queue, coreId uint8) {
	t := C.rte_eth_dev_socket_id(C.uint8_t(port))
	if t > 0 && t != C.int(C.rte_lcore_to_socket_id(C.uint(coreId))) {
		common.LogWarning(common.Initialization, "Send port", port, "is on remote NUMA node to polling thread - not optimal performance.")
	}
	C.send(C.uint8_t(port), C.uint16_t(queue), IN.ring.DPDK_ring, C.uint8_t(coreId))
}

func Stop(IN *Queue) {
	C.stop(IN.ring.DPDK_ring)
}

func ParseFlags() (C.int, **C.char) {
	var DPDKFlag string
	var DPDKArgs []string
	var DPDKHelp bool
	var logType uint
	flag.StringVar(&DPDKFlag, "dpdk-args", "", "These arguments will be transparently passed to DPDK")
	flag.BoolVar(&DPDKHelp, "dpdk-help", false, "Use this for displaying DPDK help message")
	flag.UintVar(&logType, "log-type", 2, "type of logging: 0 - no output, 1 - at init stage, 2 - always, 3 - verbose. Need to switch C part manually")

	flag.Parse()
	switch logType {
	// Also you should switch debug and verbose in low.c manually!
	case 0:
		common.SetLogType(common.No)
	case 1:
		common.SetLogType(common.No | common.Initialization)
	case 2:
		common.SetLogType(common.No | common.Initialization | common.Debug)
	case 3:
		common.SetLogType(common.No | common.Initialization | common.Debug | common.Verbose)
	default:
		common.SetLogType(common.No | common.Initialization | common.Debug)
	}

	DPDKArgs = append(DPDKArgs, os.Args[0]+" --dpdk-args")
	DPDKArgs = append(DPDKArgs, "--log-level="+common.GetDPDKLogLevel())
	for _, i := range strings.Split(DPDKFlag, ",") {
		if i != "" {
			DPDKArgs = append(DPDKArgs, i)
		}
	}
	if DPDKHelp == true {
		DPDKArgs = append(DPDKArgs, "-h")
	}

	argv := C.makeArgv(C.int(len(DPDKArgs)))
	for i, arg := range DPDKArgs {
		C.handleArgv(argv, C.CString(arg), C.int(i))
	}
	return C.int(len(DPDKArgs)), argv
}

func InitDPDK(argc C.int, argv **C.char, burstSize uint, mbufNumber uint, mbufCacheSize uint) {
	// Initialize the Environment Abstraction Layer (EAL) in DPDK.
	C.eal_init(argc, argv, C.uint32_t(burstSize))

	// Created unique Mempool. All packets (mbufs) will be stored there.
	mainMempool = C.createMempool(C.int(GetPortsNumber()), C.uint32_t(mbufNumber), C.uint32_t(mbufCacheSize))
}

func GetPortsNumber() int {
	return int(C.rte_eth_dev_count())
}

func CreatePort(port uint8, receiveQueuesNumber uint16, sendQueuesNumber uint16) {
	addr := make([]byte, C.ETHER_ADDR_LEN)
	if C.port_init(C.uint8_t(port), C.uint16_t(receiveQueuesNumber), C.uint16_t(sendQueuesNumber),
		mainMempool, (*C.struct_ether_addr)(unsafe.Pointer(&(addr[0])))) != 0 {
		common.LogError(common.Initialization, "Cannot init port ", port, "!")
	}
	t := hex.Dump(addr)
	common.LogDebug(common.Initialization, "Port", port, "MAC address:", t[10:27])
}

func SetAffinity(coreId uint8) {
	runtime.LockOSThread()

	var cpuset C.cpu_set_t
	C.initCPUSet(C.uint8_t(coreId), &cpuset)
	syscall.RawSyscall(syscall.SYS_SCHED_SETAFFINITY, uintptr(0), unsafe.Sizeof(cpuset), uintptr(unsafe.Pointer(&cpuset)))
}

func AllocateMbufs(mb []uintptr) {
	err := C.allocateMbufs(mainMempool, (**C.struct_rte_mbuf)(unsafe.Pointer(&mb[0])), C.unsigned(len(mb)))
	if err != 0 {
		common.LogError(common.Debug, "AllocateMbufs cannot allocate mbuf")
	}
}

func WriteDataToMbuf(mb *Mbuf, data []byte) {
	d := unsafe.Pointer(GetPacketDataStartPointer(mb))
	slice := (*[math.MaxInt32]byte)(d)[:len(data)] // copy requires slice
	//TODO need to investigate maybe we need to use C function C.rte_memcpy here
	copy(slice, data)
}

func GetRawPacketBytesMbuf(mb *Mbuf) []byte {
	dataLen := uintptr(mb.data_len)
	dataPtr := uintptr(mb.buf_addr) + uintptr(mb.data_off)
	return (*[1 << 30]byte)(unsafe.Pointer(dataPtr))[:dataLen]
}

func GetDataLenMbuf(mb *Mbuf) uint {
	return uint(mb.data_len)
}
