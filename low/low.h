// Copyright 2017 Intel Corporation. 
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#define _GNU_SOURCE

// Do not use signals in this C code without much need.
// They can and probably will crash go runtime in complex errors.
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <unistd.h>
#include <stdbool.h>

#include <rte_cycles.h>
#include <rte_ip_frag.h>
#include <rte_bus_pci.h>
#include <rte_kni.h>
#include <rte_lpm.h>

#include <sys/socket.h>
#include <linux/if_ether.h>     // ETH_P_ALL
#include <stdio.h>              // snprintf
#include <string.h>             // memset
#include <stdlib.h>             // malloc
#include <netinet/ip.h>         // htons
#include <sys/ioctl.h>          // ioctl
#include <net/if.h>             // ifreq
#include <netpacket/packet.h>   // sockaddr_ll

#define process 1
#define stopRequest 2
#define wasStopped 9

// These constants are get from DPDK and checked for performance
#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

// 2 queues are enough for handling 40GBits. Should be checked for other NICs.
// TODO This macro should be a function that will dynamically return the needed number of cores.
#define TX_QUEUE_NUMBER 2

#define APP_RETA_SIZE_MAX (ETH_RSS_RETA_SIZE_512 / RTE_RETA_GROUP_SIZE)

// #define DEBUG
// #define REASSEMBLY
#define COUNTERS_ENABLED
#define USE_INTERLOCKED_COUNTERS
#define ANALYZE_PACKETS_SIZES

#define recvNotUsed 0
#define recvDone 2

// This macros clears packet structure which is stored inside mbuf
// 0 offset is L3 protocol pointer
// 8 offset is L4 protocol pointer
// 16 offset is a data offset and shouldn't be cleared
// 24 offset is L2 offset and is always begining of packet
// 32 offset is CMbuf offset and is initilized when mempool is created
// 40 offset is Next field. Should be 0. Will be filled later if required
#define mbufInitL2(buf) \
*(char **)((char *)(buf) + mbufStructSize + 24) = (char *)(buf) + defaultStart;
#define mbufInitCMbuf(buf) \
*(char **)((char *)(buf) + mbufStructSize + 32) = (char *)(buf);
#define mbufInitNextChain(buf) \
*(char **)((char *)(buf) + mbufStructSize + 40) = 0;

#ifdef REASSEMBLY
#define REASSEMBLY_INIT \
	struct rte_ip_frag_tbl* tbl = create_reassemble_table(); \
	struct rte_ip_frag_death_row death_row; \
	death_row.cnt = 0; /* DPDK doesn't initialize this field. It is probably a bug. */ \
	struct rte_ip_frag_death_row* pdeath_row = &death_row;

// Firstly we set "next" packet pointer (+40) to the packet from next mbuf
// Secondly we know that followed mbufs don't contain L2 and L3 headers. We assume that they start with a data
// so we assume that Data packet field (+16) should be equal to Ether packet field (+24)
// (which we parse at this packet segment receiving
#define mbufSetNext(buf) \
	*(char **)((char *)(buf) + mbufStructSize + 40) = (char *)(buf->next) + mbufStructSize; \
	*(char **)((char *)(buf->next) + mbufStructSize + 16) = *(char **)((char *)(buf->next) + mbufStructSize + 24)
#else
#define REASSEMBLY_INIT \
	struct rte_ip_frag_tbl* tbl = NULL; \
	struct rte_ip_frag_death_row* pdeath_row = NULL;
#endif

#ifdef COUNTERS_ENABLED
#ifdef USE_INTERLOCKED_COUNTERS
#define UPDATE_PACKETS(packets, dropped)                        \
    __sync_fetch_and_add(&stats->PacketsProcessed, (packets));  \
    __sync_fetch_and_add(&stats->PacketsDropped, (dropped));
#ifdef ANALYZE_PACKETS_SIZES
#define UPDATE_BYTES(bytes)                                 \
    __sync_fetch_and_add(&stats->BytesProcessed, (bytes));
#else // ANALYZE_PACKETS_SIZES
#define UPDATE_BYTES(bytes)                     \
    do {} while (0)
#endif // ANALYZE_PACKETS_SIZES
#else // USE_INTERLOCKED_COUNTERS
#define UPDATE_PACKETS(packets, dropped)        \
    stats->PacketsProcessed += (packets);       \
    stats->PacketsDropped += (dropped);
#ifdef ANALYZE_PACKETS_SIZES
#define UPDATE_BYTES(bytes)                     \
    stats->BytesProcessed += (bytes);
#else // ANALYZE_PACKETS_SIZES
#define UPDATE_BYTES(bytes)                     \
    do {} while (0)
#endif // ANALYZE_PACKETS_SIZES
#endif // USE_INTERLOCKED_COUNTERS
#define UPDATE_COUNTERS(packets, bytes, dropped)    \
    UPDATE_PACKETS(packets, dropped)                \
    UPDATE_BYTES(bytes)
#else // COUNTERS_ENABLED
#define UPDATE_COUNTERS(packets, bytes, dropped)    \
    do {} while (0)
#endif // COUNTERS_ENABLED

long receive_received = 0, receive_pushed = 0;
long send_required = 0, send_sent = 0;
long stop_freed = 0;

typedef struct {
	uint64_t PacketsProcessed, PacketsDropped, BytesProcessed;
} RXTXStats;

int mbufStructSize;
int headroomSize;
int defaultStart;
bool L2CanBeChanged;
char mempoolName[9] = "mempool1\0";

__m128 zero128 = {0, 0, 0, 0};
#ifdef RTE_MACHINE_CPUFLAG_AVX
__m256 zero256 = {0, 0, 0, 0, 0, 0, 0, 0};
#endif

// This is multiplier for conversion from PKT/s to Mbits/s for 64 (84 in total length) packets
const float multiplier = 84.0 * 8.0 / 1000.0 / 1000.0;

#define MAX_KNI 50
struct rte_kni* kni[MAX_KNI];
static int KNI_change_mtu(uint16_t port_id, unsigned int new_mtu);
static int KNI_config_network_interface(uint16_t port_id, uint8_t if_up);
static int KNI_config_mac_address(uint16_t port_id, uint8_t mac_addr[]);
static int KNI_config_promiscusity(uint16_t port_id, uint8_t to_on);

uint32_t BURST_SIZE;

struct cPort {
	uint16_t PortId;
	uint8_t QueuesNumber;
};

void initCPUSet(int coreId, cpu_set_t* cpuset) {
	CPU_ZERO(cpuset);
	CPU_SET(coreId, cpuset);
}

void setAffinity(int coreId) {
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(coreId, &cpuset);
	sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

int create_kni(uint16_t port, uint32_t core, char *name, struct rte_mempool *mbuf_pool) {
	struct rte_eth_dev_info dev_info;
	const struct rte_pci_device *pci_dev;
	const struct rte_bus *bus = NULL;

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port, &dev_info);

	struct rte_kni_conf conf_default;
	memset(&conf_default, 0, sizeof(conf_default));
	snprintf(conf_default.name, RTE_KNI_NAMESIZE, "%s", name);
	conf_default.core_id = core; // Core ID to bind kernel thread on
	conf_default.group_id = port;
	conf_default.mbuf_size = 2048;
	if (dev_info.device) {
		bus = rte_bus_find_by_device(dev_info.device);
	}
	if (bus && !strcmp(bus->name, "pci")) {
		pci_dev = RTE_DEV_TO_PCI(dev_info.device);
		conf_default.addr = pci_dev->addr;
		conf_default.id = pci_dev->id;
	}
	conf_default.force_bind = 1; // Flag to bind kernel thread
	rte_eth_macaddr_get(port, (struct ether_addr *)&conf_default.mac_addr);
	rte_eth_dev_get_mtu(port, &conf_default.mtu);

	struct rte_kni_ops ops;
	memset(&ops, 0, sizeof(ops));
	ops.port_id = port;
	ops.change_mtu = KNI_change_mtu;
	ops.config_network_if = KNI_config_network_interface;
	ops.config_mac_address = KNI_config_mac_address;
	ops.config_promiscusity = KNI_config_promiscusity;

	// Both rte_kni_conf and rte_kni_ops structures are changed in DPDK
	// We should always compare our initialization with current DPDK
	// version of these structures
	kni[port] = rte_kni_alloc(mbuf_pool, &conf_default, &ops);
	if (kni[port] == NULL) {
		return -1;
	}
	return 0;
}

int free_kni(uint16_t port) {
	return rte_kni_release(kni[port]);
}

int checkRSSPacketCount(struct cPort *port, int16_t queue) {
	return rte_eth_rx_queue_count(port->PortId, queue);
}

int check_port_rss(uint16_t port) {
	struct rte_eth_dev_info dev_info;
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port, &dev_info);
	return dev_info.max_rx_queues;
}

int check_port_tx(uint16_t port) {
        struct rte_eth_dev_info dev_info;
        memset(&dev_info, 0, sizeof(dev_info));
        rte_eth_dev_info_get(port, &dev_info);
        return dev_info.max_tx_queues;
}

// Initializes a given port using global settings and with the RX buffers
// coming from the mbuf_pool passed as a parameter.
int port_init(uint16_t port, bool willReceive, struct rte_mempool **mbuf_pools, bool promiscuous, bool hwtxchecksum, int32_t inIndex) {
	uint16_t rx_rings, tx_rings = TX_QUEUE_NUMBER;

	struct rte_eth_dev_info dev_info;
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port, &dev_info);

	if (tx_rings > dev_info.max_tx_queues) {
		tx_rings = check_port_tx(port);
	}

	if (willReceive) {
		rx_rings = inIndex;
	} else {
		rx_rings = 0;
	}

	if (port >= rte_eth_dev_count())
		return -1;

	struct rte_eth_conf port_conf_default = {
		.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN,
					.mq_mode = ETH_MQ_RX_RSS    },
		.txmode = { .mq_mode = ETH_MQ_TX_NONE, },
		.rx_adv_conf.rss_conf.rss_key = NULL,
		.rx_adv_conf.rss_conf.rss_hf = dev_info.flow_type_rss_offloads
	};

	if (hwtxchecksum) {
        /* Enable everything that is supported by hardware */
        port_conf_default.txmode.offloads = dev_info.tx_offload_capa;
	}

	/* Configure the Ethernet device. */
	int retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf_default);
	if (retval != 0)
		return retval;

	/* Allocate and set up RX queues per Ethernet port. */
	for (uint16_t q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pools[q]);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up TX queues per Ethernet port. */
	for (uint16_t q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), &dev_info.default_txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	if (promiscuous == true) {
		/* Enable RX in promiscuous mode for the Ethernet device. */
		rte_eth_promiscuous_enable(port);
	}

	// Not to use .rx_deferred_start = 0 in custom configuration
	// and use default configuration instead
	struct cPort newPort = {
		.PortId  = port,
		.QueuesNumber = rx_rings
	};

	return 0;
}

#if defined(COUNTERS_ENABLED) && defined(ANALYZE_PACKETS_SIZES)
__attribute__((always_inline))
static inline uint64_t calculateSize(struct rte_mbuf *bufs[BURST_SIZE], uint16_t number) {
	uint64_t size = 0;
	for (uint32_t i = 0; i < number; i++) {
		size += bufs[i]->pkt_len;
	}
	return size;
}
#endif

__attribute__((always_inline))
static inline void handleUnpushed(struct rte_mbuf *bufs[BURST_SIZE], uint16_t real_number, uint16_t required_number) {
	if (unlikely(real_number < required_number)) {
	        for (uint16_t i = real_number; i < required_number; i++) {
	                rte_pktmbuf_free(bufs[i]);
	        }
	}
}

__attribute__((always_inline))
static inline uint16_t handleReceived(struct rte_mbuf *bufs[BURST_SIZE], uint16_t rx_pkts_number, struct rte_ip_frag_tbl* tbl, struct rte_ip_frag_death_row* death_row) {
#ifndef REASSEMBLY
	if (L2CanBeChanged == true) {
		for (uint16_t i = 0; i < rx_pkts_number; i++) {
			// TODO prefetch
			mbufInitL2(bufs[i]);
		}
	}
#else
	uint16_t temp_number = 0;
	uint64_t cur_tsc = rte_rdtsc();
	for (uint16_t i = 0; i < rx_pkts_number; i++) {
	        // Prefetch decreases speed here without reassembly and increases with reassembly.
	        // Speed of this is highly influenced by size of mempool. It seems that due to caches.
		if (L2CanBeChanged == true) {
			mbufInitL2(bufs[i]);
		}
		mbufInitNextChain(bufs[i]);
	        // TODO prefetch will give 8-10% performance in reassembly case.
	        // However we need additional investigations about small (< 3) packet numbers.
	        //rte_prefetch0(rte_pktmbuf_mtod(bufs[i + 3] /*PREFETCH_OFFSET*/, void *));
	        bufs[i] = reassemble(tbl, bufs[i], death_row, cur_tsc);
	        if (bufs[i] == NULL) {
	                continue;
	        }
	        struct rte_mbuf *temp = bufs[i];
	        while (temp->next != NULL) {
	                mbufSetNext(temp);
	                temp = temp->next;
	        }
	        bufs[temp_number] = bufs[i];
	        temp_number++;
	}
	rx_pkts_number = temp_number;
	rte_ip_frag_free_death_row(death_row, 0 /* PREFETCH_OFFSET */);
#endif
	return rx_pkts_number;
}

struct rte_ip_frag_tbl* create_reassemble_table() {
	static uint32_t max_flow_num = 0x1000;
	static uint32_t max_flow_ttl = MS_PER_S;
	// TODO maybe we want these as parameters?
	uint64_t frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S * max_flow_ttl;
	struct rte_ip_frag_tbl* tbl = rte_ip_frag_table_create(max_flow_num, 16, max_flow_num, frag_cycles, SOCKET_ID_ANY);
	if (tbl == NULL) {
		fprintf(stderr, "ERROR: Can't create a table for ip reassemble");
		exit(0);
	}
	return tbl;
}

__attribute__((always_inline))
static inline struct rte_mbuf* reassemble(struct rte_ip_frag_tbl* tbl, struct rte_mbuf *buf, struct rte_ip_frag_death_row* death_row, uint64_t cur_tsc) {
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(buf, struct ether_hdr *);

	// TODO packet_type is not mandatory required for drivers.
	// Some drivers won't set it. However this is DPDK implementation.
	if (RTE_ETH_IS_IPV4_HDR(buf->packet_type)) { // if packet is IPv4
		struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

		if (rte_ipv4_frag_pkt_is_fragmented(ip_hdr)) { // try to reassemble
			buf->l2_len = sizeof(*eth_hdr); // prepare mbuf: setup l2_len/l3_len.
			buf->l3_len = sizeof(*ip_hdr); // prepare mbuf: setup l2_len/l3_len.
			// This function will return first mbuf from mbuf chain
			// Following mbufs in a chain will be without L2 and L3 headers
			return rte_ipv4_frag_reassemble_packet(tbl, death_row, buf, cur_tsc, ip_hdr);
		}
	}
	if (RTE_ETH_IS_IPV6_HDR(buf->packet_type)) { // if packet is IPv6
		struct ipv6_hdr *ip_hdr = (struct ipv6_hdr *)(eth_hdr + 1);
		struct ipv6_extension_fragment *frag_hdr = rte_ipv6_frag_get_ipv6_fragment_header(ip_hdr);

		if (frag_hdr != NULL) {
			buf->l2_len = sizeof(*eth_hdr); // prepare mbuf: setup l2_len/l3_len.
			buf->l3_len = sizeof(*ip_hdr) + sizeof(*frag_hdr); // prepare mbuf: setup l2_len/l3_len.
			// This function will return first mbuf from mbuf chain
			// Following mbufs in a chain will be without L2 and L3 headers
			return rte_ipv6_frag_reassemble_packet(tbl, death_row, buf, cur_tsc, ip_hdr, frag_hdr);
		}
	}
	return buf;
}

void receiveRSS(uint16_t port, volatile int32_t *inIndex, struct rte_ring **out_rings, volatile int *flag, int coreId, volatile int *race, RXTXStats *stats) {
	setAffinity(coreId);
	struct rte_mbuf *bufs[BURST_SIZE];
	REASSEMBLY_INIT
	while (*flag == process) {
		for (int q = 0; q < inIndex[0]; q++) {
			// Get packets from port
			uint16_t rx_pkts_number = rte_eth_rx_burst(port, inIndex[q+1], bufs, BURST_SIZE);
			__atomic_store_n(race, recvDone, __ATOMIC_RELAXED);
			if (unlikely(rx_pkts_number == 0)) {
				continue;
			}
			rx_pkts_number = handleReceived(bufs, rx_pkts_number, tbl, pdeath_row);

			uint16_t pushed_pkts_number = rte_ring_enqueue_burst(out_rings[inIndex[q+1]], (void*)bufs, rx_pkts_number, NULL);

			UPDATE_COUNTERS(pushed_pkts_number, calculateSize(bufs, pushed_pkts_number), rx_pkts_number - pushed_pkts_number);

			// Free any packets which can't be pushed to the ring. The ring is probably full.
			handleUnpushed((void*)bufs, pushed_pkts_number, rx_pkts_number);
#ifdef DEBUG
			receive_received += rx_pkts_number;
			receive_pushed += pushed_pkts_number;
#endif // DEBUG
		}
	}
	free(out_rings);
	__atomic_store_n(race, recvNotUsed, __ATOMIC_RELAXED);
	*flag = wasStopped;
}

void nff_go_KNI(uint16_t port, volatile int *flag, int coreId,
    bool recv, struct rte_ring *out_ring,
    bool send, struct rte_ring **in_rings, int32_t inIndexNumber, RXTXStats *stats) {
	setAffinity(coreId);
	struct rte_mbuf *bufs[BURST_SIZE];
	int q = 0;
	REASSEMBLY_INIT
	while (*flag == process) {
		if (recv == true) {
			// Get packets from KNI
			uint16_t rx_pkts_number = rte_kni_rx_burst(kni[port], bufs, BURST_SIZE);
			rte_kni_handle_request(kni[port]);
			if (likely(rx_pkts_number != 0)) {
				rx_pkts_number = handleReceived(bufs, rx_pkts_number, tbl, pdeath_row);
				uint16_t pushed_pkts_number = rte_ring_enqueue_burst(out_ring, (void*)bufs, rx_pkts_number, NULL);

                UPDATE_COUNTERS(pushed_pkts_number, calculateSize(bufs, pushed_pkts_number), rx_pkts_number - pushed_pkts_number);

				// Free any packets which can't be pushed to the ring. The ring is probably full.
				handleUnpushed(bufs, pushed_pkts_number, rx_pkts_number);
			}
		}
		if (send == true) {
			(q == inIndexNumber - 1) ? q = 0 : q++;
			// Get packets for TX from ring
			uint16_t pkts_for_tx_number = rte_ring_mc_dequeue_burst(in_rings[q], (void*)bufs, BURST_SIZE, NULL);
			if (likely(pkts_for_tx_number != 0)) {
				uint16_t tx_pkts_number = rte_kni_tx_burst(kni[port], bufs, pkts_for_tx_number);

                UPDATE_COUNTERS(tx_pkts_number, calculateSize(bufs, tx_pkts_number), pkts_for_tx_number - tx_pkts_number);

				// Free any unsent packets
				handleUnpushed(bufs, tx_pkts_number, pkts_for_tx_number);
			}
		}
	}
	if (in_rings != NULL) {
		free(in_rings);
	}
	*flag = wasStopped;
}

void nff_go_send(uint16_t port, struct rte_ring **in_rings, int32_t inIndexNumber, bool anyway, volatile int *flag, int coreId, RXTXStats *stats) {
	setAffinity(coreId);

	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t buf;
	uint16_t tx_pkts_number;
	int16_t queue = 0;
	bool switchQueue = (check_port_tx(port) > 1) && (anyway || inIndexNumber > 1);
	while (*flag == process) {
		for (int q = 0; q < inIndexNumber; q++) {
			// Get packets for TX from ring
			uint16_t pkts_for_tx_number = rte_ring_mc_dequeue_burst(in_rings[q], (void*)bufs, BURST_SIZE, NULL);

			if (unlikely(pkts_for_tx_number == 0))
				continue;

			tx_pkts_number = rte_eth_tx_burst(port, queue, bufs, pkts_for_tx_number);
			// inIndexNumber must be "1" or even. This prevents any reordering.
			// anyway allows reordering explicitly
			if (switchQueue) {
				queue = !queue;
			}

            UPDATE_COUNTERS(tx_pkts_number, calculateSize(bufs, tx_pkts_number), pkts_for_tx_number - tx_pkts_number);

			// Free any unsent packets
			handleUnpushed(bufs, tx_pkts_number, pkts_for_tx_number);
#ifdef DEBUG
			send_required += pkts_for_tx_number;
			send_sent += tx_pkts_number;
#endif
		}
	}
	free(in_rings);
	*flag = wasStopped;
}

void nff_go_stop(struct rte_ring **in_rings, int len, volatile int *flag, int coreId) {
	setAffinity(coreId);
	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t buf;
	// Flag is used for both scheduler and stop.
	// stopRequest will stop scheduler and this loop will stop with stopRequest+1
	while (*flag == process || *flag == stopRequest) {
		for (int q = 0; q < len; q++) {
			// Get packets for freeing from ring
			uint16_t pkts_for_free_number = rte_ring_mc_dequeue_burst(in_rings[q], (void*)bufs, BURST_SIZE, NULL);

			if (unlikely(pkts_for_free_number == 0))
				continue;

			// Free all these packets
			for (buf = 0; buf < pkts_for_free_number; buf++) {
				rte_pktmbuf_free(bufs[buf]);
			}
#ifdef DEBUG
			stop_freed += pkts_for_free_number;
#endif
		}
	}
	free(in_rings);
	*flag = wasStopped;
}

void directStop(int pkts_for_free_number, struct rte_mbuf **bufs) {
	int buf;
	for (buf = 0; buf < pkts_for_free_number; buf++) {
		rte_pktmbuf_free(bufs[buf]);
	}
}

bool directSend(struct rte_mbuf *mbuf, uint16_t port) {
	// try to send one packet to specified port, zero queue
	if (rte_eth_tx_burst(port, 0, &mbuf, 1) == 1) {
		return true;
	} else {
		rte_pktmbuf_free(mbuf);
		return false;
	}
}

char ** makeArgv(int n) {
	return (char**) malloc(n * sizeof(char**));
}

void handleArgv(char ** argv, char * s, int i) {
	argv[i] = s;
}

void statistics(float N) {
#ifdef DEBUG
	//TODO This is only for 64 byte packets! 84 size is hardcoded.
	fprintf(stderr, "DEBUG: Current speed of all receives: received %.0f Mbits/s, pushed %.0f Mbits/s\n",
		(receive_received/N) * multiplier, (receive_pushed/N) * multiplier);
	if (receive_pushed < receive_received) {
		fprintf(stderr, "DROP: Receive dropped %ld packets\n", receive_received - receive_pushed);
	}
	fprintf(stderr, "DEBUG: Current speed of all sends: required %.0f Mbits/s, sent %.0f Mbits/s\n",
		(send_required/N) * multiplier, (send_sent/N) * multiplier);
	if (send_sent < send_required) {
		fprintf(stderr, "DROP: Send dropped %ld packets\n", send_required - send_sent);
	}
	fprintf(stderr, "DEBUG: Current speed of stop ring: freed %.0f Mbits/s\n", (stop_freed/N) * multiplier);
	// Yes, there can be race conditions here. However in practise they are rare and it is more
	// important to report real speed in 90% times than to slow it by adding atomic stores to
	// receive and send functions. This is debug mode.
	receive_received = 0;
	receive_pushed = 0;
	send_required = 0;
	send_sent = 0;
	stop_freed = 0;
#endif
}

// Initialize the Environment Abstraction Layer (EAL) in DPDK.
int eal_init(int argc, char *argv[], uint32_t burstSize, int32_t needKNI, bool noPacketHeadChange)
{
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		return -1;
	if (ret < argc-1)
		return 1;
	free(argv[argc-1]);
	free(argv);
	BURST_SIZE = burstSize;
	mbufStructSize = sizeof(struct rte_mbuf);
	headroomSize = RTE_PKTMBUF_HEADROOM;
	defaultStart = mbufStructSize + headroomSize;
	L2CanBeChanged = !noPacketHeadChange;
	if (needKNI != 0) {
		rte_kni_init(MAX_KNI);
	}
	return 0;
}

int allocateMbufs(struct rte_mempool *mempool, struct rte_mbuf **bufs, unsigned count) {
	int ret = rte_pktmbuf_alloc_bulk(mempool, bufs, count);
	if (ret == 0) {
		for (int i = 0; i < count; i++) {
			if (L2CanBeChanged == true) {
				mbufInitL2(bufs[i]);
			}
#ifdef REASSEMBLY
			mbufInitNextChain(bufs[i]);
#endif
		}
	}
	return ret;
}

struct rte_mempool * createMempool(uint32_t num_mbufs, uint32_t mbuf_cache_size) {
	struct rte_mempool *mbuf_pool;

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create(mempoolName, num_mbufs,
		mbuf_cache_size, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	mempoolName[7]++;

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	// Put mbuf addresses in all packets. It is CMbuf GO field.
	struct rte_mbuf **temp;
	temp = malloc(sizeof(struct rte_mbuf *) * num_mbufs);
	rte_pktmbuf_alloc_bulk(mbuf_pool, temp, num_mbufs);
	// This initializes CMbuf field of packet structure stored in mbuf
	// All CMbuf pointers is set to point to starting of corresponding mbufs
	for (int i = 0; i < num_mbufs; i++) {
		mbufInitL2(temp[i])
		mbufInitCMbuf(temp[i])
		mbufInitNextChain(temp[i])
	}
	for (int i = 0; i < num_mbufs; i++) {
		rte_pktmbuf_free(temp[i]);
	}
	free(temp);

	return mbuf_pool;
}

int getMempoolSpace(struct rte_mempool * m) {
	return rte_mempool_in_use_count(m);
}

struct nff_go_ring {
	struct rte_ring *DPDK_ring;
	// We need this second ring pointer because CGO can't calculate address for ring pointer variable. It is CGO limitation
	void *internal_DPDK_ring;
	uint32_t offset;
};

struct rte_ring** extractDPDKRings(struct nff_go_ring** r, int32_t inIndexNumber) {
	struct rte_ring **output = malloc(inIndexNumber*sizeof(struct rte_ring *));
	for (int i = 0; i < inIndexNumber; i++) {
		output[i] = r[i]->DPDK_ring;
	}
	return output;
}

struct nff_go_ring *
nff_go_ring_create(const char *name, unsigned count, int socket_id, unsigned flags) {
	struct nff_go_ring* r = malloc(sizeof(struct nff_go_ring));

	r->DPDK_ring = rte_ring_create(name, count, socket_id, flags);
	// Ring elements are located immidiately behind rte_ring structure
	// So ring[1] is pointed to the beginning of this data
	r->internal_DPDK_ring = &(r->DPDK_ring)[1];
	r->offset = sizeof(void*);
	return r;
}

void *
lpm_create(const char *name, int socket_id, uint32_t maxRules, uint32_t numberTbl8, uint32_t (**tbl24)[1], uint32_t (**tbl8)[1]) {
	struct rte_lpm_config config;
	config.max_rules = maxRules;
	config.number_tbl8s = numberTbl8;
	struct rte_lpm *lpm = rte_lpm_create(name, socket_id, &config);
	*tbl24 = (uint32_t(*)[1])lpm->tbl24;
	*tbl8 = (uint32_t(*)[1])lpm->tbl8;
	return (void*)lpm;
}

int lpm_add(void *lpm, uint32_t ip, uint8_t depth, uint32_t next_hop) {
	return rte_lpm_add((struct rte_lpm*)lpm, ip, depth, next_hop);
}

int lpm_delete(void *lpm, uint32_t ip, uint8_t depth) {
	return rte_lpm_delete((struct rte_lpm *)lpm, ip, depth);
}

void lpm_free(void *lpm) {
	rte_lpm_free((struct rte_lpm *)lpm);
}

// Callbacks for multiple KNI requests
// If you would like to change this:
//     1. It is not recomended
//     2. You should check if there are new callbacks in DPDK
//     3. You should check examples/kni/main.c file for callbacks examples
//     4. You should understand that calling rte_eth_dev_stop in the same time of rte_eth_rx_burst will result to errors
//	 4a. One of these errors can be overloading of receive mempool
//     5. You should understand that calling rte_eth_dev_start should include receive ring handling as in port_init
static int KNI_change_mtu(uint16_t port_id, unsigned int new_mtu) {
	fprintf(stderr, "DEBUG: KNI: Change MTU of port %d to %u\n", port_id, new_mtu);
	return 0;
}

static int KNI_config_network_interface(uint16_t port_id, uint8_t if_up) {
	fprintf(stderr, "DEBUG: KNI: Configure network interface of port %d %s\n", port_id, if_up ? "up" : "down");
	return 0;
}

static int KNI_config_mac_address(uint16_t port_id, uint8_t mac_addr[]) {
	fprintf(stderr, "DEBUG: KNI: Configure new MAC address of port %d\n", port_id);
	return 0;
}

static int KNI_config_promiscusity(uint16_t port_id, uint8_t to_on) {
	fprintf(stderr, "DEBUG: KNI: Promiscusity mode of port %d %s\n", port_id, to_on ? "on" : "off");
	return 0;
}

bool check_hwtxchecksum_capability(uint16_t port_id) {
	uint64_t flags = DEV_TX_OFFLOAD_IPV4_CKSUM |
		DEV_TX_OFFLOAD_UDP_CKSUM |
		DEV_TX_OFFLOAD_TCP_CKSUM;
	struct rte_eth_dev_info dev_info;

	if (port_id >= rte_eth_dev_count())
		return false;

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port_id, &dev_info);
	return (dev_info.tx_offload_capa & flags) == flags;
}

int initDevice(char *name) {
	int s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 1) {
		fprintf(stderr, "ERROR: Can't create socket for OS send/receive\n");
		return -1;
	}

	struct ifreq ifr;
	memset (&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
	if (ioctl(s, SIOCGIFINDEX, &ifr) == -1) {
		fprintf(stderr, "ERROR: Can't find device %s\n", name);
		return -1;
	}

	struct sockaddr_ll myaddr;
	memset(&myaddr, 0, sizeof(myaddr));
	myaddr.sll_family = AF_PACKET;
	myaddr.sll_protocol = htons(ETH_P_ALL);
	myaddr.sll_ifindex = ifr.ifr_ifindex;
	if (bind(s, (struct sockaddr*)&myaddr, sizeof(myaddr)) < 0) {
		fprintf(stderr, "ERROR: Can't bind socket to %s\n", name);
		return -1;
	}

	ioctl(s, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) != 0) {
		fprintf(stderr, "ERROR: Can't set up promiscuos mode on %s\n", name);
		return -1;
	}

	return s;
}

void receiveOS(int socket, struct rte_ring *out_ring, struct rte_mempool *m, volatile int *flag, int coreId, RXTXStats *stats) {
	setAffinity(coreId);
	const int recvOSBusrst = BURST_SIZE;
	struct rte_mbuf *bufs[recvOSBusrst];
	REASSEMBLY_INIT
	while (*flag == process) {
		// Get packets from OS
		allocateMbufs(m, bufs, recvOSBusrst);
		//int step = 0;
		for (int i = 0; i < recvOSBusrst; i++) {
			int bytes_received = recv(socket, (char *)(bufs[i]) + defaultStart, ETH_FRAME_LEN, 0);
			if (unlikely(bytes_received == 0)) {
				//step++;
				i--;
				continue;
			}
			rte_pktmbuf_append(bufs[i], bytes_received);
		}
		uint16_t rx_pkts_number = handleReceived(bufs, recvOSBusrst, tbl, pdeath_row);
		uint16_t pushed_pkts_number = rte_ring_enqueue_burst(out_ring, (void*)bufs, rx_pkts_number, NULL);

        UPDATE_COUNTERS(pushed_pkts_number, calculateSize(bufs, pushed_pkts_number), rx_pkts_number - pushed_pkts_number);

        // Free any packets which can't be pushed to the ring. The ring is probably full.
        handleUnpushed((void*)bufs, pushed_pkts_number, rx_pkts_number);
	}
	*flag = wasStopped;
}

void sendOS(int socket, struct rte_ring **in_rings, int32_t inIndexNumber, volatile int *flag, int coreId, RXTXStats *stats) {
	setAffinity(coreId);

	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t buf;
	uint16_t tx_pkts_number;
	while (*flag == process) {
		for (int q = 0; q < inIndexNumber; q++) {
			// Get packets for TX from ring
			uint16_t pkts_for_tx_number = rte_ring_mc_dequeue_burst(in_rings[q], (void*)bufs, BURST_SIZE, NULL);

			for (int i = 0; i < pkts_for_tx_number; i++) {
				send(socket, (char *)(bufs[i]) + defaultStart, rte_pktmbuf_pkt_len(bufs[i]), 0);
			}

            UPDATE_COUNTERS(pkts_for_tx_number, calculateSize(bufs, pkts_for_tx_number), 0);

			// Free all packets
			handleUnpushed(bufs, 0, pkts_for_tx_number);
		}
	}
	free(in_rings);
	*flag = wasStopped;
}
