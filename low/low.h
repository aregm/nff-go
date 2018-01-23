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
#include <rte_kni.h>

// These constants are get from DPDK and checked for performance
#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

// #define DEBUG
// #define REASSEMBLY

// This macros clears packet structure which is stored inside mbuf
// 0 offset is L3 protocol pointer
// 8 offset is L4 protocol pointer
// 16 offset is a data offset and shouldn't be cleared
// 24 offset is L2 offset and is always begining of packet
// 32 offset is CMbuf offset and is initilized when mempool is created
// 40 offset is Next field. Should be 0. Will be filled later if required
#define mbufInit(buf) \
*(char **)((char *)(buf) + mbufStructSize + 24) = (char *)(buf) + defaultStart; \
*(char **)((char *)(buf) + mbufStructSize + 40) = 0;

// Firstly we set "next" packet pointer (+40) to the packet from next mbuf
// Secondly we know that followed mbufs don't contain L2 and L3 headers. We assume that they start with a data
// so we assume that Data packet field (+16) should be equal to Ether packet field (+24)
// (which we parse at this packet segment receiving
#define mbufSetNext(buf) \
*(char **)((char *)(buf) + mbufStructSize + 40) = (char *)(buf->next) + mbufStructSize; \
*(char **)((char *)(buf->next) + mbufStructSize + 16) = *(char **)((char *)(buf->next) + mbufStructSize + 24)

long receive_received = 0, receive_pushed = 0;
long send_required = 0, send_sent = 0;
long stop_freed = 0;

int mbufStructSize;
int headroomSize;
int defaultStart;
char mempoolName[9] = "mempool1\0";

__m128 zero128 = {0, 0, 0, 0};
#ifdef RTE_MACHINE_CPUFLAG_AVX
__m256 zero256 = {0, 0, 0, 0, 0, 0, 0, 0};
#endif

// This is multiplier for conversion from PKT/s to Mbits/s for 64 (84 in total length) packets
const float multiplier = 84.0 * 8.0 / 1000.0 / 1000.0;

#define MAX_KNI 50
struct rte_kni* kni[MAX_KNI];

uint32_t BURST_SIZE;

void initCPUSet(uint8_t coreId, cpu_set_t* cpuset) {
	CPU_ZERO(cpuset);
	CPU_SET(coreId, cpuset);
}

void setAffinity(uint8_t coreId) {
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(coreId, &cpuset);
	sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

void create_kni(uint8_t port, uint8_t core, char *name, struct rte_mempool *mbuf_pool) {
	struct rte_eth_dev_info dev_info;
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port, &dev_info);
	struct rte_kni_conf port_conf_default = {
	    .core_id = core, // Core ID to bind kernel thread on
	    .group_id = (uint16_t)port,
	    .mbuf_size = 2048,
	    .addr = dev_info.pci_dev->addr,
	    .id = dev_info.pci_dev->id,
	    .force_bind = 1 // Flag to bind kernel thread
	};
	snprintf(port_conf_default.name, RTE_KNI_NAMESIZE, "%s", name);
	// TODO this NULL is for ops structure which handles callbacks from kernels requests
	// DPDK example has callbacks for "change mtu" and "config network interface"
	kni[port] = rte_kni_alloc(mbuf_pool, &port_conf_default, NULL);
	if (kni[port] == NULL) {
		rte_exit(EXIT_FAILURE, "Error with KNI allocation\n");
	}
}

// Initializes a given port using global settings and with the RX buffers
// coming from the mbuf_pool passed as a parameter.
int port_init(uint8_t port, uint16_t receiveQueuesNumber, uint16_t sendQueuesNumber, struct rte_mempool *mbuf_pool,
    struct ether_addr* addr, bool hwtxchecksum) {
	const uint16_t rx_rings = receiveQueuesNumber, tx_rings = sendQueuesNumber;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	struct rte_eth_conf port_conf_default = {
	    .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN,
			.mq_mode = ETH_MQ_RX_RSS    },
	    .txmode = { .mq_mode = ETH_MQ_TX_NONE, },
	    .rx_adv_conf.rss_conf.rss_key = NULL,
	    .rx_adv_conf.rss_conf.rss_hf = ETH_RSS_PROTO_MASK
	};

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf_default);
	if (retval != 0)
		return retval;

	/* Allocate and set up RX queues per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	struct rte_eth_dev_info dev_info;
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port, &dev_info);
	if (hwtxchecksum) {
		/* Default TX settings are to disable offload operations, need to fix it */
		dev_info.default_txconf.txq_flags = 0;
	}

	/* Allocate and set up TX queues per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), &dev_info.default_txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Get the port MAC address. */
	rte_eth_macaddr_get(port, addr);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
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

struct rte_mbuf* reassemble(struct rte_ip_frag_tbl* tbl, struct rte_mbuf *buf, struct rte_ip_frag_death_row* death_row, uint64_t cur_tsc) {
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

void yanff_recv(uint8_t port, int16_t queue, struct rte_ring *out_ring, uint8_t coreId) {
	setAffinity(coreId);

	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t i;
	uint16_t rx_pkts_number;

#ifdef REASSEMBLY
	struct rte_ip_frag_tbl* tbl = create_reassemble_table();
	struct rte_ip_frag_death_row death_row;
	death_row.cnt = 0; // DPDK doesn't initialize this field. It is probably a bug.
	struct rte_mbuf *temp;
#endif
	// Run until the application is quit. Recv can't be stopped now.
	for (;;) {
		// Get RX packets from port
		if (queue != -1) {
			rx_pkts_number = rte_eth_rx_burst(port, queue, bufs, BURST_SIZE);
		} else {
			// If queue == "-1" is means that this receive is from KNI device
			rx_pkts_number = rte_kni_rx_burst(kni[port], bufs, BURST_SIZE);
		}
#ifdef REASSEMBLY
		uint16_t temp_number = 0;
		uint64_t cur_tsc = rte_rdtsc();
#endif

		if (unlikely(rx_pkts_number == 0))
			continue;

		for (i = 0; i < rx_pkts_number; i++) {
			// Prefetch decreases speed here without reassembly and increases with reassembly.
			// Speed of this is highly influenced by size of mempool. It seems that due to caches.
			mbufInit(bufs[i]);
#ifdef REASSEMBLY
			// TODO prefetch will give 8-10% performance in reassembly case.
			// However we need additional investigations about small (< 3) packet numbers.
			//rte_prefetch0(rte_pktmbuf_mtod(bufs[i + 3 /* PREFETCH_OFFSET */], void *));
			bufs[i] = reassemble(tbl, bufs[i], &death_row, cur_tsc);
			if (bufs[i] == NULL) {
				continue; // no packet to send out.
			}
			temp = bufs[i];
			while (temp->next != NULL) {
				mbufSetNext(temp);
				temp = temp->next;
			}
			bufs[temp_number] = bufs[i];
			temp_number++;
#endif
		}

#ifdef REASSEMBLY
		rx_pkts_number = temp_number;
		rte_ip_frag_free_death_row(&death_row, 0 /* PREFETCH_OFFSET */);
#endif

		uint16_t pushed_pkts_number = rte_ring_enqueue_burst(out_ring, (void*)bufs, rx_pkts_number, NULL);
		// Free any packets which can't be pushed to the ring. The ring is probably full.
		if (unlikely(pushed_pkts_number < rx_pkts_number)) {
			for (i = pushed_pkts_number; i < rx_pkts_number; i++) {
				rte_pktmbuf_free(bufs[i]);
			}
		}
#ifdef DEBUG
		receive_received += rx_pkts_number;
		receive_pushed += pushed_pkts_number;
#endif
	}
}

void yanff_send(uint8_t port, int16_t queue, struct rte_ring *in_ring, uint8_t coreId) {
	setAffinity(coreId);

	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t buf;
	uint16_t tx_pkts_number;
	// Run until the application is quit. Send can't be stopped now.
	for (;;) {
		// Get packets for TX from ring
		uint16_t pkts_for_tx_number = rte_ring_mc_dequeue_burst(in_ring, (void*)bufs, BURST_SIZE, NULL);

		if (unlikely(pkts_for_tx_number == 0))
			continue;

		if (queue != -1) {
			tx_pkts_number = rte_eth_tx_burst(port, queue, bufs, pkts_for_tx_number);
		} else {
			// if queue == "-1" this means that this send is to KNI device
			tx_pkts_number = rte_kni_tx_burst(kni[port], bufs, pkts_for_tx_number);
		}
		// Free any unsent packets.
		if (unlikely(tx_pkts_number < pkts_for_tx_number)) {
			for (buf = tx_pkts_number; buf < pkts_for_tx_number; buf++) {
				rte_pktmbuf_free(bufs[buf]);
			}
		}
#ifdef DEBUG
		send_required += pkts_for_tx_number;
		send_sent += tx_pkts_number;
#endif
	}
}

void yanff_stop(struct rte_ring *in_ring) {
	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t buf;
	// Run until the application is quit. Stop can't be stopped now.
	for (;;) {
		// Get packets for freeing from ring
		uint16_t pkts_for_free_number = rte_ring_mc_dequeue_burst(in_ring, (void*)bufs, BURST_SIZE, NULL);

		if (unlikely(pkts_for_free_number == 0))
			continue;

		// Free all this packets
		for (buf = 0; buf < pkts_for_free_number; buf++) {
			rte_pktmbuf_free(bufs[buf]);
		}

#ifdef DEBUG
		stop_freed += pkts_for_free_number;
#endif
	}
}

void directStop(int pkts_for_free_number, struct rte_mbuf **bufs) {
	int buf;
	for (buf = 0; buf < pkts_for_free_number; buf++) {
		rte_pktmbuf_free(bufs[buf]);
	}
}

bool directSend(struct rte_mbuf *mbuf, uint8_t port) {
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
		fprintf(stderr, "DROP: Receive dropped %d packets\n", receive_received - receive_pushed);
	}
	fprintf(stderr, "DEBUG: Current speed of all sends: required %.0f Mbits/s, sent %.0f Mbits/s\n",
		(send_required/N) * multiplier, (send_sent/N) * multiplier);
	if (send_sent < send_required) {
		fprintf(stderr, "DROP: Send dropped %d packets\n", send_required - send_sent);
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
void eal_init(int argc, char *argv[], uint32_t burstSize, int32_t needKNI)
{
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	if (ret < argc-1)
		rte_exit(EXIT_FAILURE, "rte_eal_init can't parse all parameters\n");
	free(argv[argc-1]);
	free(argv);
	BURST_SIZE = burstSize;
	mbufStructSize = sizeof(struct rte_mbuf);
	headroomSize = RTE_PKTMBUF_HEADROOM;
	defaultStart = mbufStructSize + headroomSize;
	if (needKNI != 0) {
		rte_kni_init(MAX_KNI);
	}
}

int allocateMbufs(struct rte_mempool *mempool, struct rte_mbuf **bufs, unsigned count);

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
	allocateMbufs(mbuf_pool, temp, num_mbufs);
	// This initializes CMbuf field of packet structure stored in mbuf
	// All CMbuf pointers is set to point to starting of corresponding mbufs
	for (int i = 0; i < num_mbufs; i++) {
		*(char**)((char*)(temp[i]) + mbufStructSize + 32) = (char*)(temp[i]);
	}
	for (int i = 0; i < num_mbufs; i++) {
		rte_pktmbuf_free(temp[i]);
	}
	free(temp);

	return mbuf_pool;
}

int allocateMbufs(struct rte_mempool *mempool, struct rte_mbuf **bufs, unsigned count) {
	int ret = rte_pktmbuf_alloc_bulk(mempool, bufs, count);
	if (ret == 0) {
		for (int i = 0; i < count; i++) {
			mbufInit(bufs[i]);
		}
	}
	return ret;
}

int getMempoolSpace(struct rte_mempool * m) {
	return rte_mempool_in_use_count(m);
}

struct yanff_ring {
        struct rte_ring *DPDK_ring;
        // We need this second ring pointer because CGO can't calculate address for ring pointer variable. It is CGO limitation
        void *internal_DPDK_ring;
        uint32_t offset;
};

struct yanff_ring *
yanff_ring_create(const char *name, unsigned count, int socket_id, unsigned flags) {
        struct yanff_ring* r;
        r = malloc(sizeof(struct yanff_ring));

        r->DPDK_ring = rte_ring_create(name, count, socket_id, flags);
        // Ring elements are located immidiately behind rte_ring structure
        // So ring[1] is pointed to the beginning of this data
        r->internal_DPDK_ring = &(r->DPDK_ring)[1];
        r->offset = sizeof(void*);
        return r;
}
