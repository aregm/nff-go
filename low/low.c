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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>


// These constants are get from DPDK and checked for performance
#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

// #define DEBUG

#ifdef RTE_MACHINE_CPUFLAG_AVX
#define mbufClear(buf) \
	_mm256_storeu_ps((float*)(buf + mbufStructSize), zero256);
#else
#define mbufClear(buf) \
	_mm_storeu_ps((float*)(buf + mbufStructSize), zero128); \
	_mm_storeu_ps((float*)(buf + mbufStructSize + 16), zero128);
#endif

// This macros clears packet structure which is stored inside mbuf
// mbufClear clears IPv4, IPv6, TCP and UDP protocols
// 32 offset clears ICMP protocol
// 40 offset is a data offset and shouldn't be cleared
// 48 offset is L2 offset and is always begining of packet
// 56 offset is CMbuf offset and is initilized when mempool is created
#define mbufInit(buf) \
	mbufClear(buf) \
	*(char**)((char*)(buf) + mbufStructSize + 32) = 0; \
	*(char**)((char*)(buf) + mbufStructSize + 48) = (char*)(buf) + defaultStart;

int allocateMbufs(struct rte_mempool *mempool, struct rte_mbuf **bufs, unsigned count);

long receive_received = 0, receive_pushed = 0;
long send_required = 0, send_sent = 0;
long stop_freed = 0;

int64_t mbufStructSize;
int headroomSize;
int defaultStart;
char mempoolName[9] = "mempool1\0";

__m128 zero128 = {0, 0, 0, 0};
#ifdef RTE_MACHINE_CPUFLAG_AVX
__m256 zero256 = {0, 0, 0, 0, 0, 0, 0, 0};
#endif

// This is multiplier for conversion from PKT/s to Mbits/s for 64 (84 in total length) packets
const float multiplier = 84.0 * 8.0 / 1000.0 / 1000.0;

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

// Initializes a given port using global settings and with the RX buffers
// coming from the mbuf_pool passed as a parameter.
int port_init(uint8_t port, uint16_t receiveQueuesNumber, uint16_t sendQueuesNumber, struct rte_mempool *mbuf_pool,
    struct ether_addr* addr, bool hwtxchecksum)
{
	//struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = receiveQueuesNumber, tx_rings = sendQueuesNumber;
	//const uint16_t rx_rings = 1, tx_rings = 1;
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

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port, &dev_info);
    if (hwtxchecksum) {
        /* Default TX settings are to disable offload operations, need to fix it */
        dev_info.default_txconf.txq_flags = 0;
    }

	/* Allocate and set up 1 TX queue per Ethernet port. */
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

void recv(uint8_t port, uint16_t queue, struct rte_ring *out_ring, uint8_t coreId) {
	setAffinity(coreId);

	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t i;

	// Run until the application is quit. Recv can't be stopped now.
	for (;;) {
		// Get RX packets from port
		const uint16_t rx_pkts_number = rte_eth_rx_burst(port, queue, bufs, BURST_SIZE);

		if (unlikely(rx_pkts_number == 0))
			continue;

		for (i = 0; i < rx_pkts_number; i++) {
			// Prefetch decreases speed here.
			// Speed of this is highly influenced by size of mempool. It seems that due to caches.
			mbufInit(bufs[i]);
		}

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

void send(uint8_t port, uint16_t queue, struct rte_ring *in_ring, uint8_t coreId) {
	setAffinity(coreId);

	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t buf;
	// Run until the application is quit. Send can't be stopped now.
	for (;;) {
		// Get packets for TX from ring
		uint16_t pkts_for_tx_number = rte_ring_mc_dequeue_burst(in_ring, (void*)bufs, BURST_SIZE, NULL);

		if (unlikely(pkts_for_tx_number == 0))
			continue;

		const uint16_t tx_pkts_number = rte_eth_tx_burst(port, queue, bufs, pkts_for_tx_number);
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

void stop(struct rte_ring *in_ring) {
	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t buf;
	// Run until the application is quit. Stop can't be stopped now.
	for (;;) {
		// Get packets for freeing from ring
		uint16_t pkts_for_free_number = rte_ring_mc_dequeue_burst(in_ring, (void*)bufs, BURST_SIZE, NULL);

		if (unlikely(pkts_for_free_number == 0))
			continue;

		// Free all this packets
		for (buf = 0; buf < pkts_for_free_number; buf++)
			rte_pktmbuf_free(bufs[buf]);

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
void eal_init(int argc, char *argv[], uint32_t burstSize)
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
	allocateMbufs(mbuf_pool, temp, num_mbufs);
	// This initializes CMbuf field of packet structure stored in mbuf
	// All CMbuf pointers is set to point to starting of cerresponding mbufs
	for (int i = 0; i < num_mbufs; i++) {
		*(char**)((char*)(temp[i]) + mbufStructSize + 56) = (char*)(temp[i]);
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
