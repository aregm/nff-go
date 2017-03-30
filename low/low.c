// Copyright 2017 Intel Corporation. 
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#define _GNU_SOURCE

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <signal.h>
#include <unistd.h>

// These constants are get from DPDK and checked for performance
#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

// #define DEBUG
// #define VERBOSE

struct rte_mempool * mp;
long receive_received = 0, receive_pushed = 0;
long send_required = 0, send_sent = 0;
long stop_freed = 0;
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
int port_init(uint8_t port, uint16_t receiveQueuesNumber, uint16_t sendQueuesNumber, struct rte_mempool *mbuf_pool, struct ether_addr* addr)
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

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
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
	uint16_t buf;
	// Run until the application is quit. Recv can't be stopped now.
	for (;;) {
		// Get RX packets from port
		const uint16_t rx_pkts_number = rte_eth_rx_burst(port, queue, bufs, BURST_SIZE);

		if (unlikely(rx_pkts_number == 0))
			continue;

		uint16_t pushed_pkts_number = rte_ring_enqueue_burst(out_ring, (void*)bufs, rx_pkts_number);
		// Free any packets which can't be pushed to the ring. The ring is probably full.
		if (unlikely(pushed_pkts_number < rx_pkts_number)) {
#ifdef VERBOSE
			fprintf(stderr, "WARNING: Receive pushes to queue only: %d packets from %d\n", pushed_pkts_number, rx_pkts_number);
#endif
			for (buf = pushed_pkts_number; buf < rx_pkts_number; buf++) {
				rte_pktmbuf_free(bufs[buf]);
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
		uint16_t pkts_for_tx_number = rte_ring_mc_dequeue_burst(in_ring, (void*)bufs, BURST_SIZE);

		if (unlikely(pkts_for_tx_number == 0))
			continue;

		const uint16_t tx_pkts_number = rte_eth_tx_burst(port, queue, bufs, pkts_for_tx_number);
		// Free any unsent packets.
		if (unlikely(tx_pkts_number < pkts_for_tx_number)) {
#ifdef VERBOSE
			fprintf(stderr, "WARNING: Send sends only: %d packets from %d\n", tx_pkts_number, pkts_for_tx_number);
#endif
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
		uint16_t pkts_for_free_number = rte_ring_mc_dequeue_burst(in_ring, (void*)bufs, BURST_SIZE);

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

void statistics(int sig) {
	float N = 4;
	//TODO This is only for 64 byte packets! 84 size is hardcoded.
	fprintf(stderr, "DEBUG: Current speed of all receives: received %.0f Mbits/s, pushed %.0f Mbits/s\n",
		(receive_received/N) * multiplier, (receive_pushed/N) * multiplier);
	fprintf(stderr, "DEBUG: Current speed of all sends: required %.0f Mbits/s, sent %.0f Mbits/s\n",
		(send_required/N) * multiplier, (send_sent/N) * multiplier);
	fprintf(stderr, "DEBUG: Current speed of stop ring: freed %.0f Mbits/s\n", (stop_freed/N) * multiplier);
	receive_received = 0;
	receive_pushed = 0;
	send_required = 0;
	send_sent = 0;
	stop_freed = 0;

	//TODO after we decide how many mempools to use we need reports for each mempool capacity here

	alarm(N);
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
#ifdef DEBUG
	signal(SIGALRM, statistics);
	alarm(1);
#endif
}

struct rte_mempool * createMempool(int portsNumber, uint32_t num_mbufs, uint32_t mbuf_cache_size) {
	struct rte_mempool *mbuf_pool;

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", num_mbufs * portsNumber,
		mbuf_cache_size, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	return mbuf_pool;
}
