// Copyright 2017 Intel Corporation. 
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#define _GNU_SOURCE

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "nfv_ring.h"

struct nfv_queue {
	struct nfv_ring *ring;
  //	uint64_t rx_quantity;
};

struct nfv_queue *
nfv_queue_create(const char *name, unsigned count, int socket_id, unsigned flags) {
        struct nfv_queue *queue;
	queue = malloc(sizeof(struct nfv_queue));

        queue->ring = nfv_ring_create(name, count, socket_id, flags);
        //	queue->rx_quantity = 0;
	return queue;
}
