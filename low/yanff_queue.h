// Copyright 2017 Intel Corporation. 
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#define _GNU_SOURCE

#include <stdbool.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "yanff_ring.h"

struct yanff_queue {
	struct yanff_ring *ring;
  //	uint64_t rx_quantity;
};

struct yanff_queue *
yanff_queue_create(const char *name, unsigned count, int socket_id, unsigned flags) {
        struct yanff_queue *queue;
	queue = malloc(sizeof(struct yanff_queue));

        queue->ring = yanff_ring_create(name, count, socket_id, flags);
        //	queue->rx_quantity = 0;
	return queue;
}
