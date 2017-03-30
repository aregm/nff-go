// Copyright 2017 Intel Corporation. 
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <rte_ring.h>

struct nfv_ring {
	struct rte_ring *DPDK_ring;
	// We need this second ring pointer because CGO can't calculate address for ring pointer variable. It is CGO limitation
	void *internal_DPDK_ring;
	uint32_t offset;
};

struct nfv_ring *
nfv_ring_create(const char *name, unsigned count, int socket_id, unsigned flags) {
	struct nfv_ring* r;
	r = malloc(sizeof(struct nfv_ring));

	r->DPDK_ring = rte_ring_create(name, count, socket_id, flags);
	r->internal_DPDK_ring = r->DPDK_ring->ring;
	r->offset = sizeof(r->DPDK_ring->ring[0]);
	return r;
}
