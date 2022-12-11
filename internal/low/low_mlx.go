// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build mlx

package low

/*
#cgo LDFLAGS: -lrte_distributor -lrte_reorder -lrte_kni -lrte_pipeline -lrte_table -lrte_port -lrte_timer -lrte_jobstats -lrte_lpm -lrte_power -lrte_acl -lrte_meter -lrte_sched -lrte_vhost -lrte_ip_frag -lrte_cfgfile -Wl,--whole-archive -Wl,--start-group -lrte_kvargs -lrte_mbuf -lrte_hash -lrte_ethdev -lrte_gso -lrte_mempool -lrte_ring -lrte_mempool_ring -lrte_eal -lrte_cmdline -lrte_net -lrte_bus_pci -lrte_pci -lrte_bus_vdev -lrte_timer -lrte_pmd_bond -lrte_pmd_vmxnet3_uio -lrte_pmd_virtio -lrte_pmd_cxgbe -lrte_pmd_enic -lrte_pmd_i40e -lrte_pmd_fm10k -lrte_pmd_ixgbe -lrte_pmd_e1000 -lrte_pmd_ena -lrte_pmd_ring -lrte_pmd_af_packet -lrte_pmd_null -lrte_pmd_failsafe -lrte_pmd_tap -lrte_pmd_vdev_netvsc -lrte_bus_vmbus -lrte_pmd_netvsc -libverbs -lmnl -lmlx4 -lmlx5 -lrte_pmd_mlx4 -lrte_pmd_mlx5 -Wl,--end-group -Wl,--no-whole-archive -lrt -lm -ldl -lnuma
*/
import "C"
