// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asm

func Rte_compiler_rmb() /* lfence*/
func Rte_compiler_wmb() /* sfence */
func Prefetcht0(addr uintptr)
