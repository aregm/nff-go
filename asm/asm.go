// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asm

// RteCompilerRmb is lfence
func RteCompilerRmb()

// RteCompilerWmb is sfence
func RteCompilerWmb()

// Prefetcht0 is prefetch
func Prefetcht0(addr uintptr)
