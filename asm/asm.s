// Copyright 2017 Intel Corporation. 
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"
TEXT ·Rte_compiler_rmb(SB),NOSPLIT,$0-0
        LFENCE
        RET
TEXT ·Rte_compiler_wmb(SB),NOSPLIT,$0-0
        SFENCE
        RET
TEXT ·Prefetcht0(SB),NOSPLIT,$0-8
        MOVQ    addr+0(FP), AX
        PREFETCHT0      (AX)
        RET
