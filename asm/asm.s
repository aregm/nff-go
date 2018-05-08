// Copyright 2017 Intel Corporation. 
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"
TEXT ·RteCompilerRmb(SB),NOSPLIT,$0-0
        LFENCE
        RET
TEXT ·RteCompilerWmb(SB),NOSPLIT,$0-0
        SFENCE
        RET
TEXT ·Prefetcht0(SB),NOSPLIT,$0-8
        MOVQ    addr+0(FP), AX
        PREFETCHT0      (AX)
        RET
TEXT ·GenerateMask(SB),NOSPLIT,$0-33
        MOVQ    v1+0(FP), AX
        MOVQ    v2+8(FP), BX
        MOVQ    previousMask+16(FP), CX
        MOVQ    result+24(FP), DX
        VMOVDQU (AX), Y0
        VMOVDQU (BX), Y1
        VMOVDQU (CX), Y2
        VPCMPEQB Y0, Y1, Y0
        VPAND Y0, Y2, Y0
        VPTEST Y0, Y0
        SETEQ a+32(FP)
        VMOVDQU Y0, (DX)
        VZEROUPPER
        RET
