// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// This is asm block routine unrolled x8 and acting on 8 input blocks

// func encrypt8BlocksAsm(xk *uint32, dst, src [][]byte)
TEXT ·encrypt8BlocksAsm(SB), NOSPLIT, $0
	// For now 128 only
	MOVQ       xk+0(FP), AX
	MOVQ       dst+8(FP), DI  // dst
	MOVQ       src+32(FP), SI // src
	MOVQ       (SI), BX // &src[0]
	MOVQ       24(SI), BP // &src[1] ...
	MOVQ       48(SI), R9
	MOVQ       72(SI), R10
	MOVQ       96(SI), R11
	MOVQ       120(SI), R12
	MOVQ       144(SI), R13
	MOVQ       168(SI), R14
	MOVUPS     0(AX), X0 // Key
	MOVUPS     0(BX), X1 //src[0]
	MOVUPS     0(BP), X2
	MOVUPS     0(R9), X3
	MOVUPS     0(R10), X4
	MOVUPS     0(R11), X5
	MOVUPS     0(R12), X6
	MOVUPS     0(R13), X7
	MOVUPS     0(R14), X8
	ADDQ       $16, AX
	PXOR       X0, X1
	PXOR       X0, X2
	PXOR       X0, X3
	PXOR       X0, X4
	PXOR       X0, X5
	PXOR       X0, X6
	PXOR       X0, X7
	PXOR       X0, X8
	MOVUPS     0(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     16(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     32(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     48(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     64(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     80(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     96(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     112(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     128(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     144(AX), X0
	AESENCLAST X0, X1
	AESENCLAST X0, X2
	AESENCLAST X0, X3
	AESENCLAST X0, X4
	AESENCLAST X0, X5
	AESENCLAST X0, X6
	AESENCLAST X0, X7
	AESENCLAST X0, X8
	MOVQ       (DI), DX // &dst[0]
	MOVQ       24(DI), SI
	MOVQ       48(DI), AX
	MOVQ       72(DI), BX
	MOVQ       96(DI), CX
	MOVQ       120(DI), BP
	MOVQ       144(DI), R8
	MOVQ       168(DI), R9
	MOVUPS     X1, 0(DX)
	MOVUPS     X2, 0(SI)
	MOVUPS     X3, 0(AX)
	MOVUPS     X4, 0(BX)
	MOVUPS     X5, 0(CX)
	MOVUPS     X6, 0(BP)
	MOVUPS     X7, 0(R8)
	MOVUPS     X8, 0(R9)
	RET
