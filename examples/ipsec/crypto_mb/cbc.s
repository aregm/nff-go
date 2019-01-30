// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"
// func xor16(dst,src,iv *byte)
TEXT ·xor16(SB), NOSPLIT, $0
	MOVQ   dst+0(FP), AX
	MOVQ   src+8(FP), BX
	MOVQ   iv+16(FP), CX
	MOVUPS (BX), X0
	MOVUPS (CX), X1
	PXOR   X0, X1
	MOVUPS X1, (AX)
	RET

// func aes_x8_cbc_encrypt(xk *uint32,dst,src,iv [][]byte,ln int)
TEXT ·aes_x8_cbc_encrypt(SB), NOSPLIT, $0
	MOVQ xk+0(FP), AX   // xk
	MOVQ dst+8(FP), DI  // dst
	MOVQ src+16(FP), SI // src
	MOVQ iv+24(FP), BP  // iv
	MOVQ ln+32(FP), BX  // ln
	MOVQ 0(BP), R8      // iv[0]
	MOVQ 8(BP), R9     // iv[1]
	MOVQ 16(BP), R10
	MOVQ 24(BP), R11
	MOVQ 32(BP), R12
	MOVQ 40(BP), R13
	MOVQ 48(BP), R14
	MOVQ 56(BP), R15
	XORQ CX, CX

loop:
	CMPQ       CX, BX
	JGE        done
	MOVUPS     0(AX), X0        // key
	MOVQ       0(SI), DX        // &src[0]
	MOVUPS     0(R8), X1
	MOVUPS     0(R9), X2
	MOVUPS     0(R10), X3
	MOVUPS     0(R11), X4
	MOVUPS     0(R12), X5
	MOVUPS     0(R13), X6
	MOVUPS     0(R14), X7
	MOVUPS     0(R15), X8
	MOVUPS     0(CX)(DX*1), X9  // src[0][CX:CX+16]
	PXOR       X9, X1
	MOVQ       8(SI), DX       // &src[1]
	MOVUPS     0(CX)(DX*1), X9
	PXOR       X9, X2
	MOVQ       16(SI), DX       // &src[2]
	MOVUPS     0(CX)(DX*1), X9
	PXOR       X9, X3
	MOVQ       24(SI), DX       // &src[3]
	MOVUPS     0(CX)(DX*1), X9
	PXOR       X9, X4
	MOVQ       32(SI), DX       // &src[4]
	MOVUPS     0(CX)(DX*1), X9
	PXOR       X9, X5
	MOVQ       40(SI), DX      // &src[5]
	MOVUPS     0(CX)(DX*1), X9
	PXOR       X9, X6
	MOVQ       48(SI), DX      // &src[6]
	MOVUPS     0(CX)(DX*1), X9
	PXOR       X9, X7
	MOVQ       56(SI), DX      // &src[7]
	MOVUPS     0(CX)(DX*1), X9
	PXOR       X9, X8
	PXOR       X0, X1
	PXOR       X0, X2
	PXOR       X0, X3
	PXOR       X0, X4
	PXOR       X0, X5
	PXOR       X0, X6
	PXOR       X0, X7
	PXOR       X0, X8
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
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     160(AX), X0
	AESENCLAST X0, X1
	AESENCLAST X0, X2
	AESENCLAST X0, X3
	AESENCLAST X0, X4
	AESENCLAST X0, X5
	AESENCLAST X0, X6
	AESENCLAST X0, X7
	AESENCLAST X0, X8
	MOVQ       (DI), DX         // &dst[0]
	MOVUPS     X1, 0(CX)(DX*1)
	LEAQ       0(CX)(DX*1), R8
	MOVQ       8(DI), DX
	MOVUPS     X2, 0(CX)(DX*1)
	LEAQ       0(CX)(DX*1), R9
	MOVQ       16(DI), DX
	MOVUPS     X3, 0(CX)(DX*1)
	LEAQ       0(CX)(DX*1), R10
	MOVQ       24(DI), DX
	MOVUPS     X4, 0(CX)(DX*1)
	LEAQ       0(CX)(DX*1), R11
	MOVQ       32(DI), DX
	MOVUPS     X5, 0(CX)(DX*1)
	LEAQ       0(CX)(DX*1), R12
	MOVQ       40(DI), DX
	MOVUPS     X6, 0(CX)(DX*1)
	LEAQ       0(CX)(DX*1), R13
	MOVQ       48(DI), DX
	MOVUPS     X7, 0(CX)(DX*1)
	LEAQ       0(CX)(DX*1), R14
	MOVQ       56(DI), DX
	MOVUPS     X8, 0(CX)(DX*1)
	LEAQ       0(CX)(DX*1), R15
	ADDQ       $16, CX // Move to next block
	JMP        loop

done:
	RET

// func aes_x8_cbc_decrypt(xk *uint32,dst,src,iv [][]byte,ln int)
TEXT ·aes_x8_cbc_decrypt(SB), NOSPLIT, $0
	MOVQ xk+0(FP), AX   // xk
	MOVQ dst+8(FP), DI  // dst
	MOVQ src+16(FP), SI // src
	MOVQ iv+24(FP), BP  // iv
	MOVQ ln+32(FP), BX  // ln
	MOVQ 0(SI), R8      // in[0]
	MOVQ 8(SI), R9     // in[1]...
	MOVQ 16(SI), R10
	MOVQ 24(SI), R11
	MOVQ 32(SI), R12
	MOVQ 40(SI), R13
	MOVQ 48(SI), R14
	MOVQ 56(SI), R15
	MOVQ $0, CX
	//MOVQ $16, CX
	SUBQ $16,BX

	//Do it backwards due to lack of registers,
	//Because we need to keep ciphertext for xoring
loop:
	CMPQ       BX,$-16
	JLE done
	CMPQ       CX, BX
	JGE        last_block
	MOVUPS     0(BX)(R8*1), X1
	MOVUPS     0(BX)(R9*1), X2
	MOVUPS     0(BX)(R10*1), X3
	MOVUPS     0(BX)(R11*1), X4
	MOVUPS     0(BX)(R12*1), X5
	MOVUPS     0(BX)(R13*1), X6
	MOVUPS     0(BX)(R14*1), X7
	MOVUPS     0(BX)(R15*1), X8
	last_block_loop:
	MOVUPS     0(AX), X0        // key
	PXOR       X0, X1
	PXOR       X0, X2
	PXOR       X0, X3
	PXOR       X0, X4
	PXOR       X0, X5
	PXOR       X0, X6
	PXOR       X0, X7
	PXOR       X0, X8
	MOVUPS     16(AX), X0
	AESDEC     X0, X1
	AESDEC     X0, X2
	AESDEC     X0, X3
	AESDEC     X0, X4
	AESDEC     X0, X5
	AESDEC     X0, X6
	AESDEC     X0, X7
	AESDEC     X0, X8
	MOVUPS     32(AX), X0
	AESDEC     X0, X1
	AESDEC     X0, X2
	AESDEC     X0, X3
	AESDEC     X0, X4
	AESDEC     X0, X5
	AESDEC     X0, X6
	AESDEC     X0, X7
	AESDEC     X0, X8
	MOVUPS     48(AX), X0
	AESDEC     X0, X1
	AESDEC     X0, X2
	AESDEC     X0, X3
	AESDEC     X0, X4
	AESDEC     X0, X5
	AESDEC     X0, X6
	AESDEC     X0, X7
	AESDEC     X0, X8
	MOVUPS     64(AX), X0
	AESDEC     X0, X1
	AESDEC     X0, X2
	AESDEC     X0, X3
	AESDEC     X0, X4
	AESDEC     X0, X5
	AESDEC     X0, X6
	AESDEC     X0, X7
	AESDEC     X0, X8
	MOVUPS     80(AX), X0
	AESDEC     X0, X1
	AESDEC     X0, X2
	AESDEC     X0, X3
	AESDEC     X0, X4
	AESDEC     X0, X5
	AESDEC     X0, X6
	AESDEC     X0, X7
	AESDEC     X0, X8
	MOVUPS     96(AX), X0
	AESDEC     X0, X1
	AESDEC     X0, X2
	AESDEC     X0, X3
	AESDEC     X0, X4
	AESDEC     X0, X5
	AESDEC     X0, X6
	AESDEC     X0, X7
	AESDEC     X0, X8
	MOVUPS     112(AX), X0
	AESDEC     X0, X1
	AESDEC     X0, X2
	AESDEC     X0, X3
	AESDEC     X0, X4
	AESDEC     X0, X5
	AESDEC     X0, X6
	AESDEC     X0, X7
	AESDEC     X0, X8
	MOVUPS     128(AX), X0
	AESDEC     X0, X1
	AESDEC     X0, X2
	AESDEC     X0, X3
	AESDEC     X0, X4
	AESDEC     X0, X5
	AESDEC     X0, X6
	AESDEC     X0, X7
	AESDEC     X0, X8
	MOVUPS     144(AX), X0
	AESDEC     X0, X1
	AESDEC     X0, X2
	AESDEC     X0, X3
	AESDEC     X0, X4
	AESDEC     X0, X5
	AESDEC     X0, X6
	AESDEC     X0, X7
	AESDEC     X0, X8
	MOVUPS     160(AX), X0
	AESDECLAST X0, X1
	AESDECLAST X0, X2
	AESDECLAST X0, X3
	AESDECLAST X0, X4
	AESDECLAST X0, X5
	AESDECLAST X0, X6
	AESDECLAST X0, X7
	AESDECLAST X0, X8
	MOVUPS -16(BX)(R8*1),X9
	PXOR X9,X1
	MOVQ 0(DI),DX
	MOVUPS X1,0(BX)(DX*1)
	MOVUPS -16(BX)(R9*1),X9
	PXOR X9,X2
	MOVQ 8(DI),DX
	MOVUPS X2,0(BX)(DX*1)
	MOVUPS -16(BX)(R10*1),X9
	PXOR X9,X3
	MOVQ 16(DI),DX
	MOVUPS X3,0(BX)(DX*1)
	MOVUPS -16(BX)(R11*1),X9
	PXOR X9,X4
	MOVQ 24(DI),DX
	MOVUPS X4,0(BX)(DX*1)
	MOVUPS -16(BX)(R12*1),X9
	PXOR X9,X5
	MOVQ 32(DI),DX
	MOVUPS X5,0(BX)(DX*1)
	MOVUPS -16(BX)(R13*1),X9
	PXOR X9,X6
	MOVQ 40(DI),DX
	MOVUPS X6,0(BX)(DX*1)
	MOVUPS -16(BX)(R14*1),X9
	PXOR X9,X7
	MOVQ 48(DI),DX
	MOVUPS X7,0(BX)(DX*1)
	MOVUPS -16(BX)(R15*1),X9
	PXOR X9,X8
	MOVQ 56(DI),DX
	MOVUPS X8,0(BX)(DX*1)

	SUBQ $16,BX //move to prev block
	JMP        loop

last_block:
//TODO cmp
	MOVUPS     0(AX), X0        // key
	MOVUPS     0(BX)(R8*1), X1
	MOVUPS     0(BX)(R9*1), X2
	MOVUPS     0(BX)(R10*1), X3
	MOVUPS     0(BX)(R11*1), X4
	MOVUPS     0(BX)(R12*1), X5
	MOVUPS     0(BX)(R13*1), X6
	MOVUPS     0(BX)(R14*1), X7
	MOVUPS     0(BX)(R15*1), X8
	MOVQ 0(BP), R8      // in[0]
	MOVQ 8(BP), R9     // in[1]...
	ADDQ $16,R8
	MOVQ 16(BP), R10
	MOVQ 24(BP), R11
	MOVQ 32(BP), R12
	MOVQ 40(BP), R13
	MOVQ 48(BP), R14
	MOVQ 56(BP), R15
	JMP last_block_loop
done:
	RET
