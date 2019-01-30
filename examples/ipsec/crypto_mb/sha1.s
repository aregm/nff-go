// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

//TODO check cpuid

// AX has a pointer to area where w's are stored
#define ROUND_0_TO_15(a,b,c,d,e,t,f,index,k_const) \
      VPADDD  k_const,e,e  ; \
      VPADDD  (32*index)(AX),e,e ;  \
      VPSRLD  $(32-5),a,f ; \
      VPSLLD  $5,a,t ; \
      VPOR    f,t,t ; \
      VPADDD  t,e,e ; \
      VPXOR   d,c,f ; \
      VPAND   b,f,f ; \
      VPXOR   d,f,f ; \
      VPSRLD  $2,b,t ; \
      VPSLLD  $30,b,b ; \
      VPOR    t,b,b ; \
      VPADDD  f,e,e


#define ROUND_16_TO_19(a,b,c,d,e,t,f,index,k_const,w14,w15,w16) \
      VPADDD  k_const,e,e  ; \
      VMOVDQU (32*((index-14)&15))(AX),w14 ; \
      VPXOR w14,w16,w16 ; \
      VPXOR (32*((index-8)&15))(AX),w16,w16 ; \
      VPXOR (32*((index-3)&15))(AX),w16,w16 ; \
      VPSRLD $31,w16,f ; \
      VPSLLD $1,w16,w16 ; \
      VPOR   w16,f,f  ; \ // rotate w here
      VMOVDQU f,(32*((index-0)&15))(AX) ; \
      VPADDD f,e,e ; \
      VPSRLD $(32-5),a,f ; \
      VPSLLD $5,a,t ; \
      VPOR   f,t,t ; \
      VPADDD t,e,e ; \
      VPXOR d,c,f ; \
      VPAND b,f,f ; \
      VPXOR d,f,f ; \
      VPSRLD $2,b,t ; \
      VPSLLD $30,b,b ; \
      VPOR   t,b,b ; \
      VPADDD f,e,e


#define ROUND_20_TO_39(a,b,c,d,e,t,f,index,k_const,w14,w15,w16) \
      VPADDD  k_const,e,e  ; \
      VMOVDQU (32*((index-14)&15))(AX),w14 ; \
      VPXOR w14,w16,w16 ; \
      VPXOR (32*((index-8)&15))(AX),w16,w16 ; \
      VPXOR (32*((index-3)&15))(AX),w16,w16 ; \
      VPSRLD $31,w16,f ; \
      VPSLLD $1,w16,w16 ; \
      VPOR   w16,f,f  ; \ // rotate w here
      VMOVDQU f,(32*((index-0)&15))(AX) ; \
      VPADDD f,e,e ; \
      VPSRLD $(32-5),a,f ; \
      VPSLLD $5,a,t ; \
      VPOR   f,t,t ; \
      VPADDD t,e,e ; \
      VPXOR c,d,f ; \
      VPXOR b,f,f ; \
      VPSRLD $2,b,t ; \
      VPSLLD $30,b,b ; \
      VPOR   t,b,b ; \
      VPADDD f,e,e


#define ROUND_40_TO_59(a,b,c,d,e,t,f,index,k_const,w14,w15,w16) \
      VPADDD  k_const,e,e  ; \
      VMOVDQU (32*((index-14)&15))(AX),w14 ; \
      VPXOR w14,w16,w16 ; \
      VPXOR (32*((index-8)&15))(AX),w16,w16 ; \
      VPXOR (32*((index-3)&15))(AX),w16,w16 ; \
      VPSRLD $31,w16,f ; \
      VPSLLD $1,w16,w16 ; \
      VPOR   w16,f,f  ; \ // rotate w here
      VMOVDQU f,(32*((index-0)&15))(AX) ; \
      VPADDD f,e,e ; \
      VPSRLD $(32-5),a,f ; \
      VPSLLD $5,a,t ; \
      VPOR   f,t,t ; \
      VPADDD t,e,e ; \
      VPOR   c,b,f ; \
      VPAND  c,b,t ; \
      VPAND  d,f,f ; \
      VPOR   t,f,f ; \
      VPSRLD $2,b,t ; \
      VPSLLD $30,b,b ; \
      VPOR   t,b,b ; \
      VPADDD f,e,e


#define ROUND_60_TO_79(a,b,c,d,e,t,f,index,k_const,w14,w15,w16) \
      VPADDD  k_const,e,e  ; \
      VMOVDQU (32*((index-14)&15))(AX),w14 ; \
      VPXOR w14,w16,w16 ; \
      VPXOR (32*((index-8)&15))(AX),w16,w16 ; \
      VPXOR (32*((index-3)&15))(AX),w16,w16 ; \
      VPSRLD $31,w16,f ; \
      VPSLLD $1,w16,w16 ; \
      VPOR   w16,f,f  ; \ // rotate w here
      VMOVDQU f,(32*((index-0)&15))(AX) ; \
      VPADDD f,e,e ; \
      VPSRLD $(32-5),a,f ; \
      VPSLLD $5,a,t ; \
      VPOR   f,t,t ; \
      VPADDD t,e,e ; \
      VPXOR c,d,f ; \
      VPXOR b,f,f ; \
      VPSRLD $2,b,t ; \
      VPSLLD $30,b,b ; \
      VPOR   t,b,b ; \
      VPADDD f,e,e




//func multiblock(d *digest8sha1, p *[8]*byte, ln int)
TEXT ·multiblock(SB), NOSPLIT, $0
	MOVQ   d+0(FP), DX // digest
	MOVQ   p+8(FP), SI // Input array
	MOVQ   ln+16(FP), DI // len
	MOVQ   (SI),R8 // R8-15 inputs
	MOVQ   8(SI),R9
	MOVQ   16(SI),R10
	MOVQ   24(SI),R11
	MOVQ   32(SI),R12
	MOVQ   40(SI),R13
	MOVQ   48(SI),R14
	MOVQ   56(SI),R15
	MOVQ   (DX),AX  // pointer to scratch area
	VMOVDQU   8(DX),Y11    // Y11 = vec of A
	VMOVDQU   40(DX),Y12   // Y12 = vec of B
	VMOVDQU   72(DX),Y13   // Y13 = vec of C
	VMOVDQU   104(DX),Y14  // Y14 = vec of D
	VMOVDQU   136(DX),Y15  // Y15 = vec of E
	XORQ   CX,CX // i = 0
loop:
	CMPQ   CX,DI // i < len
	JGE done
	MOVQ    $BSWAP_SHUFB_CTL<>(SB), BX
	VMOVDQU (BX), Y10 // mask for byte swapping
	VMOVDQU  0(CX)(R8*1),Y0// load first half of a block
	VMOVDQU  0(CX)(R9*1),Y1
	VMOVDQU  0(CX)(R10*1),Y2
	VMOVDQU  0(CX)(R11*1),Y3
	VMOVDQU  0(CX)(R12*1),Y4
	VMOVDQU  0(CX)(R13*1),Y5
	VMOVDQU  0(CX)(R14*1),Y6
	VMOVDQU  0(CX)(R15*1),Y7 // transpone it using Y8 and Y9 as temporaries, aa..,bb..,cc.. -> abc..,abc..
	BYTE $0xC5; BYTE $0x7C; BYTE $0xC6; BYTE $0xC1; BYTE $0x44       	// vshufps $0x44,%ymm1,%ymm0,%ymm8
	BYTE $0xC5; BYTE $0xFC; BYTE $0xC6; BYTE $0xC1; BYTE $0xEE       	// vshufps $0xee,%ymm1,%ymm0,%ymm0
	BYTE $0xC5; BYTE $0x6C; BYTE $0xC6; BYTE $0xCB; BYTE $0x44       	// vshufps $0x44,%ymm3,%ymm2,%ymm9
	BYTE $0xC5; BYTE $0xEC; BYTE $0xC6; BYTE $0xD3; BYTE $0xEE       	// vshufps $0xee,%ymm3,%ymm2,%ymm2
	BYTE $0xC4; BYTE $0xC1; BYTE $0x3C; BYTE $0xC6; BYTE $0xD9; BYTE $0xDD  // vshufps $0xdd,%ymm9,%ymm8,%ymm3
	BYTE $0xC5; BYTE $0xFC; BYTE $0xC6; BYTE $0xCA; BYTE $0x88       	// vshufps $0x88,%ymm2,%ymm0,%ymm1
	BYTE $0xC5; BYTE $0xFC; BYTE $0xC6; BYTE $0xC2; BYTE $0xDD       	// vshufps $0xdd,%ymm2,%ymm0,%ymm0
	BYTE $0xC4; BYTE $0x41; BYTE $0x3C; BYTE $0xC6; BYTE $0xC1; BYTE $0x88  // vshufps $0x88,%ymm9,%ymm8,%ymm8
	BYTE $0xC5; BYTE $0xDC; BYTE $0xC6; BYTE $0xD5; BYTE $0x44       	// vshufps $0x44,%ymm5,%ymm4,%ymm2
	BYTE $0xC5; BYTE $0xDC; BYTE $0xC6; BYTE $0xE5; BYTE $0xEE       	// vshufps $0xee,%ymm5,%ymm4,%ymm4
	BYTE $0xC5; BYTE $0x4C; BYTE $0xC6; BYTE $0xCF; BYTE $0x44       	// vshufps $0x44,%ymm7,%ymm6,%ymm9
	BYTE $0xC5; BYTE $0xCC; BYTE $0xC6; BYTE $0xF7; BYTE $0xEE       	// vshufps $0xee,%ymm7,%ymm6,%ymm6
	BYTE $0xC4; BYTE $0xC1; BYTE $0x6C; BYTE $0xC6; BYTE $0xF9; BYTE $0xDD  // vshufps $0xdd,%ymm9,%ymm2,%ymm7
	BYTE $0xC5; BYTE $0xDC; BYTE $0xC6; BYTE $0xEE; BYTE $0x88       	// vshufps $0x88,%ymm6,%ymm4,%ymm5
	BYTE $0xC5; BYTE $0xDC; BYTE $0xC6; BYTE $0xE6; BYTE $0xDD       	// vshufps $0xdd,%ymm6,%ymm4,%ymm4
	BYTE $0xC4; BYTE $0x41; BYTE $0x6C; BYTE $0xC6; BYTE $0xC9; BYTE $0x88  // vshufps $0x88,%ymm9,%ymm2,%ymm9
	VPERM2F128 $0x13, Y1, Y5, Y6
	VPERM2F128 $0x02, Y1, Y5, Y2
	VPERM2F128 $0x13, Y3, Y7, Y5
	VPERM2F128 $0x02, Y3, Y7, Y1
	VPERM2F128 $0x13, Y0, Y4, Y7
	VPERM2F128 $0x02, Y0, Y4, Y3
	VPERM2F128 $0x13, Y8, Y9, Y4
	VPERM2F128 $0x02, Y8, Y9, Y0
	VPSHUFB    Y10, Y0, Y0 // get w's (endianness swapped p's)
	VMOVDQU    Y0,(AX) // Store it onto stack
	VPSHUFB    Y10, Y1, Y1
	VMOVDQU    Y1,32(AX)
	VPSHUFB    Y10, Y2, Y2
	VMOVDQU    Y2,64(AX)
	VPSHUFB    Y10, Y3, Y3
	VMOVDQU    Y3,96(AX)
	VPSHUFB    Y10, Y4, Y4
	VMOVDQU    Y4,128(AX)
	VPSHUFB    Y10, Y5, Y5
	VMOVDQU    Y5,160(AX)
	VPSHUFB    Y10, Y6, Y6
	VMOVDQU    Y6,192(AX)
	VPSHUFB    Y10, Y7, Y7
	VMOVDQU    Y7,224(AX)
	VMOVDQU  32(CX)(R8*1),Y0  // Do the same for second half of input block
	VMOVDQU  32(CX)(R9*1),Y1
	VMOVDQU  32(CX)(R10*1),Y2
	VMOVDQU  32(CX)(R11*1),Y3
	VMOVDQU  32(CX)(R12*1),Y4
	VMOVDQU  32(CX)(R13*1),Y5
	VMOVDQU  32(CX)(R14*1),Y6
	VMOVDQU  32(CX)(R15*1),Y7
	BYTE $0xC5; BYTE $0x7C; BYTE $0xC6; BYTE $0xC1; BYTE $0x44       	// vshufps $0x44,%ymm1,%ymm0,%ymm8
	BYTE $0xC5; BYTE $0xFC; BYTE $0xC6; BYTE $0xC1; BYTE $0xEE       	// vshufps $0xee,%ymm1,%ymm0,%ymm0
	BYTE $0xC5; BYTE $0x6C; BYTE $0xC6; BYTE $0xCB; BYTE $0x44       	// vshufps $0x44,%ymm3,%ymm2,%ymm9
	BYTE $0xC5; BYTE $0xEC; BYTE $0xC6; BYTE $0xD3; BYTE $0xEE       	// vshufps $0xee,%ymm3,%ymm2,%ymm2
	BYTE $0xC4; BYTE $0xC1; BYTE $0x3C; BYTE $0xC6; BYTE $0xD9; BYTE $0xDD  // vshufps $0xdd,%ymm9,%ymm8,%ymm3
	BYTE $0xC5; BYTE $0xFC; BYTE $0xC6; BYTE $0xCA; BYTE $0x88       	// vshufps $0x88,%ymm2,%ymm0,%ymm1
	BYTE $0xC5; BYTE $0xFC; BYTE $0xC6; BYTE $0xC2; BYTE $0xDD       	// vshufps $0xdd,%ymm2,%ymm0,%ymm0
	BYTE $0xC4; BYTE $0x41; BYTE $0x3C; BYTE $0xC6; BYTE $0xC1; BYTE $0x88  // vshufps $0x88,%ymm9,%ymm8,%ymm8
	BYTE $0xC5; BYTE $0xDC; BYTE $0xC6; BYTE $0xD5; BYTE $0x44       	// vshufps $0x44,%ymm5,%ymm4,%ymm2
	BYTE $0xC5; BYTE $0xDC; BYTE $0xC6; BYTE $0xE5; BYTE $0xEE       	// vshufps $0xee,%ymm5,%ymm4,%ymm4
	BYTE $0xC5; BYTE $0x4C; BYTE $0xC6; BYTE $0xCF; BYTE $0x44       	// vshufps $0x44,%ymm7,%ymm6,%ymm9
	BYTE $0xC5; BYTE $0xCC; BYTE $0xC6; BYTE $0xF7; BYTE $0xEE       	// vshufps $0xee,%ymm7,%ymm6,%ymm6
	BYTE $0xC4; BYTE $0xC1; BYTE $0x6C; BYTE $0xC6; BYTE $0xF9; BYTE $0xDD  // vshufps $0xdd,%ymm9,%ymm2,%ymm7
	BYTE $0xC5; BYTE $0xDC; BYTE $0xC6; BYTE $0xEE; BYTE $0x88       	// vshufps $0x88,%ymm6,%ymm4,%ymm5
	BYTE $0xC5; BYTE $0xDC; BYTE $0xC6; BYTE $0xE6; BYTE $0xDD       	// vshufps $0xdd,%ymm6,%ymm4,%ymm4
	BYTE $0xC4; BYTE $0x41; BYTE $0x6C; BYTE $0xC6; BYTE $0xC9; BYTE $0x88  // vshufps $0x88,%ymm9,%ymm2,%ymm9
	VPERM2F128 $0x13, Y1, Y5, Y6
	VPERM2F128 $0x02, Y1, Y5, Y2
	VPERM2F128 $0x13, Y3, Y7, Y5
	VPERM2F128 $0x02, Y3, Y7, Y1
	VPERM2F128 $0x13, Y0, Y4, Y7
	VPERM2F128 $0x02, Y0, Y4, Y3
	VPERM2F128 $0x13, Y8, Y9, Y4
	VPERM2F128 $0x02, Y8, Y9, Y0
	VPSHUFB    Y10, Y0, Y0
	VMOVDQU    Y0,256(AX)
	VPSHUFB    Y10, Y1, Y1
	VMOVDQU    Y1,288(AX)
	VPSHUFB    Y10, Y2, Y2
	VMOVDQU    Y2,320(AX)
	VPSHUFB    Y10, Y3, Y3
	VMOVDQU    Y3,352(AX)
	VPSHUFB    Y10, Y4, Y4
	VMOVDQU    Y4,384(AX)
	VPSHUFB    Y10, Y5, Y5
	VMOVDQU    Y5,416(AX)
	VPSHUFB    Y10, Y6, Y6
	VMOVDQU    Y6,448(AX)
	VPSHUFB    Y10, Y7, Y7
	VMOVDQU    Y7,480(AX)
	VMOVDQU   Y11,Y0  // make a copy of A,B,C,D,E
	VMOVDQU   Y12,Y1
	VMOVDQU   Y13,Y2
	VMOVDQU   Y14,Y3
	VMOVDQU   Y15,Y4
	MOVQ    $K_XMM_AR<>(SB), BX
	VMOVDQU (BX), Y10 // contants for rounds 0-19
	ROUND_0_TO_15(Y0,Y1,Y2,Y3,Y4,Y5,Y6,0,Y10)
	ROUND_0_TO_15(Y4,Y0,Y1,Y2,Y3,Y5,Y6,1,Y10)
	ROUND_0_TO_15(Y3,Y4,Y0,Y1,Y2,Y5,Y6,2,Y10)
	ROUND_0_TO_15(Y2,Y3,Y4,Y0,Y1,Y5,Y6,3,Y10)
	ROUND_0_TO_15(Y1,Y2,Y3,Y4,Y0,Y5,Y6,4,Y10)
	ROUND_0_TO_15(Y0,Y1,Y2,Y3,Y4,Y5,Y6,5,Y10)
	ROUND_0_TO_15(Y4,Y0,Y1,Y2,Y3,Y5,Y6,6,Y10)
	ROUND_0_TO_15(Y3,Y4,Y0,Y1,Y2,Y5,Y6,7,Y10)
	ROUND_0_TO_15(Y2,Y3,Y4,Y0,Y1,Y5,Y6,8,Y10)
	ROUND_0_TO_15(Y1,Y2,Y3,Y4,Y0,Y5,Y6,9,Y10)
	ROUND_0_TO_15(Y0,Y1,Y2,Y3,Y4,Y5,Y6,10,Y10)
	ROUND_0_TO_15(Y4,Y0,Y1,Y2,Y3,Y5,Y6,11,Y10)
	ROUND_0_TO_15(Y3,Y4,Y0,Y1,Y2,Y5,Y6,12,Y10)
	ROUND_0_TO_15(Y2,Y3,Y4,Y0,Y1,Y5,Y6,13,Y10)
	ROUND_0_TO_15(Y1,Y2,Y3,Y4,Y0,Y5,Y6,14,Y10)
	ROUND_0_TO_15(Y0,Y1,Y2,Y3,Y4,Y5,Y6,15,Y10)
	VMOVDQU (AX),Y9
	VMOVDQU 32(AX),Y8
	ROUND_16_TO_19(Y4,Y0,Y1,Y2,Y3,Y5,Y6,16,Y10,Y7,Y8,Y9)
	ROUND_16_TO_19(Y3,Y4,Y0,Y1,Y2,Y5,Y6,17,Y10,Y9,Y7,Y8)
	ROUND_16_TO_19(Y2,Y3,Y4,Y0,Y1,Y5,Y6,18,Y10,Y8,Y9,Y7)
	ROUND_16_TO_19(Y1,Y2,Y3,Y4,Y0,Y5,Y6,19,Y10,Y7,Y8,Y9)
	VMOVDQU 32(BX), Y10 // contants for rounds 20-39
	ROUND_20_TO_39(Y0,Y1,Y2,Y3,Y4,Y5,Y6,20,Y10,Y9,Y7,Y8)
	ROUND_20_TO_39(Y4,Y0,Y1,Y2,Y3,Y5,Y6,21,Y10,Y8,Y9,Y7)
	ROUND_20_TO_39(Y3,Y4,Y0,Y1,Y2,Y5,Y6,22,Y10,Y7,Y8,Y9)
	ROUND_20_TO_39(Y2,Y3,Y4,Y0,Y1,Y5,Y6,23,Y10,Y9,Y7,Y8)
	ROUND_20_TO_39(Y1,Y2,Y3,Y4,Y0,Y5,Y6,24,Y10,Y8,Y9,Y7)
	ROUND_20_TO_39(Y0,Y1,Y2,Y3,Y4,Y5,Y6,25,Y10,Y7,Y8,Y9)
	ROUND_20_TO_39(Y4,Y0,Y1,Y2,Y3,Y5,Y6,26,Y10,Y9,Y7,Y8)
	ROUND_20_TO_39(Y3,Y4,Y0,Y1,Y2,Y5,Y6,27,Y10,Y8,Y9,Y7)
	ROUND_20_TO_39(Y2,Y3,Y4,Y0,Y1,Y5,Y6,28,Y10,Y7,Y8,Y9)
	ROUND_20_TO_39(Y1,Y2,Y3,Y4,Y0,Y5,Y6,29,Y10,Y9,Y7,Y8)
	ROUND_20_TO_39(Y0,Y1,Y2,Y3,Y4,Y5,Y6,30,Y10,Y8,Y9,Y7)
	ROUND_20_TO_39(Y4,Y0,Y1,Y2,Y3,Y5,Y6,31,Y10,Y7,Y8,Y9)
	ROUND_20_TO_39(Y3,Y4,Y0,Y1,Y2,Y5,Y6,32,Y10,Y9,Y7,Y8)
	ROUND_20_TO_39(Y2,Y3,Y4,Y0,Y1,Y5,Y6,33,Y10,Y8,Y9,Y7)
	ROUND_20_TO_39(Y1,Y2,Y3,Y4,Y0,Y5,Y6,34,Y10,Y7,Y8,Y9)
	ROUND_20_TO_39(Y0,Y1,Y2,Y3,Y4,Y5,Y6,35,Y10,Y9,Y7,Y8)
	ROUND_20_TO_39(Y4,Y0,Y1,Y2,Y3,Y5,Y6,36,Y10,Y8,Y9,Y7)
	ROUND_20_TO_39(Y3,Y4,Y0,Y1,Y2,Y5,Y6,37,Y10,Y7,Y8,Y9)
	ROUND_20_TO_39(Y2,Y3,Y4,Y0,Y1,Y5,Y6,38,Y10,Y9,Y7,Y8)
	ROUND_20_TO_39(Y1,Y2,Y3,Y4,Y0,Y5,Y6,39,Y10,Y8,Y9,Y7)
	VMOVDQU 64(BX), Y10 // contants for rounds 40-59
	ROUND_40_TO_59(Y0,Y1,Y2,Y3,Y4,Y5,Y6,40,Y10,Y7,Y8,Y9)
	ROUND_40_TO_59(Y4,Y0,Y1,Y2,Y3,Y5,Y6,41,Y10,Y9,Y7,Y8)
	ROUND_40_TO_59(Y3,Y4,Y0,Y1,Y2,Y5,Y6,42,Y10,Y8,Y9,Y7)
	ROUND_40_TO_59(Y2,Y3,Y4,Y0,Y1,Y5,Y6,43,Y10,Y7,Y8,Y9)
	ROUND_40_TO_59(Y1,Y2,Y3,Y4,Y0,Y5,Y6,44,Y10,Y9,Y7,Y8)
	ROUND_40_TO_59(Y0,Y1,Y2,Y3,Y4,Y5,Y6,45,Y10,Y8,Y9,Y7)
	ROUND_40_TO_59(Y4,Y0,Y1,Y2,Y3,Y5,Y6,46,Y10,Y7,Y8,Y9)
	ROUND_40_TO_59(Y3,Y4,Y0,Y1,Y2,Y5,Y6,47,Y10,Y9,Y7,Y8)
	ROUND_40_TO_59(Y2,Y3,Y4,Y0,Y1,Y5,Y6,48,Y10,Y8,Y9,Y7)
	ROUND_40_TO_59(Y1,Y2,Y3,Y4,Y0,Y5,Y6,49,Y10,Y7,Y8,Y9)
	ROUND_40_TO_59(Y0,Y1,Y2,Y3,Y4,Y5,Y6,50,Y10,Y9,Y7,Y8)
	ROUND_40_TO_59(Y4,Y0,Y1,Y2,Y3,Y5,Y6,51,Y10,Y8,Y9,Y7)
	ROUND_40_TO_59(Y3,Y4,Y0,Y1,Y2,Y5,Y6,52,Y10,Y7,Y8,Y9)
	ROUND_40_TO_59(Y2,Y3,Y4,Y0,Y1,Y5,Y6,53,Y10,Y9,Y7,Y8)
	ROUND_40_TO_59(Y1,Y2,Y3,Y4,Y0,Y5,Y6,54,Y10,Y8,Y9,Y7)
	ROUND_40_TO_59(Y0,Y1,Y2,Y3,Y4,Y5,Y6,55,Y10,Y7,Y8,Y9)
	ROUND_40_TO_59(Y4,Y0,Y1,Y2,Y3,Y5,Y6,56,Y10,Y9,Y7,Y8)
	ROUND_40_TO_59(Y3,Y4,Y0,Y1,Y2,Y5,Y6,57,Y10,Y8,Y9,Y7)
	ROUND_40_TO_59(Y2,Y3,Y4,Y0,Y1,Y5,Y6,58,Y10,Y7,Y8,Y9)
	ROUND_40_TO_59(Y1,Y2,Y3,Y4,Y0,Y5,Y6,59,Y10,Y9,Y7,Y8)
	VMOVDQU 96(BX), Y10 // contants for rounds 60-79
	ROUND_60_TO_79(Y0,Y1,Y2,Y3,Y4,Y5,Y6,60,Y10,Y8,Y9,Y7)
	ROUND_60_TO_79(Y4,Y0,Y1,Y2,Y3,Y5,Y6,61,Y10,Y7,Y8,Y9)
	ROUND_60_TO_79(Y3,Y4,Y0,Y1,Y2,Y5,Y6,62,Y10,Y9,Y7,Y8)
	ROUND_60_TO_79(Y2,Y3,Y4,Y0,Y1,Y5,Y6,63,Y10,Y8,Y9,Y7)
	ROUND_60_TO_79(Y1,Y2,Y3,Y4,Y0,Y5,Y6,64,Y10,Y7,Y8,Y9)
	ROUND_60_TO_79(Y0,Y1,Y2,Y3,Y4,Y5,Y6,65,Y10,Y9,Y7,Y8)
	ROUND_60_TO_79(Y4,Y0,Y1,Y2,Y3,Y5,Y6,66,Y10,Y8,Y9,Y7)
	ROUND_60_TO_79(Y3,Y4,Y0,Y1,Y2,Y5,Y6,67,Y10,Y7,Y8,Y9)
	ROUND_60_TO_79(Y2,Y3,Y4,Y0,Y1,Y5,Y6,68,Y10,Y9,Y7,Y8)
	ROUND_60_TO_79(Y1,Y2,Y3,Y4,Y0,Y5,Y6,69,Y10,Y8,Y9,Y7)
	ROUND_60_TO_79(Y0,Y1,Y2,Y3,Y4,Y5,Y6,70,Y10,Y7,Y8,Y9)
	ROUND_60_TO_79(Y4,Y0,Y1,Y2,Y3,Y5,Y6,71,Y10,Y9,Y7,Y8)
	ROUND_60_TO_79(Y3,Y4,Y0,Y1,Y2,Y5,Y6,72,Y10,Y8,Y9,Y7)
	ROUND_60_TO_79(Y2,Y3,Y4,Y0,Y1,Y5,Y6,73,Y10,Y7,Y8,Y9)
	ROUND_60_TO_79(Y1,Y2,Y3,Y4,Y0,Y5,Y6,74,Y10,Y9,Y7,Y8)
	ROUND_60_TO_79(Y0,Y1,Y2,Y3,Y4,Y5,Y6,75,Y10,Y8,Y9,Y7)
	ROUND_60_TO_79(Y4,Y0,Y1,Y2,Y3,Y5,Y6,76,Y10,Y7,Y8,Y9)
	ROUND_60_TO_79(Y3,Y4,Y0,Y1,Y2,Y5,Y6,77,Y10,Y9,Y7,Y8)
	ROUND_60_TO_79(Y2,Y3,Y4,Y0,Y1,Y5,Y6,78,Y10,Y8,Y9,Y7)
	ROUND_60_TO_79(Y1,Y2,Y3,Y4,Y0,Y5,Y6,79,Y10,Y7,Y8,Y9)
	VPADDD Y11,Y0,Y0
	VPADDD Y12,Y1,Y1
	VPADDD Y13,Y2,Y2
	VPADDD Y14,Y3,Y3
	VPADDD Y15,Y4,Y4
	VMOVDQU   Y0,Y11  // make a copy of A,B,C,D,E
	VMOVDQU   Y1,Y12
	VMOVDQU   Y2,Y13
	VMOVDQU   Y3,Y14
	VMOVDQU   Y4,Y15
	ADDQ   $64,CX // i+=64
	JMP loop
done:
	VMOVDQU Y0,8(DX)
	VMOVDQU Y1,40(DX)
	VMOVDQU Y2,72(DX)
	VMOVDQU Y3,104(DX)
	VMOVDQU Y4,136(DX)
	VZEROUPPER
	RET

DATA K_XMM_AR<>+0x00(SB)/4,$0x5a827999
DATA K_XMM_AR<>+0x04(SB)/4,$0x5a827999
DATA K_XMM_AR<>+0x08(SB)/4,$0x5a827999
DATA K_XMM_AR<>+0x0c(SB)/4,$0x5a827999
DATA K_XMM_AR<>+0x10(SB)/4,$0x5a827999
DATA K_XMM_AR<>+0x14(SB)/4,$0x5a827999
DATA K_XMM_AR<>+0x18(SB)/4,$0x5a827999
DATA K_XMM_AR<>+0x1c(SB)/4,$0x5a827999
DATA K_XMM_AR<>+0x20(SB)/4,$0x6ed9eba1
DATA K_XMM_AR<>+0x24(SB)/4,$0x6ed9eba1
DATA K_XMM_AR<>+0x28(SB)/4,$0x6ed9eba1
DATA K_XMM_AR<>+0x2c(SB)/4,$0x6ed9eba1
DATA K_XMM_AR<>+0x30(SB)/4,$0x6ed9eba1
DATA K_XMM_AR<>+0x34(SB)/4,$0x6ed9eba1
DATA K_XMM_AR<>+0x38(SB)/4,$0x6ed9eba1
DATA K_XMM_AR<>+0x3c(SB)/4,$0x6ed9eba1
DATA K_XMM_AR<>+0x40(SB)/4,$0x8f1bbcdc
DATA K_XMM_AR<>+0x44(SB)/4,$0x8f1bbcdc
DATA K_XMM_AR<>+0x48(SB)/4,$0x8f1bbcdc
DATA K_XMM_AR<>+0x4c(SB)/4,$0x8f1bbcdc
DATA K_XMM_AR<>+0x50(SB)/4,$0x8f1bbcdc
DATA K_XMM_AR<>+0x54(SB)/4,$0x8f1bbcdc
DATA K_XMM_AR<>+0x58(SB)/4,$0x8f1bbcdc
DATA K_XMM_AR<>+0x5c(SB)/4,$0x8f1bbcdc
DATA K_XMM_AR<>+0x60(SB)/4,$0xca62c1d6
DATA K_XMM_AR<>+0x64(SB)/4,$0xca62c1d6
DATA K_XMM_AR<>+0x68(SB)/4,$0xca62c1d6
DATA K_XMM_AR<>+0x6c(SB)/4,$0xca62c1d6
DATA K_XMM_AR<>+0x70(SB)/4,$0xca62c1d6
DATA K_XMM_AR<>+0x74(SB)/4,$0xca62c1d6
DATA K_XMM_AR<>+0x78(SB)/4,$0xca62c1d6
DATA K_XMM_AR<>+0x7c(SB)/4,$0xca62c1d6
GLOBL K_XMM_AR<>(SB),RODATA,$128

DATA BSWAP_SHUFB_CTL<>+0x00(SB)/4,$0x00010203
DATA BSWAP_SHUFB_CTL<>+0x04(SB)/4,$0x04050607
DATA BSWAP_SHUFB_CTL<>+0x08(SB)/4,$0x08090a0b
DATA BSWAP_SHUFB_CTL<>+0x0c(SB)/4,$0x0c0d0e0f
DATA BSWAP_SHUFB_CTL<>+0x10(SB)/4,$0x00010203
DATA BSWAP_SHUFB_CTL<>+0x14(SB)/4,$0x04050607
DATA BSWAP_SHUFB_CTL<>+0x18(SB)/4,$0x08090a0b
DATA BSWAP_SHUFB_CTL<>+0x1c(SB)/4,$0x0c0d0e0f
GLOBL BSWAP_SHUFB_CTL<>(SB),RODATA,$32
