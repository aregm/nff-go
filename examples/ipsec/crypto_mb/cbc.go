// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package crypto_mb

//TODO split into subpackages

// This is based on crypto/cipher & co

// A MultiBlock represents an implementation of block cipher
// using a given key and acting on a several blocks ata once.
// All blocks must use the same key. It provides the capability to encrypt
// or decrypt "vectors" of individual blocks. The mode implementations
// extend that capability to streams of blocks.
type MultiBlock interface {
	// BlockSize returns the cipher's block size.
	BlockSize() int

	// VecSize return a number of blocks encrypted at once
	VecSize() int

	// DecryptMany decrypts the first block in src into dst.
	// Dst and src may point at the same memory.
	DecryptMany(dst, src [][]byte)
}

// A BlockMode represents a block cipher running in a block-based mode (CBC,
// ECB etc).
type MultiBlockMode interface {
	// BlockSize returns the mode's block size.
	BlockSize() int
	// VecSize return a number of blocks encrypted at once
	VecSize() int
	// CryptManyBlocks encrypts or decrypts a number of blocks. The length of
	// src must be a multiple of the block size. Dst and src may point to
	// the same memory.
	CryptManyBlocks(dst, src [][]byte)
}

type MultiSetIVer interface {
	SetIV(IV [][]byte)
	SetIVat(IVslice []byte, index int)
}

type multicbc struct {
	mb        MultiBlock
	blockSize int
	vecSize   int
	iv        [][]byte
	tmp       [][]byte
}

type cbcVectorEncrypter multicbc

func NewMultiCBCEncrypter(mb MultiBlock, iv [][]byte) MultiBlockMode {
	if mb.VecSize() <= 0 {
		panic("MultiBlock should have positive vector size")
	}
	if len(iv) != mb.VecSize() {
		panic("NewMultiCBCEncrypter: number of IVs is not equal to vectro size of MultiBlock")
	}
	for i := range iv {
		if len(iv[i]) != mb.BlockSize() {
			panic("NewMultiCBCEncrypter: IV length must equal block size")
		}
	}
	tmp := make([][]byte, mb.VecSize())
	for i := 0; i < mb.VecSize(); i++ {
		tmp[i] = make([]byte, mb.BlockSize())
	}
	//TODO why do we need to dup
	iv2 := make([][]byte, mb.VecSize())
	for i := 0; i < mb.VecSize(); i++ {

		iv2[i] = make([]byte, len(iv[i]))
		copy(iv2[i], iv[i])
	}
	ret := &multicbc{mb: mb, blockSize: mb.BlockSize(), vecSize: mb.VecSize(), iv: iv2, tmp: tmp}
	return (*cbcVectorEncrypter)(ret)
}

func (this *cbcVectorEncrypter) BlockSize() int {
	return this.blockSize
}

func (this *cbcVectorEncrypter) VecSize() int {
	return this.vecSize
}

func (this *cbcVectorEncrypter) CryptManyBlocks(dst, src [][]byte) {
	if len(src) != this.vecSize {
		panic("Number of sources must be equal to vecSize")
	}
	if len(src) != len(dst) {
		panic("number of inputs must equal number of outputs")
	}
	srcLen := len(src[0])
	if srcLen%this.blockSize != 0 {
		panic("Input should be full blocks")
	}
	for i := 1; i < this.vecSize; i++ {
		if len(src[i]) != srcLen {
			panic("All elements of src must have same length")
		}
	}
	for i := 0; i < this.vecSize; i++ {
		if len(dst[i]) < srcLen {
			panic("Not enough space in dst")
		}
	}
	iv := this.iv
	val, ok := this.mb.(*aes_x8)
	if ok {
		var dst1, src1, iv1 [8]*byte
		for i := 0; i < 8; i++ {
			dst1[i] = &dst[i][0]
			src1[i] = &src[i][0]
			iv1[i] = &iv[i][0]
		}
		aes_x8_cbc_encrypt(&val.enc[0], &dst1, &src1, &iv1, len(src[0]))
	} else {
	}

	//Save iv for later CryptManyBlocks calls
	for i := 0; i < this.vecSize; i++ {
		copy(this.iv[i], iv[i])
	}
}

func (this *cbcVectorEncrypter) SetIV(IV [][]byte) {
	if len(IV) != this.vecSize {
		panic("Wrong IV size")
	}
	for i := range IV {
		if len(IV[i]) != this.blockSize {
			panic("SetIV: IV length must equal block size")
		}
	}
	for i := range IV {
		copy(this.iv[i], IV[i])
	}
}

func (this *cbcVectorEncrypter) SetIVat(IVslice []byte, index int) {
	if len(IVslice) != this.blockSize {
		panic("SetIVat: IV length must equal block size")
	}
	//no check, bounds checks are automatic
	copy(this.iv[index], IVslice)
}

func xorBytes(dst, src, iv [][]byte, blockSize int) {
	if blockSize == 16 {
		for i := range dst {
			xor16(&dst[i][0], &src[i][0], &iv[i][0])
		}
	} else {
		for i := range dst {
			for j := 0; j < blockSize; j++ {
				dst[i][j] = src[i][j] ^ iv[i][j]
			}
		}
	}
}

// in cbc.s
//go:noescape
func aes_x8_cbc_encrypt(xk *uint32, dst1, src1, iv *[8]*byte, ln int)

// in cbc.s
//go:noescape
func xor16(dst, src, iv *byte)

// in cbc.s
//go:noescape
func aes_x8_cbc_decrypt(xk *uint32, dst1, src1, iv *[8]*byte, ln int)

type cbcVectorDecrypter multicbc

func NewMultiCBCDecrypter(mb MultiBlock, iv [][]byte) MultiBlockMode {
	if mb.VecSize() <= 0 {
		panic("MultiBlock should have positive vector size")
	}
	if len(iv) != mb.VecSize() {
		panic("NewMultiCBCDecrypter: number of IVs is not equal to vectro size of MultiBlock")
	}
	for i := range iv {
		if len(iv[i]) != mb.BlockSize() {
			panic("NewMultiCBCDecrypter: IV length must equal block size")
		}
	}
	tmp := make([][]byte, mb.VecSize())
	for i := 0; i < mb.VecSize(); i++ {
		tmp[i] = make([]byte, mb.BlockSize())
	}
	//TODO why do we need to dup
	iv2 := make([][]byte, mb.VecSize())
	for i := 0; i < mb.VecSize(); i++ {

		iv2[i] = make([]byte, len(iv[i]))
		copy(iv2[i], iv[i])
	}
	ret := &multicbc{mb: mb, blockSize: mb.BlockSize(), vecSize: mb.VecSize(), iv: iv2, tmp: tmp}
	return (*cbcVectorDecrypter)(ret)
}

func (this *cbcVectorDecrypter) BlockSize() int {
	return this.blockSize
}

func (this *cbcVectorDecrypter) VecSize() int {
	return this.vecSize
}

func (this *cbcVectorDecrypter) SetIV(IV [][]byte) {
	if len(IV) != this.vecSize {
		panic("Wrong IV size")
	}
	for i := range IV {
		if len(IV[i]) != this.blockSize {
			panic("SetIV: IV length must equal block size")
		}
	}
	for i := range IV {
		copy(this.iv[i], IV[i])
	}
}

func (this *cbcVectorDecrypter) SetIVat(IVslice []byte, index int) {
	if len(IVslice) != this.blockSize {
		panic("SetIVat: IV length must equal block size")
	}
	//no check, bounds checks are automatic
	copy(this.iv[index], IVslice)
}

func (this *cbcVectorDecrypter) CryptManyBlocks(dst, src [][]byte) {
	if len(src) != this.vecSize {
		panic("Number of sources must be equal to vecSize")
	}
	if len(src) != len(dst) {
		panic("number of inputs must equal number of outputs")
	}
	srcLen := len(src[0])
	if srcLen%this.blockSize != 0 {
		panic("Input should be full blocks")
	}
	for i := 1; i < this.vecSize; i++ {
		if len(src[i]) != srcLen {
			panic("All elements of src must have same length")
		}
	}
	for i := 0; i < this.vecSize; i++ {
		if len(dst[i]) < srcLen {
			panic("Not enough space in dst")
		}
	}
	iv := this.iv
	val, ok := this.mb.(*aes_x8)
	if ok {
		var dst1, src1, iv1 [8]*byte
		for i := 0; i < 8; i++ {
			dst1[i] = &dst[i][0]
			src1[i] = &src[i][0]
			iv1[i] = &iv[i][0]
		}
		aes_x8_cbc_decrypt(&val.dec[0], &dst1, &src1, &iv1, len(src[0]))
	} else {
		panic("Not implemented yet")
	}

	//Save iv for later CryptManyBlocks calls
	for i := 0; i < this.vecSize; i++ {
		copy(this.iv[i], iv[i])
	}
}
