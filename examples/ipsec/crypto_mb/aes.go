// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package crypto_mb

//TODO check cpuid

type aes_x8 struct {
	blockSize int
	enc       []uint32
	dec       []uint32
}

func (this *aes_x8) BlockSize() int {
	return this.blockSize
}

func (this *aes_x8) VecSize() int {
	return 8
}

//TODO accept number of blocks
func NewAESMultiBlock(key []byte) MultiBlock {
	if len(key) != 16 {
		// TODO return error?
		panic("For now only 16-byte keys are supported")
	}
	n := len(key) + 28
	rounds := 10
	c := aes_x8{len(key), make([]uint32, n), make([]uint32, n)}
	expandKeyAsm(rounds, &key[0], &c.enc[0], &c.dec[0])
	return &c
}

// in aes.s
//go:noescape
func encrypt8BlocksAsm(xk *uint32, dst, src [][]byte)

func (this *aes_x8) DecryptMany(dst, src [][]byte) {
	panic("Not implemented yet")
}
