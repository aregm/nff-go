// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package crypto_mb

//TODO check cpuid

// based on crypto/sha1 and hash

// The size of a SHA1 checksum in bytes.
const SizeSHA1 = 20

// The blocksize of SHA1 in bytes.
const BlockSizeSHA1 = 64

const vecSize = 8

const (
	SHA1chunk = 64
	SHA1init0 = 0x67452301
	SHA1init1 = 0xEFCDAB89
	SHA1init2 = 0x98BADCFE
	SHA1init3 = 0x10325476
	SHA1init4 = 0xC3D2E1F0
)

type digest8sha1 struct {
	scratch *[BlockSizeSHA1 * vecSize]byte
	h       [5][vecSize]uint32 //transponed order
	x       [vecSize][SHA1chunk]byte
	nx      int
	len     uint64
	tmp     [][]byte
}

// MultiHash is the common interface implemented by all hash functions.
type MultiHash interface {
	// Write adds more data to the running hash.
	Write(p [][]byte) (n int) // TODO []io.writer?

	// Sum appends the current hash to b and returns the resulting slice.
	// It does not change the underlying hash state.
	Sum(b [][]byte) [][]byte

	// Reset resets the MultiHash to its initial state.
	Reset()

	// Size returns the number of bytes Sum will return.
	Size() int

	// VecSize returns numer of blocks summed in parallel
	VecSize() int

	// BlockSize returns the hash's underlying block size.
	// The Write method must be able to accept any amount
	// of data, but it may operate more efficiently if all writes
	// are a multiple of the block size.
	BlockSize() int
}

func (d *digest8sha1) Reset() {
	for i := 0; i < d.VecSize(); i++ {
		d.h[0][i] = SHA1init0
		d.h[1][i] = SHA1init1
		d.h[2][i] = SHA1init2
		d.h[3][i] = SHA1init3
		d.h[4][i] = SHA1init4
	}
	d.nx = 0
	d.len = 0
}

func (d *digest8sha1) BlockSize() int { return BlockSizeSHA1 }
func (d *digest8sha1) Size() int      { return SizeSHA1 }
func (d *digest8sha1) VecSize() int   { return vecSize }

//TODO rename to sha1new or move to separate package
// New returns a new MultiHash computing the SHA1 checksum.
func New() MultiHash {
	d := new(digest8sha1)
	var scratchSpace [BlockSizeSHA1 * vecSize]byte
	d.scratch = &scratchSpace
	d.tmp = make([][]byte, vecSize)
	for i := range d.tmp {
		d.tmp[i] = make([]byte, BlockSizeSHA1)
	}
	d.Reset()
	return d

}
func (d *digest8sha1) Write(param [][]byte) (nn int) {
	//TODO error?
	if len(param) != d.VecSize() {
		panic("Expected a vector of 8 inputs")
	}
	nn = len(param[0])
	for i := 1; i < d.VecSize(); i++ {
		if nn != len(param[i]) {
			panic("All inputs must have the same length")
		}
	}
	p := make([][]byte, vecSize)
	for i := range param {
		p[i] = param[i]
	}
	d.len += uint64(nn)
	if d.nx > 0 {
		var n int
		for i := 0; i < d.VecSize(); i++ {
			n = copy(d.x[i][d.nx:], p[i])
			p[i] = p[i][n:]
		}
		d.nx += n
		if d.nx == SHA1chunk {
			var par [vecSize]*byte
			for i := 0; i < d.VecSize(); i++ {
				par[i] = &d.x[i][0]
			}
			multiblock(d, &par, SHA1chunk)
			d.nx = 0
		}
	}
	if len(p[0]) >= SHA1chunk {
		n := len(p[0]) &^ (SHA1chunk - 1)
		var par [vecSize]*byte
		for i := 0; i < d.VecSize(); i++ {
			par[i] = &p[i][0]
		}
		multiblock(d, &par, n)
		for i := 0; i < d.VecSize(); i++ {
			p[i] = p[i][n:]
		}
	}
	if len(p[0]) > 0 {
		for i := 0; i < d.VecSize(); i++ {
			d.nx = copy(d.x[i][:], p[i])
		}
	}
	return
}

func (d0 *digest8sha1) Sum(in [][]byte) [][]byte {
	// Make a copy of d0 so that caller can keep writing and summing.
	d := *d0
	var ret [][]byte
	var ret1 [vecSize][]byte
	var digest [vecSize][SizeSHA1]byte
	for i := 0; i < d.VecSize(); i++ {
		ret1[i] = digest[i][:]
	}
	ret = ret1[:]
	d.checkSum(ret)
	for i := 0; i < d.VecSize(); i++ {
		if i < len(in) {
			ret[i] = append(in[i], ret[i]...)
		}
	}
	return ret
}

func (d *digest8sha1) checkSum(ret [][]byte) {
	length := d.len
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	sz := 0
	if length%64 < 56 {
		sz = int(56 - length%64)
	} else {
		sz = int(64 + 56 - length%64)
	}
	for i := 0; i < d.VecSize(); i++ {
		d.tmp[i] = d.tmp[i][:sz]
		for j := range d.tmp[i] {
			d.tmp[i][j] = 0
		}
		d.tmp[i][0] = 0x80
	}
	d.Write(d.tmp)

	// Length in bits.
	length <<= 3
	for i := 0; i < d.VecSize(); i++ {
		d.tmp[i] = d.tmp[i][0:8]
		// TODO encodin/binary putuint64?
		lane := d.tmp[i]
		_ = lane[7]
		lane[0] = byte(length >> 56)
		lane[1] = byte(length >> 48)
		lane[2] = byte(length >> 40)
		lane[3] = byte(length >> 32)
		lane[4] = byte(length >> 24)
		lane[5] = byte(length >> 16)
		lane[6] = byte(length >> 8)
		lane[7] = byte(length)
	}
	d.Write(d.tmp)

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	for j := range d.h {
		for i := range d.h[j] {
			//TODO encoding/binary
			s := d.h[j][i]
			offset := j * 4
			lane := ret[i][offset:]
			_ = lane[3]
			lane[0] = byte(s >> 24)
			lane[1] = byte(s >> 16)
			lane[2] = byte(s >> 8)
			lane[3] = byte(s)
		}
	}

	return
}

// In sha1.s
//go:noescape
func multiblock(d *digest8sha1, p *[vecSize]*byte, ln int)
