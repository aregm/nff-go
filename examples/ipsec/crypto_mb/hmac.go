// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package crypto_mb

//based on crypto/hmac
// key is zero padded to the block size of the hash function
// ipad = 0x36 byte repeated for key length
// opad = 0x5c byte repeated for key length
// hmac = H([key ^ opad] H([key ^ ipad] text))

type multihmac struct {
	size         int
	blocksize    int
	vecsize      int
	opad, ipad   [][]byte
	outer, inner MultiHash
	p1, p2       [][]byte
}

func (h *multihmac) Sum(in [][]byte) [][]byte {
	origLen := 0
	if len(in) != 0 {
		origLen = len(in[0])
	}
	//TODO fix,check len(in)
	in = h.inner.Sum(in)
	h.outer.Reset()
	h.outer.Write(h.opad)
	for i := range h.p1 {
		h.p1[i] = in[i][origLen:]
		h.p2[i] = in[i][:origLen]
	}
	h.outer.Write(h.p1)
	return h.outer.Sum(h.p2)
}

// Doesn't implement io.writer due to input
func (h *multihmac) Write(p [][]byte) int {
	return h.inner.Write(p)
}

func (h *multihmac) Size() int { return h.size }

func (h *multihmac) BlockSize() int { return h.blocksize }

func (h *multihmac) VecSize() int { return h.vecsize }

func (h *multihmac) Reset() {
	h.inner.Reset()
	h.inner.Write(h.ipad)
}

//TODO separate packages to avoid name collisions
// New returns a new HMAC hash using the given hash.Hash type and key.
func NewHmac(h func() MultiHash, key []byte) MultiHash {
	hm := new(multihmac)
	hm.outer = h()
	hm.inner = h()
	hm.size = hm.inner.Size()
	hm.vecsize = hm.inner.VecSize()
	hm.blocksize = hm.inner.BlockSize()
	hm.ipad = make([][]byte, hm.vecsize)
	hm.opad = make([][]byte, hm.vecsize)
	hm.p1 = make([][]byte, hm.vecsize)
	hm.p2 = make([][]byte, hm.vecsize)
	keys := make([][]byte, hm.vecsize)
	for i := range hm.ipad {
		hm.ipad[i] = make([]byte, hm.blocksize)
		hm.opad[i] = make([]byte, hm.blocksize)
		keys[i] = make([]byte, len(key))
		copy(keys[i], key)
	}
	//	println(keys[0])
	if len(key) > hm.blocksize {
		// If key is too big, hash it.
		hm.outer.Write(keys)
		keys = hm.outer.Sum(nil)
		//		println(keys[0])
	}
	for i := 0; i < hm.vecsize; i++ {
		copy(hm.ipad[i], keys[i])
		copy(hm.opad[i], keys[i])
		for j := range hm.ipad[i] {
			hm.ipad[i][j] ^= 0x36
		}
		for j := range hm.opad[i] {
			hm.opad[i][j] ^= 0x5c
		}
	}
	hm.inner.Write(hm.ipad)
	return hm
}
