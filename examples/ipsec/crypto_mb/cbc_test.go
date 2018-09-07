// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package crypto_mb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"strconv"
	"testing"
)

//TODO Separate test package?

// Common values for tests.

var commonInput = []byte{
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
}

var commonKey128 = []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}

var commonKey192 = []byte{
	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
	0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
}

var commonKey256 = []byte{
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
}

var commonIV = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

var cbcAESTests = []struct {
	name string
	key  []byte
	iv   []byte
	in   []byte
	out  []byte
}{
	// NIST SP 800-38A pp 27-29
	{
		"CBC-AES128",
		commonKey128,
		commonIV,
		commonInput,
		[]byte{
			0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
			0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
			0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
			0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
		},
	},
	/*	{
			"CBC-AES192",
			commonKey192,
			commonIV,
			commonInput,
			[]byte{
				0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
				0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4, 0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
				0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
				0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81, 0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd,
			},
		},
		{
			"CBC-AES256",
			commonKey256,
			commonIV,
			commonInput,
			[]byte{
				0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
				0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
				0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
				0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b,
			},
		},*/
}

func TestCBCEncrypterAES(t *testing.T) {
	for _, tt := range cbcAESTests {
		c := NewAESMultiBlock(tt.key)
		iv := make([][]byte, 0)
		in := make([][]byte, 0)
		for i := 0; i < c.VecSize(); i++ {
			tmp_i := make([]byte, len(tt.in))
			copy(tmp_i, tt.in)
			in = append(in, tmp_i)
			iv = append(iv, tt.iv)
		}

		encrypter := NewMultiCBCEncrypter(c, iv)
		encrypter.CryptManyBlocks(in, in)
		for i := 0; i < c.VecSize(); i++ {
			if !bytes.Equal(tt.out, in[i]) {
				t.Errorf("%s: CBCEncrypter\nhave %x\nwant %x in %d round", tt.name, in[i], tt.out, i)
			}
		}
	}
}

func TestSetIV(t *testing.T) {
	for _, tt := range cbcAESTests {
		c := NewAESMultiBlock(tt.key)
		iv := make([][]byte, c.VecSize())
		iv2 := make([][]byte, c.VecSize())
		in := make([][]byte, c.VecSize())
		for i := range iv {
			iv[i] = make([]byte, len(tt.iv))
			iv2[i] = make([]byte, len(tt.iv))
			in[i] = make([]byte, len(tt.in))
			copy(in[i], tt.in)
			copy(iv2[i], tt.iv)
		}
		encrypter := NewMultiCBCEncrypter(c, iv)
		encrypter.(MultiSetIVer).SetIV(iv2)
		encrypter.CryptManyBlocks(in, in)
		for i := 0; i < c.VecSize(); i++ {
			if !bytes.Equal(tt.out, in[i]) {
				t.Errorf("%s: CBCEncrypter\nhave %x\nwant %x in %d lane", tt.name, in[i], tt.out, i)
			}
		}
	}
}

func TestCBCEncrypterAESagainstNonMB(t *testing.T) {
	c := NewAESMultiBlock(commonKey128)
	iv1 := make([][]byte, 0)
	in1 := make([][]byte, 0)
	iv2 := make([][]byte, 0)
	in2 := make([][]byte, 0)
	for i := 0; i < c.VecSize(); i++ {
		tmp_in1 := make([]byte, 128)
		tmp_in2 := make([]byte, 128)
		for j := range tmp_in2 {
			//TODO math/rand
			tmp_in2[j] = byte(j*7 + i + 23)
			tmp_in1[j] = byte(j*7 + i + 23)
		}
		tmp_iv1 := make([]byte, 16)
		tmp_iv2 := make([]byte, 16)
		for j := range tmp_iv2 {
			tmp_iv2[j] = byte(j*7 + i + 23)
			tmp_iv1[j] = byte(j*7 + i + 23)
		}
		in1 = append(in1, tmp_in1)
		in2 = append(in2, tmp_in2)
		iv1 = append(iv1, tmp_iv1)
		iv2 = append(iv2, tmp_iv2)
	}

	encrypter := NewMultiCBCEncrypter(c, iv1)
	encrypter.CryptManyBlocks(in1, in1)
	c2, err := aes.NewCipher(commonKey128)
	if err != nil {
		t.Errorf("Failed to create aes.NewCipher")
	}

	for i := 0; i < c.VecSize(); i++ {
		scalarEncrypter := cipher.NewCBCEncrypter(c2, iv2[i])
		scalarEncrypter.CryptBlocks(in2[i], in2[i])
		if !bytes.Equal(in2[i], in1[i]) {
			t.Errorf("MultiCBCEncrypter produced %x\nwant %x in %d lane", in1[i], in2[i], i)
		}
	}
}

func BenchmarkAESCBCEncrypt(b *testing.B) {
	sizes := []int{16, 64, 320, 1024, 8096}
	for i := range sizes {
		size := sizes[i]
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			buf := make([][]byte, 0)
			iv := make([][]byte, 0)
			var key [16]byte
			c := NewAESMultiBlock(key[:])
			for i := 0; i < c.VecSize(); i++ {
				buf = append(buf, make([]byte, size))
				iv = append(iv, make([]byte, 16))
			}
			cbc := NewMultiCBCEncrypter(c, iv)
			b.SetBytes(int64(len(buf[0]) * c.VecSize()))
			for i := 0; i < b.N; i++ {
				cbc.CryptManyBlocks(buf, buf)
			}
		})
	}
}

func BenchmarkAESCBCEncryptAlloc(b *testing.B) {
	sizes := []int{16, 64, 320, 1024, 8096}
	for i := range sizes {
		size := sizes[i]
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			buf := make([][]byte, 0)
			iv := make([][]byte, 0)
			var key [16]byte
			c := NewAESMultiBlock(key[:])
			for i := 0; i < c.VecSize(); i++ {
				buf = append(buf, make([]byte, size))
				iv = append(iv, make([]byte, 16))
			}
			b.SetBytes(int64(len(buf[0]) * c.VecSize()))
			for i := 0; i < b.N; i++ {
				cbc := NewMultiCBCEncrypter(c, iv)
				cbc.CryptManyBlocks(buf, buf)
			}
		})
	}
}

func TestCBCDecrypterAES(t *testing.T) {
	for _, tt := range cbcAESTests {
		c := NewAESMultiBlock(tt.key)
		iv := make([][]byte, 0)
		in := make([][]byte, 0)
		for i := 0; i < c.VecSize(); i++ {
			tmp_i := make([]byte, len(tt.in))
			copy(tmp_i, tt.out)
			in = append(in, tmp_i)
			iv = append(iv, tt.iv)
		}

		decrypter := NewMultiCBCDecrypter(c, iv)
		decrypter.CryptManyBlocks(in, in)
		for i := 0; i < c.VecSize(); i++ {
			if !bytes.Equal(tt.in, in[i]) {
				t.Errorf("%s: CBCDecrypter\nhave %x\nwant %x in %d lane", tt.name, in[i], tt.in, i)
			}
		}
	}
}
