// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package crypto_mb

// in aes.s
//go:noescape
func expandKeyAsm(nr int, key *byte, enc, dec *uint32)
