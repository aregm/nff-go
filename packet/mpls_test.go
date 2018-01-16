// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"encoding/hex"
	"log"
	"testing"

	"github.com/intel-go/yanff/low"
)

func init() {
	mempool = GetMempoolForTest()
}

func TestAllMpls(t *testing.T) {
	// From pktgen
	buf, _ := hex.DecodeString("6805ca3331386805ca3332688847fffffb394500002a6bf500000406c886c0a80001c0a8010104d2162e123456781234569050102000f0dd00003031")
	mb := make([]uintptr, 1)
	if err := low.AllocateMbufs(mb, mempool, 1); err != nil {
		log.Fatal(err)
	}
	current := ExtractPacket(mb[0])
	GeneratePacketFromByte(current, buf)

	m := current.GetMPLSNoCheck()
	internalTest(m, t, 1048575, 5, 1, 57)
	if m.DecreaseTTL() != true {
		t.Errorf("Decrease from 57 shouldn't return false")
	}
	internalTest(m, t, 1048575, 5, 1, 56)
	label := m.GetMPLSLabel()
	if label != 1048575 {
		t.Errorf("Incorrect result:\ngot:  %d, \nwant: %d\n\n", label, 1048575)
	}
	label = label - 2
	m.SetMPLSLabel(label)
	internalTest(m, t, 1048573, 5, 1, 56)
	current.RemoveMPLS()
	newMPLS := uint32(0x11111a01)
	current.AddMPLS(newMPLS)
	internalTest(m, t, 69905, 5, 0, 1)
	if m.DecreaseTTL() != false {
		t.Errorf("Decrease from 0 should return false to discard this packet")
	}
}

func internalTest(m *MPLSHdr, t *testing.T, label uint32, exp uint32, s uint32, ttl uint32) {
	if SwapBytesUint32(m.mpls)>>12 != label {
		t.Errorf("Incorrect result:\ngot:  %d, \nwant: %d\n\n", SwapBytesUint32(m.mpls)>>12, label)
	}
	if (SwapBytesUint32(m.mpls)>>9)&0x00000007 != exp {
		t.Errorf("Incorrect result:\ngot:  %d, \nwant: %d\n\n", (SwapBytesUint32(m.mpls)>>9)&0x00000007, exp)
	}
	if (SwapBytesUint32(m.mpls)>>8)&1 != s {
		t.Errorf("Incorrect result:\ngot:  %d, \nwant: %d\n\n", (SwapBytesUint32(m.mpls)>>8)&1, s)
	}
	if SwapBytesUint32(m.mpls)&0x000000ff != ttl {
		t.Errorf("Incorrect result:\ngot:  %d, \nwant: %d\n\n", SwapBytesUint32(m.mpls)&0x000000ff, ttl)
	}
}
