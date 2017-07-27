// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"github.com/intel-go/yanff/common"
	"time"
)

const (
	NUM_PUB_ADDRS = 1

	PORT_START = 1024
	PORT_END = 65500
	NUM_PORTS = PORT_END - PORT_START

	CONNECTION_TIMEOUT time.Duration = 10 * time.Minute
)

type PortMapEntry struct {
	lastused time.Time
	addr     uint32
}

var (
	portmap  [][]PortMapEntry
	lastport int
	maxport  int
)

func init() {
	maxport = NUM_PORTS * NUM_PUB_ADDRS
	portmap = make([][]PortMapEntry, common.UDPNumber + 1)
	portmap[common.ICMPNumber] = make([]PortMapEntry, maxport)
	portmap[common.TCPNumber] = make([]PortMapEntry, maxport)
	portmap[common.UDPNumber] = make([]PortMapEntry, maxport)
	lastport = 0
}

func deleteOldConnection(protocol uint8, port int) {
	pub2priKey := TupleKey{
		Tuple: Tuple{
			addr: portmap[protocol][port].addr,
			port: uint16(port),
		},
		protocol: protocol,
	}

	pri2pubKey := TupleKey{
		Tuple: table[pub2priKey],
		protocol: protocol,
	}

	table[pri2pubKey] = EMPTY_ENTRY
	table[pub2priKey] = EMPTY_ENTRY
}

// This function currently is not thread safe and should be executed
// under a global lock
func allocNewPort(protocol uint8) int {
	pm := portmap[protocol]
	for {
		for p := lastport; p < maxport; p++ {
			if pm[p].lastused.Add(CONNECTION_TIMEOUT).Before(time.Now()) {
				lastport = p
				deleteOldConnection(protocol, p)
				return p
			}
		}

		for p := 0; p < lastport; p++ {
			if pm[p].lastused.Add(CONNECTION_TIMEOUT).Before(time.Now()) {
				lastport = p
				deleteOldConnection(protocol, p)
				return p
			}
		}
	}
}
