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
	maxport = PORT_END
	portmap = make([][]PortMapEntry, common.UDPNumber + 1)
	portmap[common.ICMPNumber] = make([]PortMapEntry, maxport)
	portmap[common.TCPNumber] = make([]PortMapEntry, maxport)
	portmap[common.UDPNumber] = make([]PortMapEntry, maxport)
	lastport = PORT_START
}

func deleteOldConnection(protocol uint8, port int) {
	t := table[protocol]

	pub2priKey := Tuple{
		addr: portmap[protocol][port].addr,
		port: uint16(port),
	}
	pri2pubKey, found := t.Load(pub2priKey)

	if found {
		if debug && loggedDelete < 100 {
			pri2pubVal := pri2pubKey.(Tuple)
			println("Deleting connection:", pri2pubVal.String(), "->", pub2priKey.String())
			loggedDelete++
		}

		t.Delete(pri2pubKey)
		t.Delete(pub2priKey)
	} else {
		if debug && loggedDelete < 100 {
			println("Failing to delete connection:", pub2priKey.String())
			loggedDelete++
		}
	}
}

// This function currently is not thread safe and should be executed
// under a global lock
func allocNewPort(protocol uint8) int {
	pm := portmap[protocol]
	for {
		for p := lastport; p < PORT_END; p++ {
			if pm[p].lastused.Add(CONNECTION_TIMEOUT).Before(time.Now()) {
				lastport = p
				deleteOldConnection(protocol, p)
				return p
			}
		}

		for p := PORT_START; p < lastport; p++ {
			if pm[p].lastused.Add(CONNECTION_TIMEOUT).Before(time.Now()) {
				lastport = p
				deleteOldConnection(protocol, p)
				return p
			}
		}
		println("WARNING! All ports are allocated! Trying again")
	}
}
