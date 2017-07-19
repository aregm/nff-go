// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
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
	portmap  []PortMapEntry
	lastport int
	maxport  int
)

func init() {
	maxport = NUM_PORTS * NUM_PUB_ADDRS
	portmap = make([]PortMapEntry, maxport)
	lastport = 0
}

func deleteOldConnection(port int) {
	pub2priKey := Tuple{
		addr: portmap[port].addr,
		port: uint16(port),
	}

	pri2pubKey := table[pub2priKey]
	table[*pri2pubKey] = nil
	table[pub2priKey] = nil
}

// This function currently is not thread safe and should be executed
// under a global lock
func allocNewPort() int {
	for {
		for p := lastport; p < maxport; p++ {
			if portmap[p].lastused.Add(CONNECTION_TIMEOUT).Before(time.Now()) {
				lastport = p
				deleteOldConnection(p)
				return p
			}
		}

		for p := 0; p < lastport; p++ {
			if portmap[p].lastused.Add(CONNECTION_TIMEOUT).Before(time.Now()) {
				lastport = p
				deleteOldConnection(p)
				return p
			}
		}
	}
}
