// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"errors"
	"github.com/intel-go/yanff/common"
	"strconv"
	"time"
)

type terminationDirection uint8

const (
	NUM_PUB_ADDRS = 1

	PORT_START = 1024
	PORT_END = 65500
	NUM_PORTS = PORT_END - PORT_START

	CONNECTION_TIMEOUT time.Duration = 1 * time.Minute

	PRI2PUB terminationDirection = 0x0f
	PUB2PRI terminationDirection = 0xf0
)

func (dir terminationDirection) String() string {
	if dir == PUB2PRI {
		return "pub2pri"
	} else if dir == PRI2PUB {
		return "pri2pub"
	} else {
		return "unknown(" + strconv.Itoa(int(dir)) + ")"
	}
}

type PortMapEntry struct {
	lastused   time.Time
	addr       uint32
	finCount   uint8
	terminationDirection terminationDirection
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
	pubTable := &pub2priTable[protocol]
	pm := portmap[protocol]

	pub2priKey := Tuple{
		addr: pm[port].addr,
		port: uint16(port),
	}
	pri2pubKey, found := pubTable.Load(pub2priKey)

	if found {
		if debug && (loggedDelete < logThreshold || debugPort == uint16(port)) {
			pri2pubVal := pri2pubKey.(Tuple)
			println("Deleting connection", loggedDelete, ":", pri2pubVal.String(), "->", pub2priKey.String())
			loggedDelete++
		}

		pri2pubTable[protocol].Delete(pri2pubKey)
		pubTable.Delete(pub2priKey)
	} else {
		if debug && (loggedDelete < logThreshold || debugPort == uint16(port)) {
			println("Failing to delete connection", loggedDelete, ":", pub2priKey.String())
			loggedDelete++
		}
	}
	pm[port] = PortMapEntry{}
}

// This function currently is not thread safe and should be executed
// under a global lock
func allocNewPort(protocol uint8) (int, error) {
	pm := portmap[protocol]
	for {
		now := time.Now()
		for p := lastport; p < PORT_END; p++ {
			if pm[p].lastused.Add(CONNECTION_TIMEOUT).Before(now) {
				lastport = p
				deleteOldConnection(protocol, p)
				return p, nil
			}
		}

		for p := PORT_START; p < lastport; p++ {
			if pm[p].lastused.Add(CONNECTION_TIMEOUT).Before(now) {
				lastport = p
				deleteOldConnection(protocol, p)
				return p, nil
			}
		}
		return 0, errors.New("WARNING! All ports are allocated! Trying again")
	}
}
