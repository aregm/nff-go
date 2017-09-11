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
	numPubAddr = 1

	portStart = 1024
	portEnd   = 65500
	numPorts  = portEnd - portStart

	connectionTimeout time.Duration = 1 * time.Minute

	pri2pub terminationDirection = 0x0f
	pub2pri terminationDirection = 0xf0
)

func (dir terminationDirection) String() string {
	if dir == pub2pri {
		return "pub2pri"
	} else if dir == pri2pub {
		return "pri2pub"
	} else {
		return "unknown(" + strconv.Itoa(int(dir)) + ")"
	}
}

type portMapEntry struct {
	lastused             time.Time
	addr                 uint32
	finCount             uint8
	terminationDirection terminationDirection
}

var (
	portmap  [][]portMapEntry
	lastport int
	maxport  int
)

func init() {
	maxport = portEnd
	portmap = make([][]portMapEntry, common.UDPNumber+1)
	portmap[common.ICMPNumber] = make([]portMapEntry, maxport)
	portmap[common.TCPNumber] = make([]portMapEntry, maxport)
	portmap[common.UDPNumber] = make([]portMapEntry, maxport)
	lastport = portStart
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
		pri2pubTable[protocol].Delete(pri2pubKey)
		pubTable.Delete(pub2priKey)
	}
	pm[port] = portMapEntry{}
}

// This function currently is not thread safe and should be executed
// under a global lock
func allocNewPort(protocol uint8) (int, error) {
	pm := portmap[protocol]
	for {
		now := time.Now()
		for p := lastport; p < portEnd; p++ {
			if pm[p].lastused.Add(connectionTimeout).Before(now) {
				lastport = p
				deleteOldConnection(protocol, p)
				return p, nil
			}
		}

		for p := portStart; p < lastport; p++ {
			if pm[p].lastused.Add(connectionTimeout).Before(now) {
				lastport = p
				deleteOldConnection(protocol, p)
				return p, nil
			}
		}
		return 0, errors.New("WARNING! All ports are allocated! Trying again")
	}
}
