// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"errors"
	"strconv"
	"time"
)

const (
	numPubAddr = 1

	portStart = 1024
	portEnd   = 65500
	numPorts  = portEnd - portStart
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

func (pp *portPair) deleteOldConnection(ipv6 bool, protocol uint8, port int) {
	pubTable := pp.PublicPort.translationTable[protocol]
	pm := pp.getPublicPortPortmap(ipv6, protocol)

	pub2priKey := pp.makePublicPortTuple(ipv6, uint16(port))
	pri2pubKey, found := pubTable.Load(pub2priKey)

	if found {
		pp.PrivatePort.translationTable[protocol].Delete(pri2pubKey)
		pubTable.Delete(pub2priKey)
	}
	pm[port] = portMapEntry{}
}

// This function currently is not thread safe and should be executed
// under a global lock
func (pp *portPair) allocNewPort(ipv6 bool, protocol uint8) (int, error) {
	pm := pp.getPublicPortPortmap(ipv6, protocol)
	for {
		for p := pp.lastport; p < portEnd; p++ {
			if !pm[p].static && time.Since(pm[p].lastused) > connectionTimeout {
				pp.lastport = p
				pp.deleteOldConnection(ipv6, protocol, p)
				return p, nil
			}
		}

		for p := portStart; p < pp.lastport; p++ {
			if !pm[p].static && time.Since(pm[p].lastused) > connectionTimeout {
				pp.lastport = p
				pp.deleteOldConnection(ipv6, protocol, p)
				return p, nil
			}
		}
		return 0, errors.New("WARNING! All ports are allocated! Trying again")
	}
}

func (pp *portPair) getPublicPortPortmap(ipv6 bool, protocol uint8) []portMapEntry {
	if ipv6 {
		return pp.PublicPort.portmap6[protocol]
	} else {
		return pp.PublicPort.portmap[protocol]
	}
}

func (pp *portPair) makePublicPortTuple(ipv6 bool, port uint16) interface{} {
	if ipv6 {
		return Tuple6{
			addr: pp.PublicPort.Subnet6.Addr,
			port: uint16(port),
		}
	} else {
		return Tuple{
			addr: pp.PublicPort.Subnet.Addr,
			port: uint16(port),
		}
	}
}
