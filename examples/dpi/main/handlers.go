package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"sync/atomic"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/examples/dpi/pattern"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

type localCounters struct {
	handlerID         uint
	allowedCounterPtr *uint64
	readCounterPtr    *uint64
	blockedCounterPtr *uint64
}

// Create new counters for new handler
func (lc localCounters) Copy() interface{} {
	var newlc localCounters
	// Clones has the same id
	id := lc.handlerID
	newlc.handlerID = id
	newlc.allowedCounterPtr = &allowedPktsCount[id]
	newlc.readCounterPtr = &readPktsCount[id]
	newlc.blockedCounterPtr = &blockedPktsCount[id]
	return newlc
}

func (lc localCounters) Delete() {
}

func filterByRegexp(pkt *packet.Packet, context flow.UserContext) bool {
	cnt := context.(localCounters)
	numRead := cnt.readCounterPtr
	numAllowed := cnt.allowedCounterPtr
	numBlocked := cnt.blockedCounterPtr

	atomic.AddUint64(numRead, 1)
	data, ok := pkt.GetPacketPayload()
	if !ok {
		fmt.Println("WARNING: cannot get payload, drop packet")
		return false
	}

	accept := false
	block := false
	for _, p := range patterns {
		result := p.Re.Match(data)
		if !result {
			continue
		}
		if p.Allow {
			accept = true
		} else {
			accept = false
			block = true
		}
	}
	if accept {
		atomic.AddUint64(numAllowed, 1)
	}
	if !accept && block {
		atomic.AddUint64(numBlocked, 1)
	}
	return accept
}

func splitBy5Tuple(pkt *packet.Packet, context flow.UserContext) uint {
	hash := fnv.New64a()
	ip4, ip6, _ := pkt.ParseAllKnownL3()
	if ip4 != nil {
		pkt.ParseL4ForIPv4()
	} else if ip6 != nil {
		pkt.ParseL4ForIPv6()
	} else {
		// Other protocols not supported
		return pattern.TotalNumFlows - 1
	}
	if ip4 != nil {
		if ip4.NextProtoID != common.TCPNumber && ip4.NextProtoID != common.UDPNumber {
			return pattern.TotalNumFlows - 1
		}
		hash.Write([]byte{ip4.NextProtoID})
		buf := new(bytes.Buffer)
		flow.CheckFatal(binary.Write(buf, binary.LittleEndian, ip4.SrcAddr))
		hash.Write(buf.Bytes())
		flow.CheckFatal(binary.Write(buf, binary.LittleEndian, ip4.DstAddr))
		hash.Write(buf.Bytes())
	} else if ip6 != nil {
		if ip6.Proto != common.TCPNumber && ip6.Proto != common.UDPNumber {
			return pattern.TotalNumFlows - 1
		}
		flow.CheckFatal(binary.Write(hash, binary.BigEndian, ip6.Proto))
		hash.Write(ip6.SrcAddr[:])
		hash.Write(ip6.DstAddr[:])
	}

	binary.Write(hash, binary.BigEndian, pkt.GetTCPNoCheck().SrcPort)
	binary.Write(hash, binary.BigEndian, pkt.GetTCPNoCheck().DstPort)

	return uint(hash.Sum64()) % pattern.NumFlows
}

func onMatch(id uint, from, to uint64, flags uint, context interface{}) error {
	isMatch := context.(*bool)
	// Report outside that match was found
	*isMatch = true
	return nil
}

func filterByHS(pkt *packet.Packet, context flow.UserContext) bool {
	cnt := context.(localCounters)
	hid := cnt.handlerID
	numRead := cnt.readCounterPtr
	numAllowed := cnt.allowedCounterPtr

	atomic.AddUint64(numRead, 1)

	data, ok := pkt.GetPacketPayload()
	if !ok {
		fmt.Println("WARNING: cannot get payload, drop packet")
		return false
	}

	result := new(bool)
	if err := hsdb.Bdb.Scan(data, hsdb.Scratches[hid], onMatchCallback, result); err != nil {
		return false
	}

	if *result {
		atomic.AddUint64(numAllowed, 1)
	}
	return *result
}
