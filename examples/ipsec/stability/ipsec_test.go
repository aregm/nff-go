// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "github.com/intel-go/nff-go/examples/ipsec"
import "github.com/intel-go/nff-go/flow"
import "github.com/intel-go/nff-go/packet"
import "unsafe"
import "testing"
import "time"

var t *testing.T
var n1 int
var n2 int
var s = make(chan int)
var s1 = make(chan int)

func init() {
	config := flow.Config{
		CPUList:    "0-15",
		MbufNumber: 8191 * 4,
		RingSize:   64 * 8,
	}
	flow.SystemInit(&config)
}

func TestVector(m *testing.T) {
	t = m
	n1 = 0
	n2 = 0
	input1 := flow.SetGenerator(generatePacket, nil)
	flow.SetVectorHandlerDrop(input1, ipsec.VectorEncapsulation, ipsec.VContext{})
	flow.SetHandlerDrop(input1, ipsec.Decapsulation, ipsec.SContext{})
	flow.SetHandler(input1, check, nil)
	flow.SetStopper(input1)

	go flow.SystemStart()
	<-s1
	flow.SystemStop()
}

func TestScalar(m *testing.T) {
	t = m
	n1 = 0
	n2 = 0
	input2 := flow.SetGenerator(generatePacket, nil)
	flow.SetHandlerDrop(input2, ipsec.ScalarEncapsulation, ipsec.SContext{})
	flow.SetHandlerDrop(input2, decapsulation, sContext{})
	flow.SetHandler(input2, check, nil)
	flow.SetStopper(input2)

	go flow.SystemStart()
	<-s1
	flow.SystemStop()
}

func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	packet.InitEmptyIPv4TCPPacket(pkt, 6)

	for i := 0; i < 60; i++ {
		// This will full rewrite packet. No parsing methods are allowed
		// Because EtherType and VersionIhl are wrong now.
		(*((*[60]byte)(unsafe.Pointer(pkt.StartAtOffset(0)))))[i] = byte(n1 % 10)
	}
	n1++
	if n1 == 10001 {
		<-s
		s1 <- 1
		time.Sleep(10000)
	}

	pkt.Ether.DAddr = [6]uint8{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	pkt.Ether.SAddr = [6]uint8{0x66, 0x55, 0x44, 0x33, 0x22, 0x11}
	pkt.GetIPv4NoCheck().SrcAddr = packet.BytesToIPv4(123, 45, 6, 0)
	pkt.GetIPv4NoCheck().DstAddr = packet.BytesToIPv4(5, 43, 210, 0)
	pkt.GetTCPNoCheck().SrcPort = packet.SwapBytesUint16(999)
	pkt.GetTCPNoCheck().DstPort = packet.SwapBytesUint16(111)
}

var groundTruth = [][]byte{{17, 34, 51, 68, 85, 102, 102, 85, 68, 51, 34, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 45, 6, 0, 5, 43, 210, 0, 3, 231, 0, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{17, 34, 51, 68, 85, 102, 102, 85, 68, 51, 34, 17, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 123, 45, 6, 0, 5, 43, 210, 0, 3, 231, 0, 111, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{17, 34, 51, 68, 85, 102, 102, 85, 68, 51, 34, 17, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 123, 45, 6, 0, 5, 43, 210, 0, 3, 231, 0, 111, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
	{17, 34, 51, 68, 85, 102, 102, 85, 68, 51, 34, 17, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 123, 45, 6, 0, 5, 43, 210, 0, 3, 231, 0, 111, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
	{17, 34, 51, 68, 85, 102, 102, 85, 68, 51, 34, 17, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 123, 45, 6, 0, 5, 43, 210, 0, 3, 231, 0, 111, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4},
	{17, 34, 51, 68, 85, 102, 102, 85, 68, 51, 34, 17, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 123, 45, 6, 0, 5, 43, 210, 0, 3, 231, 0, 111, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
	{17, 34, 51, 68, 85, 102, 102, 85, 68, 51, 34, 17, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 123, 45, 6, 0, 5, 43, 210, 0, 3, 231, 0, 111, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6},
	{17, 34, 51, 68, 85, 102, 102, 85, 68, 51, 34, 17, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 123, 45, 6, 0, 5, 43, 210, 0, 3, 231, 0, 111, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7},
	{17, 34, 51, 68, 85, 102, 102, 85, 68, 51, 34, 17, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 123, 45, 6, 0, 5, 43, 210, 0, 3, 231, 0, 111, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8},
	{17, 34, 51, 68, 85, 102, 102, 85, 68, 51, 34, 17, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 123, 45, 6, 0, 5, 43, 210, 0, 3, 231, 0, 111, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}}

func check(currentPacket *packet.Packet, context flow.UserContext) {
	W := currentPacket.GetRawPacketBytes()
	for i := 0; i < 60; i++ {
		if W[i] != groundTruth[n2%10][i] {
			if n2 < 10000 {
				t.Errorf("Raw truth=%x\nRaw bytes=%x\n", groundTruth[n2%10], W)
			}
		}
	}
	n2++
	if n2 == 10000 {
		s <- 1
	}
}
