// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"io"
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/intel-go/yanff/common"
)

func init() {
	resetClockImplementation()
}

func resetClockImplementation() {
	now = func() time.Time {
		return fixedTime
	}
}

var (
	globHdrBuffer = []byte{0x4d, 0x3c, 0xb2, 0xa1, 0x02, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0x01, 0, 0, 0}
	globHdr       = PcapGlobHdr{
		MagicNumber:  0xa1b23c4d,
		VersionMajor: 2,
		VersionMinor: 4,
		Snaplen:      65535,
		Network:      1,
	}

	// Rec Pcap header in case of fixedTime
	recHdrBuffer = []byte{0xfd, 0xc4, 0x2f, 0x5a, 0xff, 0x0f, 0, 0, 0xa2, 0, 0, 0, 0xa2, 0, 0, 0}
	recHdr       = PcapRecHdr{
		TsSec:   1513080061, // seconds of fixedTime
		TsUsec:  4095,       // nanoseconds of fixedTime
		InclLen: 162,        // len of test packet, returned by getIPv6ICMPTestPacket()
		OrigLen: 162,        // len of test packet, returned by getIPv6ICMPTestPacket()
	}

	fixedTime = time.Date(2017, 12, 12, 12, 1, 1, 4095, time.UTC)
)

func TestWritePcapGlobalHdr(t *testing.T) {
	wantBuffer := bytes.NewBuffer(globHdrBuffer)
	buffer := bytes.NewBuffer([]byte{})

	err := WritePcapGlobalHdr(buffer)
	if err != nil {
		log.Fatal(err)
	}

	if !reflect.DeepEqual(buffer, wantBuffer) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buffer, wantBuffer)
	}
}

func TestReadPcapGlobalHdr(t *testing.T) {
	source := bytes.NewBuffer(globHdrBuffer)
	var gotGlobHdr PcapGlobHdr

	err := ReadPcapGlobalHdr(source, &gotGlobHdr)
	if err != nil {
		log.Fatal(err)
	}

	if gotGlobHdr != globHdr {
		t.Errorf("Incorrect result:\ngot:  %+v, \nwant: %+v\n\n", gotGlobHdr, globHdr)
	}
}

func TestWritePcapOnePacket(t *testing.T) {
	pkt := getIPv6ICMPTestPacket()
	pktBuffer := pkt.GetRawPacketBytes()
	wantBuffer := bytes.NewBuffer(append(recHdrBuffer, pktBuffer...))

	buffer := bytes.NewBuffer([]byte{})
	err := pkt.WritePcapOnePacket(buffer)
	if err != nil {
		log.Fatal(err)
	}

	if !reflect.DeepEqual(buffer, wantBuffer) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buffer, wantBuffer)
	}
}

// Test fro internal readPcapRecHdr
func TestReadPcapRecHdr(t *testing.T) {
	wantHdr := recHdr
	var hdr PcapRecHdr
	buffer := bytes.NewBuffer(recHdrBuffer)
	err := readPcapRecHdr(buffer, &hdr)

	if !reflect.DeepEqual(hdr, wantHdr) || err != nil {
		t.Errorf("Incorrect result:\ngot:  %+v, \nwant: %+v,\n err got = %v,\n err want = %v\n\n", hdr, wantHdr, err, nil)
	}

	// Test read from empty buffer
	emptyBuffer := bytes.NewBuffer([]byte{})
	err = readPcapRecHdr(emptyBuffer, &hdr)

	if common.GetNFError(err).Cause() != io.EOF {
		t.Errorf("Incorrect result:\ngot:  %+v, \nwant: %+v\n\n", err, io.EOF)
	}
}

func TestReadPcapOnePacket(t *testing.T) {
	wantPkt := getIPv6ICMPTestPacket()
	pkt := getPacket()

	srcBytes := wantPkt.GetRawPacketBytes()
	srcBuffer := bytes.NewBuffer(append(recHdrBuffer, srcBytes...))

	_, err := pkt.ReadPcapOnePacket(srcBuffer)
	if err != nil {
		log.Fatal(err)
	}
	pkt.ParseData()

	if !reflect.DeepEqual(pkt.Ether, wantPkt.Ether) {
		t.Errorf("Incorrect L2 result:\ngot:  %+v, \nwant: %+v\n\n", pkt.Ether, wantPkt.Ether)
	}

	if !reflect.DeepEqual(pkt.GetIPv6(), wantPkt.GetIPv6()) {
		t.Errorf("Incorrect L3 result:\ngot:  %+v, \nwant: %+v\n\n", pkt.GetIPv6(), wantPkt.GetIPv6())
	}

	if !reflect.DeepEqual(pkt.GetIPv4(), wantPkt.GetIPv4()) {
		t.Errorf("Incorrect L3 result:\ngot:  %+v, \nwant: %+v\n\n", pkt.GetIPv4(), wantPkt.GetIPv4())
	}

	if !reflect.DeepEqual(pkt.GetICMPForIPv6(), wantPkt.GetICMPForIPv6()) {
		t.Errorf("Incorrect L4 result:\ngot:  %+v, \nwant: %+v\n\n", pkt.GetICMPForIPv6(), wantPkt.GetICMPForIPv6())
	}
}
