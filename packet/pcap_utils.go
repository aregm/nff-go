// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"encoding/binary"
	"io"
	"time"

	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/low"
)

type nowFuncT func() time.Time

var now nowFuncT = func() time.Time { return time.Now() }

// PcapGlobHdrSize is a size of cap global header.
const PcapGlobHdrSize int64 = 24

// PcapGlobHdr is a Pcap global header.
type PcapGlobHdr struct {
	MagicNumber  uint32 /* magic number */
	VersionMajor uint16 /* major version number */
	VersionMinor uint16 /* minor version number */
	Thiszone     int32  /* GMT to local correction */
	Sigfigs      uint32 /* accuracy of timestamps */
	Snaplen      uint32 /* max length of captured packets, in octets */
	Network      uint32 /* data link type */
}

// PcapRecHdr is a Pcap packet header.
type PcapRecHdr struct {
	TsSec   uint32 /* timestamp seconds */
	TsUsec  uint32 /* timestamp nanoseconds */
	InclLen uint32 /* number of octets of packet saved in file */
	OrigLen uint32 /* actual length of packet */
}

// WritePcapGlobalHdr writes global pcap header into file.
func WritePcapGlobalHdr(f io.Writer) {
	glHdr := PcapGlobHdr{
		MagicNumber:  0xa1b2c3d4,
		VersionMajor: 2,
		VersionMinor: 4,
		Snaplen:      65535,
		Network:      1,
	}
	err := binary.Write(f, binary.LittleEndian, &glHdr)
	if err != nil {
		common.LogError(common.Debug, "WritePcapGlobalHdr:", err)
	}
}

// WritePcapOnePacket writes one packet with pcap header in file.
// Assumes global pcap header is already present in file. Packet timestamps have nanosecond resolution.
func (pkt *Packet) WritePcapOnePacket(f io.Writer) {
	bytes := low.GetRawPacketBytesMbuf(pkt.CMbuf)
	writePcapRecHdr(f, bytes)
	writePacketBytes(f, bytes)
}

func writePcapRecHdr(f io.Writer, pktBytes []byte) error {
	t := now()
	hdr := PcapRecHdr{
		TsSec:   uint32(t.Unix()),
		TsUsec:  uint32(t.UnixNano() - t.Unix()*1e9),
		InclLen: uint32(len(pktBytes)),
		OrigLen: uint32(len(pktBytes)),
	}
	err := binary.Write(f, binary.LittleEndian, &hdr)
	if err != nil {
		return err
	}
	return nil
}

func writePacketBytes(f io.Writer, pktBytes []byte) {
	err := binary.Write(f, binary.LittleEndian, pktBytes)
	if err != nil {
		common.LogError(common.Debug, "WritePcapOnePacket internal error:", err)
	}
}

// ReadPcapGlobalHdr read global pcap header into file.
func ReadPcapGlobalHdr(f io.Reader, glHdr *PcapGlobHdr) {
	err := binary.Read(f, binary.LittleEndian, glHdr)
	if err != nil {
		common.LogError(common.Debug, "ReadPcapGlobalHdr:", err)
	}
}

func readPcapRecHdr(f io.Reader, hdr *PcapRecHdr) error {
	return binary.Read(f, binary.LittleEndian, hdr)
}

func readPacketBytes(f io.Reader, inclLen uint32) []byte {
	pkt := make([]byte, inclLen)
	err := binary.Read(f, binary.LittleEndian, pkt)
	if err != nil {
		common.LogError(common.Debug, "ReadPcapOnePacket internal error:", err)
	}
	return pkt
}

// ReadPcapOnePacket read one packet with pcap header from file.
// Assumes that global pcap header is already read.
func (pkt *Packet) ReadPcapOnePacket(f io.Reader) bool {
	var hdr PcapRecHdr
	err := readPcapRecHdr(f, &hdr)
	if err == io.EOF {
		return true
	} else if err != nil {
		common.LogError(common.Debug, "ReadPcapOnePacket:", err)
	}
	bytes := readPacketBytes(f, hdr.InclLen)
	GeneratePacketFromByte(pkt, bytes)
	return false
}
