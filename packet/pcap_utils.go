// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"time"
	"unsafe"

	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/low"
)

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
	TsUsec  uint32 /* timestamp microseconds */
	InclLen uint32 /* number of octets of packet saved in file */
	OrigLen uint32 /* actual length of packet */
}

// WritePcapGlobalHdr writes global pcap header into file.
func WritePcapGlobalHdr(f *os.File) {
	glHdr := PcapGlobHdr{
		MagicNumber:  0xa1b2c3d4,
		VersionMajor: 2,
		VersionMinor: 4,
		Snaplen:      65535,
		Network:      1,
	}
	buffer := bytes.Buffer{}
	err := binary.Write(&buffer, binary.LittleEndian, &glHdr)
	if err != nil {
		common.LogError(common.Debug, err)
	}
	_, err = f.Write(buffer.Bytes())
	if err != nil {
		common.LogError(common.Debug, err)
	}
}

// WritePcapOnePacket writes one packet with pcap header in file.
// Assumes global pcap header is already present in file.
func (pkt *Packet) WritePcapOnePacket(f *os.File) {
	bytes := low.GetRawPacketBytesMbuf(pkt.CMbuf)
	writePcapRecHdr(f, bytes)
	writePacketBytes(f, bytes)
}

func writePcapRecHdr(f *os.File, pktBytes []byte) error {
	t := time.Now()
	hdr := PcapRecHdr{
		TsSec:   uint32(t.Unix()),
		TsUsec:  uint32(t.UnixNano() - t.Unix()*1e9),
		InclLen: uint32(len(pktBytes)),
		OrigLen: uint32(len(pktBytes)),
	}
	buffer := bytes.Buffer{}
	err := binary.Write(&buffer, binary.LittleEndian, &hdr)
	if err != nil {
		common.LogError(common.Debug, err)
	}
	_, err = f.Write(buffer.Bytes())
	if err != nil {
		common.LogError(common.Debug, err)
	}
	return nil
}

func writePacketBytes(f *os.File, pktBytes []byte) {
	_, err := f.Write(pktBytes)
	if err != nil {
		common.LogError(common.Debug, err)
	}
}

// ReadPcapGlobalHdr read global pcap header into file.
func ReadPcapGlobalHdr(f *os.File, glHdr *PcapGlobHdr) {
	data := make([]byte, unsafe.Sizeof(*glHdr))
	_, err := f.Read(data)
	if err != nil {
		common.LogError(common.Debug, err)
	}

	buffer := bytes.NewBuffer(data)
	err = binary.Read(buffer, binary.LittleEndian, glHdr)
	if err != nil {
		common.LogError(common.Debug, err)
	}
}

func readPcapRecHdr(f *os.File, hdr *PcapRecHdr) error {
	data := make([]byte, unsafe.Sizeof(*hdr))
	_, err := f.Read(data)

	if err != nil {
		return err
	}

	buffer := bytes.NewBuffer(data)
	err = binary.Read(buffer, binary.LittleEndian, hdr)
	if err != nil {
		common.LogError(common.Debug, err)
	}
	return nil
}

func readPacketBytes(f *os.File, inclLen uint32) []byte {
	pkt := make([]byte, inclLen)
	_, err := f.Read(pkt)
	if err != nil {
		common.LogError(common.Debug, err)
	}
	return pkt
}

// ReadPcapOnePacket read one packet with pcap header from file.
// Assumes that global pcap header is already read.
func (pkt *Packet) ReadPcapOnePacket(f *os.File) bool {
	var hdr PcapRecHdr
	err := readPcapRecHdr(f, &hdr)
	if err == io.EOF {
		return true
	} else if err != nil {
		common.LogError(common.Debug, err)
	}
	bytes := readPacketBytes(f, hdr.InclLen)
	GeneratePacketFromByte(pkt, bytes)
	return false
}
