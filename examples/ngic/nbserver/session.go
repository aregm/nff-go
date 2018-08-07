// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//Package nbserver Defines struccture mapping for ngic CP C struture
// to avoid UDP pkt parsing
package nbserver

/*
#include "session.h"
*/
import "C"
import (
	"fmt"
	"github.com/intel-go/nff-go/packet"
	"os"
	"unsafe"
)

//Messages type S11 constants
const (
	/* Session Bearer Map Hash Table*/
	MsgSessTblCRE uint64 = iota
	MsgSessTblDES
	MsgSessCRE
	MsgSessMOD
	MsgSessDEL
	/* ADC Rule Table*/
	MsgADCTblCRE
	MsgADCTblDES
	MsgADCTblADD
	MsgADCTblDEL
	/* PCC Rule Table*/
	MsgPCCTblCRE
	MsgPCCTblDES
	MsgPCCTblADD
	MsgPCCTblDEL
	/* Meter Tables*/
	MsgMtrCRE
	MsgMtrDES
	MsgMtrADD
	MsgMtrDEL
	MsgMtrCFG
	/* Filter Table for SDF & ADC*/
	MsgSDFCRE
	MsgSDFDES
	MsgSDFADD
	MsgSDFDEL
	MsgExpCDR
	/* DDN from DP to CP*/
	MsgDDN

	MsgEND
)

//CpMsg  CP msg s11 messages
type CpMsg C.struct_msgbuf

//CSessionInfo session info struct
type CSessionInfo C.struct_session_info

//CIpAddr Ip address
type CIpAddr C.struct_ip_addr

//UlS1Info Uplink S1 info
type UlS1Info struct {
	SgwTeid    uint32
	EnbIP      uint32
	SgwIP      uint32
	S5S8PgwuIP uint32
}

//DlS1Info Downlink S1 info
type DlS1Info struct {
	EnbTeid    uint32
	EnbIP      uint32
	SgwIP      uint32
	S5S8SgwuIP uint32
}

//Session UE context/session  struct
type Session struct {
	UeIP     uint32
	UlS1Info *UlS1Info
	DlS1Info *DlS1Info
}

//GetUeIP parse and extract the ue ip information
func GetUeIP(sessInfo *CSessionInfo) uint32 {
	ueIP := sessInfo.UeAddr.UIp[:]
	var tmp [4]byte
	copy(tmp[:], ueIP[:4])
	return packet.ArrayToIPv4(tmp)
}

//GetSessionObj parse and extract session object
func GetSessionObj(msg []byte) (uint64, *Session) {
	obj := (*CpMsg)(unsafe.Pointer(&msg[0]))
	msgType := uint64(obj.MType)
	defer func() { //catch or finally
		if err := recover(); err != nil { //catch
			fmt.Fprintf(os.Stderr, "Exception: %v\n", err)
		}
	}()
	sl := obj.MsgUnion[:]
	sessInfo := (*CSessionInfo)(unsafe.Pointer(&sl[0]))
	session := Session{}
	session.UeIP = GetUeIP(sessInfo)
	session.UlS1Info = GetUlInfo(sessInfo)
	session.DlS1Info = GetDlInfo(sessInfo)
	return msgType, &session
}

//GetUlInfo parse uplin information  and return
func GetUlInfo(sessInfo *CSessionInfo) *UlS1Info {

	ulS1Info := UlS1Info{}
	ulS1Info.SgwTeid = uint32(sessInfo.UlS1Info.SgwTeid)

	ueIP := sessInfo.UlS1Info.EnbAddr.UIp[:]
	var tmp [4]byte
	copy(tmp[:], ueIP[:4])
	ulS1Info.EnbIP = packet.ArrayToIPv4(tmp)
	ueIP = sessInfo.UlS1Info.SgwAddr.UIp[:]
	copy(tmp[:], ueIP[:4])
	ulS1Info.SgwIP = packet.ArrayToIPv4(tmp)

	return &ulS1Info
}

//GetDlInfo parse uplin information  and return
func GetDlInfo(sessInfo *CSessionInfo) *DlS1Info {

	dlS1Info := DlS1Info{}
	dlS1Info.EnbTeid = uint32(sessInfo.DlS1Info.EnbTeid)

	uIP := sessInfo.DlS1Info.EnbAddr.UIp[:]
	var ueIP [4]byte
	copy(ueIP[:], uIP[:4])
	dlS1Info.EnbIP = SwapBytesUint32(packet.ArrayToIPv4(ueIP))
	uIP = sessInfo.DlS1Info.SgwAddr.UIp[:]
	copy(ueIP[:], uIP[:4])
	dlS1Info.SgwIP = packet.ArrayToIPv4(ueIP)

	return &dlS1Info
}

// SwapBytesUint32 swaps uint32 in Little Endian and Big Endian
func SwapBytesUint32(x uint32) uint32 {
	return ((x & 0x000000ff) << 24) | ((x & 0x0000ff00) << 8) | ((x & 0x00ff0000) >> 8) | ((x & 0xff000000) >> 24)
}
