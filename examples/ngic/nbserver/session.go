// Copyright 2018-2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//Package nbserver Defines struccture mapping for ngic CP C struture
// to avoid UDP pkt parsing
package nbserver

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
