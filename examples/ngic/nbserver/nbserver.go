// Copyright 2018-2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// NB API interface over UDP(Port 20) providing following
// CreateSession --create ue session
// UpdateSession --modify bearer
// DeleteSession --delete ue session
//
package nbserver

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

//UlMap and DlMap stores the UE context
var (
	UlMap = New(128)
	DlMap = New(128)
)

//Start NB API server
func Start() {
}

//CreateSession API
func CreateSession(in *Session) error {
	if ok := UlMap.StoreIfAbsent(packet.SwapBytesUint32(in.UlS1Info.SgwTeid), *in); !ok {
		common.LogError(common.No, "Create session: SgwTeid", strconv.FormatInt(int64(in.UlS1Info.SgwTeid), 16),
			", Int ip = ", in.UeIP)
		return errors.New("Session exists for UE Ip: " + types.IPv4Address(packet.SwapBytesUint32(in.UeIP)).String())
	}
	common.LogDebug(common.Debug, "Create session: SgwTeid", strconv.FormatInt(int64(in.UlS1Info.SgwTeid), 16),
		", Int ip = ", types.IPv4Address(packet.SwapBytesUint32(in.UeIP)).String())
	return nil
}

//UpdateSession API
func UpdateSession(in *Session) error {
	if ok := UlMap.Has(packet.SwapBytesUint32(in.UlS1Info.SgwTeid)); ok {
		common.LogDebug(common.Debug, "Modify session: SgwTeid ", strconv.FormatInt(int64(in.UlS1Info.SgwTeid), 16),
			", Int ip = ", types.IPv4Address(packet.SwapBytesUint32(in.UeIP)).String())
		DlMap.Store(packet.SwapBytesUint32(in.UeIP), *in)
		return nil
	}
	common.LogError(common.No, " modify session not found : ", strconv.FormatInt(int64(in.UlS1Info.SgwTeid), 16),
		", Int ip = ", types.IPv4Address(packet.SwapBytesUint32(in.UeIP)).String())
	return errors.New("Session doesn't exist for UE Ip: " + types.IPv4Address(packet.SwapBytesUint32(in.UeIP)).String())
}

var isPrinted = true

//DeleteSession API
func DeleteSession(in *Session) error {
	if isPrinted {
		fmt.Println("UL Entry count ", UlMap.Count())
		fmt.Println("DL Entry count ", DlMap.Count())
		//		isPrinted = false
	}
	UlKey := in.UlS1Info.SgwTeid
	if ok := UlMap.Has(UlKey); ok {
		UlMap.Delete(UlKey)
		DlMap.Delete(packet.SwapBytesUint32(in.UeIP))
		return nil
	}
	common.LogError(common.Debug, "delete session not found for ", types.IPv4Address(packet.SwapBytesUint32(in.UeIP)).String())
	return errors.New("Session doesn't exist for UE Ip: " + types.IPv4Address(packet.SwapBytesUint32(in.UeIP)).String())
}
