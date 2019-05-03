//Package nbserver ...
// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// NB API interface over UDP(Port 20) providing following
// CreateSession --create ue session
// UpdateSession --modify bearer
// DeleteSession --delere ue session
//
package nbserver

import (
	"errors"
	"fmt"
	"github.com/golang-collections/go-datastructures/queue"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	"net"
	"os"
	"strconv"
	"sync"
	"unsafe"
)

//UlMap and DlMap stores the UE context
var (
	UlMap = New(128)
	DlMap = New(128)
)

const (
	maxQueueSize = 1000 //1000 TPS
)

type message struct {
	msg    []byte
	length int
}

// NB worker currently 1 client only
var nbWorkers = 1

//pool buffer
var bufferPool sync.Pool

//msg procesing queue
var mq = queue.New(maxQueueSize)

//process message from the queue
func processMsgFromQueue() {
	for {
		items, err := mq.Get(100)
		if err == nil {
			for _, item := range items {
				m := item.(message)
				handleMessage(m.msg[0:m.length])
				bufferPool.Put(m.msg)
			}
		}
	}
}

//CheckError A Simple function to verify error
func CheckError(err error) {
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(0)
	}
}

//Start NB API server
func Start() {
	structSize := int(unsafe.Sizeof(CpMsg{}))
	bufferPool = sync.Pool{
		New: func() interface{} { return make([]byte, structSize) },
	}
	listenAndReceive(nbWorkers)
}

//Start udp servr and listen for Session requests
func listenAndReceive(maxWorkers int) error {
	sAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:20")
	CheckError(err)
	c, err := net.ListenUDP("udp", sAddr)
	CheckError(err)
	//	c.SetReadBuffer(1048576)
	fmt.Println("NB Server listening on ", c.LocalAddr().String())
	for i := 0; i < maxWorkers; i++ {
		go processMsgFromQueue()
		go receiveCon(c)
	}
	return nil
}

// receiveCon accepts incoming datagrams on c and calls handleMessage() for each message
func receiveCon(con *net.UDPConn) {
	defer con.Close()

	for {
		msg := bufferPool.Get().([]byte)
		nbytes, err := con.Read(msg[0:])
		if err != nil {
			fmt.Printf("Error %s", err)
			continue
		}
		mq.Put(message{msg, nbytes})
	}
}

//request handler
func handleMessage(msg []byte) {
	msgType, session := GetSessionObj(msg)

	switch msgType {

	case MsgSessCRE:
		CreateSession(session)
	case MsgSessMOD:
		UpdateSession(session)
	case MsgSessDEL:
		DeleteSession(session)

	}

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
