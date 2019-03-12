//Package simucp ...
// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// CP Simulator to establish the UE session
// config file : config/simu_cp.cfg
//
package simucp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"time"

	"gopkg.in/ini.v1"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/examples/ngic/nbserver"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

var simuCPConfigFilePath = "config/simu_cp.cfg"
var s1uSpgwGtpuTeidOffset uint32

//SimuConfig s11 simulator configuration structure
type SimuConfig struct {
	s1uSgwIP       string
	ueIPStart      string
	eNBIPStart     string
	ueIPStartRange string
	asIPStart      string
	maxUESessCount int
	tps            int
	breakDuration  int
	defaultBearer  int
	maxUERanCount  int
	maxENBRANCount int
	startS1uTEID   uint32
	startEnbTEID   uint32
}

//
// Method : initialize the simu configuration
//
func initConfig() SimuConfig {
	config := SimuConfig{}
	cfg, err := ini.Load(simuCPConfigFilePath)
	flow.CheckFatal(err)

	for key, value := range cfg.Section("0").KeysHash() {
		common.LogInfo(common.Info, key, "=", value)
		if key == "S1U_SGW_IP" {
			config.s1uSgwIP = value
		} else if key == "ENODEB_IP_START" {
			config.eNBIPStart = value
		} else if key == "UE_IP_START" {
			config.ueIPStart = value
		} else if key == "UE_IP_START_RANGE" {
			config.ueIPStartRange = value
		} else if key == "AS_IP_START" {
			config.asIPStart = value
		} else if key == "MAX_UE_SESS" {
			config.maxUESessCount, err = strconv.Atoi(value)
			flow.CheckFatal(err)
		} else if key == "TPS" {
			config.tps, err = strconv.Atoi(value)
			flow.CheckFatal(err)
		} else if key == "BREAK_DURATION" {
			config.breakDuration, err = strconv.Atoi(value)
			flow.CheckFatal(err)
		} else if key == "DEFAULTBEARER" {
			config.defaultBearer, err = strconv.Atoi(value)
			flow.CheckFatal(err)
		} else if key == "MAX_UE_RAN" {
			config.maxUERanCount, err = strconv.Atoi(value)
			flow.CheckFatal(err)
		} else if key == "MAX_ENB_RAN" {
			config.maxENBRANCount, err = strconv.Atoi(value)
			flow.CheckFatal(err)
		} else if key == "StartS1U_TEID" {
			newValue, err := strconv.ParseUint(value, 10, 32)
			flow.CheckFatal(err)
			config.startS1uTEID = uint32(newValue)
		} else if key == "StartENB_TEID" {
			newValue, err := strconv.ParseUint(value, 10, 32)
			flow.CheckFatal(err)
			config.startEnbTEID = uint32(newValue)
		}

	}
	return config
}

//TrainDP : populate the UE Context map UL and DL
func TrainDP() {
	config := initConfig()

	processCreateModifySession(config)

	fmt.Println("-------------------------------")
	fmt.Println(" MAX_NUM_CS = ", config.maxUESessCount)
	fmt.Println(" MAX_NUM_MB = ", config.maxUESessCount)
	fmt.Println(" NUM_CS_SEND = ", config.maxUESessCount)
	fmt.Println(" NUM_MB_SEND = ", config.maxUESessCount)
	fmt.Println(" NUM_CS_FAILED = ", (config.maxUESessCount - nbserver.UlMap.Count()))
	fmt.Println(" NUM_MB_FAILED = ", (config.maxUESessCount - nbserver.DlMap.Count()))
	fmt.Println("-------------------------------")

}

/* Generate unique eNB teid. */

func generateEnbTeid(ueIdx int, maxUeRan int, maxEnbRan int,
	teid *uint32, enbIdx *uint32) int32 {
	var ran int
	var enb uint32
	var enbOfRan int
	var ueOfRan int
	var ueTeid uint32
	var sessionIdx uint32

	if maxUeRan == 0 || maxEnbRan == 0 {
		return -1 /* need to have at least one of each */
	}
	ueOfRan = ueIdx % maxUeRan
	ran = ueIdx / maxUeRan
	enbOfRan = ueOfRan % maxEnbRan
	enb = uint32(ran*maxEnbRan + enbOfRan)

	ueTeid = uint32(ueOfRan + maxUeRan*int(sessionIdx) + 1)

	*teid = ueTeid
	*enbIdx = enb

	return 0
}

func generateTeid(startS1uTeid uint32, teid *uint32) {
	*teid = startS1uTeid + s1uSpgwGtpuTeidOffset
	s1uSpgwGtpuTeidOffset++
}

//populateULTable
func processCreateModifySession(config SimuConfig) {

	startUeIP := net.ParseIP(config.ueIPStart)
	var s1uTeid uint32
	var enbTeid uint32
	var enbIPIdx uint32
	ticker := time.NewTicker(time.Second)
	var tps = config.tps
	var count int

	for range ticker.C {

		for i := 0; i < config.maxUESessCount; i++ {

			session := new(nbserver.Session)

			session.UeIP = Ip2int(startUeIP) + uint32(count)

			/*generate teid for each create session */
			generateTeid(config.startS1uTEID, &s1uTeid)
			generateEnbTeid(i, config.maxUERanCount, config.maxENBRANCount,
				&enbTeid, &enbIPIdx)

			uls1Info := new(nbserver.UlS1Info)
			uls1Info.SgwTeid = s1uTeid
			uls1Info.SgwIP = Ip2int(net.ParseIP(config.s1uSgwIP))

			session.UlS1Info = uls1Info

			nbserver.CreateSession(session)

			dls1Info := new(nbserver.DlS1Info)
			dls1Info.SgwIP = Ip2int(net.ParseIP(config.s1uSgwIP))
			dls1Info.EnbTeid = enbTeid
			dls1Info.EnbIP = packet.SwapBytesUint32(Ip2int(net.ParseIP(config.eNBIPStart)) + enbIPIdx)

			session.DlS1Info = dls1Info

			nbserver.UpdateSession(session)
			count++
			if count == tps {
				tps = tps + config.tps
				break
			}

		}
		if config.maxUESessCount == count {
			break
		}
	}
}

// Ip2int convert IPv4 address to int
func Ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}
