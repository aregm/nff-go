//Package simucp ...
// Copyright (c) 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package simucp

import (
	"fmt"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"gopkg.in/ini.v1"
	"net"
	"strconv"
)

var simuCPConfigFilePath = "config/simu_cp.cfg"

//SimuConfig s11 simulator configuration structure
type SimuConfig struct {
	StartUeIP        string
	StartEnbIP       string
	StartAppServerIP string
	EnbCount         int
	FlowCount        int
	StartS1uTEID     uint32
	StartEnbTEID     uint32
}

//
//
//ENBFTEID .. ENB FTEID mapping structure TEID + IP
type ENBFTEID struct {
	TEID uint32
	IP   uint32
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
		if key == "StartS1U_TEID" {
			tmpVal, err := strconv.ParseUint(value, 10, 32)
			flow.CheckFatal(err)
			config.StartS1uTEID = uint32(tmpVal)
		} else if key == "StartUEIP" {
			config.StartUeIP = value
		} else if key == "StartENBIP" {
			config.StartEnbIP = value
		} else if key == "StartAPPServerIP" {
			config.StartAppServerIP = value
		} else if key == "ENBCount" {
			config.EnbCount, err = strconv.Atoi(value)
			flow.CheckFatal(err)

		} else if key == "FlowCount" {
			config.FlowCount, err = strconv.Atoi(value)
			flow.CheckFatal(err)

		} else if key == "StartENB_TEID" {
			tmpVal, err := strconv.ParseUint(value, 10, 32)
			flow.CheckFatal(err)
			config.StartEnbTEID = uint32(tmpVal)
		}

	}
	return config
}

//TrainDP : populate the UE Context map UL and DL
func TrainDP() (map[uint32]uint32, map[uint32]*ENBFTEID) {
	config := initConfig()
	ulMap := populateULTable(&config)
	dlMap := populateDLTable(&config)

	fmt.Println("-------------------------------")
	fmt.Println(" MAX_NUM_CS = ", config.FlowCount)
	fmt.Println(" MAX_NUM_MB = ", config.FlowCount)
	fmt.Println(" NUM_CS_SEND = ", config.FlowCount)
	fmt.Println(" NUM_MB_SEND = ", config.FlowCount)
	fmt.Println(" NUM_CS_FAILED = ", (config.FlowCount - len(ulMap)))
	fmt.Println(" NUM_MB_FAILED = ", (config.FlowCount - len(dlMap)))
	fmt.Println("-------------------------------")

	return ulMap, dlMap
}

//populateULTable
func populateULTable(config *SimuConfig) map[uint32]uint32 {
	ulMap := make(map[uint32]uint32)
	startUeIP := net.ParseIP(config.StartUeIP)
	for i := 0; i < config.FlowCount; i++ {
		ulMap[config.StartS1uTEID] = packet.StringToIPv4(common.NextIP(startUeIP, uint(i)).String())
		config.StartS1uTEID++
	}
	return ulMap
}

//populate DL map
func populateDLTable(config *SimuConfig) map[uint32]*ENBFTEID {
	dlMap := make(map[uint32]*ENBFTEID)
	startUeIP := net.ParseIP(config.StartUeIP)
	for i := 0; i < config.FlowCount; i++ {

		enbFteid := ENBFTEID{
			TEID: config.StartEnbTEID,
			IP:   packet.StringToIPv4(config.StartEnbIP),
		}
		dlMap[packet.StringToIPv4(common.NextIP(startUeIP, uint(i)).String())] = &enbFteid

		//  startENB_TEID++  //CHANGEME
	}
	return dlMap
}
