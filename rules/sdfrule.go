//Package rules ...
// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package rules

import (
	"fmt"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"gopkg.in/ini.v1"
	"net"
	"os"
	"sort"
	"strconv"
)

//constants for sdf filter
const (
	LblNumSdfFilters = "NUM_SDF_FILTERS"
	LblSdfFilter     = "SDF_FILTER"

	LblDirection           = "DIRECTION"
	LblIpv4Local           = "IPV4_LOCAL"
	LblIpv4Remote          = "IPV4_REMOTE"
	LblIpv4LocalMask       = "IPV4_LOCAL_MASK"
	LblIpv4RemoteMask      = "IPV4_REMOTE_MASK"
	LblProtocol            = "PROTOCOL"
	LblLocalLowLimitPort   = "LOCAL_LOW_LIMIT_PORT"
	LblLocalHighLimitPort  = "LOCAL_HIGH_LIMIT_PORT"
	LblRemoteLowLimitPort  = "REMOTE_LOW_LIMIT_PORT"
	LblRemoteHighLimitPort = "REMOTE_HIGH_LIMIT_PORT"

	LblDirectionUl = "uplink_only"
	LblDirectionDl = "downlink_only"
	LblDirectionBi = "bidirectional"
)

//SDFFilter ...
type SDFFilter struct {
	SDFFilterIdx   int
	Direction      string //(Bidirectional, Uplink, Downlink)
	IPv4Remote     string //(IP Address)
	IPv4RemoteMask string

	IPv4RemoteNW net.IPNet //lookup ease

	IPv4Local     string //(IP Address)
	IPv4LocalMask string

	IPv4LocalNW net.IPNet //lookup ease

	Protocol            int
	RemoteLowLimitPort  int
	RemoteHighLimitPort int

	LocalLowLimitPort  int
	LocalHighLimitPort int
}

//ParseSDFRules ...
func ParseSDFRules(filepath string) []SDFFilter {
	common.LogInfo(common.Info, "Loading SDF Rules...")
	cfg, err := ini.Load(filepath)
	flow.CheckFatal(err)

	noOfFilters, err := cfg.Section(LblGlobal).Key(LblNumSdfFilters).Int()
	flow.CheckFatal(err)
	sdfFilters := []SDFFilter{}
	for i := 1; i <= noOfFilters; i++ {
		strVal := strconv.Itoa(i)
		section := cfg.Section(LblSdfFilter + "_" + strVal)
		sdfFilter := SDFFilter{SDFFilterIdx: i}

		sdfFilter.LocalHighLimitPort = 65535
		sdfFilter.LocalLowLimitPort = 0
		sdfFilter.RemoteHighLimitPort = 65535
		sdfFilter.RemoteLowLimitPort = 0

		if section.HasKey(LblDirection) {
			sdfFilter.Direction = section.Key(LblDirection).String()

		}

		// TODO remove these fields IPV4_REMOTE/IPV4_REMOTE_MASK instead use IPV4_REMOTE_NW
		if section.HasKey(LblIpv4Local) {
			sdfFilter.IPv4Local = section.Key(LblIpv4Local).String()

		}
		if section.HasKey(LblIpv4LocalMask) {
			sdfFilter.IPv4LocalMask = section.Key(LblIpv4LocalMask).String()
		}
		//--end
		if section.HasKey(LblIpv4Local) && section.HasKey(LblIpv4LocalMask) {
			ip := net.ParseIP(section.Key(LblIpv4Local).String())
			mask := net.IPMask(net.ParseIP(section.Key(LblIpv4LocalMask).String()))
			sdfFilter.IPv4LocalNW = net.IPNet{IP: ip, Mask: mask}
		}
		//using IPNet will ease look of ip
		if section.HasKey(LblIpv4Remote) {
			sdfFilter.IPv4Remote = section.Key(LblIpv4Remote).String()

		}
		if section.HasKey(LblIpv4RemoteMask) {
			sdfFilter.IPv4RemoteMask = section.Key(LblIpv4RemoteMask).String()

		}
		//--end
		if section.HasKey(LblIpv4Remote) && section.HasKey(LblIpv4RemoteMask) {
			ip := net.ParseIP(section.Key(LblIpv4Remote).String())
			mask := net.IPMask(net.ParseIP(section.Key(LblIpv4RemoteMask).String()))
			sdfFilter.IPv4RemoteNW = net.IPNet{IP: ip, Mask: mask}
		}
		if section.HasKey(LblProtocol) {
			sdfFilter.Protocol, err = section.Key(LblProtocol).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblRemoteLowLimitPort) {
			sdfFilter.RemoteLowLimitPort, err = section.Key(LblRemoteLowLimitPort).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblRemoteHighLimitPort) {
			sdfFilter.RemoteHighLimitPort, err = section.Key(LblRemoteHighLimitPort).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblLocalLowLimitPort) {
			sdfFilter.LocalLowLimitPort, err = section.Key(LblLocalLowLimitPort).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblLocalHighLimitPort) {
			sdfFilter.LocalHighLimitPort, err = section.Key(LblLocalHighLimitPort).Int()
			flow.CheckFatal(err)
		}

		common.LogInfo(common.Info, "SDF filter: ", sdfFilter)
		sdfFilters = append(sdfFilters, sdfFilter)
	} //for
	return sdfFilters
} //

//PrepareSdfUlACL ... generate ACLs from SDF rules
func PrepareSdfUlACL(sdfFilters []SDFFilter) {

	common.LogInfo(common.Info, "Generating ACL Rules...")

	dumpFile, err := os.Create(SdfUlACLFilePath)
	if err != nil {
		fmt.Errorf("Error while creating acl file ", err)
		os.Exit(1)
	}
	defer dumpFile.Close()

	for _, sdfFilter := range sdfFilters {

		if sdfFilter.Direction == LblDirectionUl || sdfFilter.Direction == LblDirectionBi {
			ipAddrLocal := sdfFilter.IPv4LocalNW.String()
			if ipAddrLocal == "<nil>" {
				ipAddrLocal = "ANY"
			}
			ipAddr := sdfFilter.IPv4RemoteNW.String()
			if ipAddr == "<nil>" {
				ipAddr = "ANY"
			}
			aclStr := fmt.Sprintf("%s %s %d %d:%d %d:%d %d", ipAddrLocal, ipAddr, sdfFilter.Protocol,
				sdfFilter.LocalLowLimitPort, sdfFilter.LocalHighLimitPort, sdfFilter.RemoteLowLimitPort,
				sdfFilter.RemoteHighLimitPort, sdfFilter.SDFFilterIdx)
			fmt.Println("Installing  ", sdfFilter.Direction, " ACL : ", aclStr)
			common.LogInfo(common.Info, "Installing  ", sdfFilter.Direction, " ACL : ", aclStr)
			dumpFile.WriteString(aclStr + "\n")
			dumpFile.Sync()
		}
	} //

} //

//PrepareSdfDlACL generate ACL from SDF rules
func PrepareSdfDlACL(sdfFilters []SDFFilter) {

	common.LogInfo(common.Info, "Generating ACL Rules...")

	dumpFile, err := os.Create(SdfDlACLFilePath)
	if err != nil {
		fmt.Errorf("Error while creating acl file ", err)
	}
	defer dumpFile.Close()

	for _, sdfFilter := range sdfFilters {

		common.LogInfo(common.Info, sdfFilter.Direction)
		if sdfFilter.Direction == LblDirectionDl || sdfFilter.Direction == LblDirectionBi {
			ipAddrLocal := sdfFilter.IPv4LocalNW.String()
			if ipAddrLocal == "<nil>" {
				ipAddrLocal = "ANY"
			}
			ipAddr := sdfFilter.IPv4RemoteNW.String()
			if ipAddr == "<nil>" {
				ipAddr = "ANY"
			}
			aclStr := fmt.Sprintf("%s %s %d %d:%d %d:%d %d", ipAddr, ipAddrLocal, sdfFilter.Protocol,
				sdfFilter.LocalLowLimitPort, sdfFilter.LocalHighLimitPort, sdfFilter.RemoteLowLimitPort,
				sdfFilter.RemoteHighLimitPort, sdfFilter.SDFFilterIdx)
			fmt.Println("Installing  ", sdfFilter.Direction, " ACL : ", aclStr)
			common.LogInfo(common.Info, "Installing  ", sdfFilter.Direction, " ACL : ", aclStr)
			dumpFile.WriteString(aclStr + "\n")
			dumpFile.Sync()
		}
	}

} //

//BuildPCCSDFMap ... prepare a map with key as sdf index and value as pcc rule
func BuildPCCSDFMap(pccFilters []PCCFilter) map[int][]PCCFilter {
	common.LogInfo(common.Info, " Populating PCC SDF Map ...")

	pccSdfMap := make(map[int][]PCCFilter)
	for _, pccFilter := range pccFilters {
		for _, idx := range pccFilter.SDFFilterIdx {
			val, ok := pccSdfMap[idx]
			if ok {
				common.LogInfo(common.Info, "value exist")
				val = append(val, pccFilter)

				//sort in ascending order
				sort.Slice(val, func(i, j int) bool {
					return val[i].Precedence < val[j].Precedence
				})
				pccSdfMap[idx] = val

			} else {
				var nval []PCCFilter
				nval = append(nval, pccFilter)
				pccSdfMap[idx] = nval
			} //

		} //for
	} //for

	for key, value := range pccSdfMap {
		common.LogInfo(common.Info, "Key = ", key, ", Value = ", value)
	} //
	return pccSdfMap
}
