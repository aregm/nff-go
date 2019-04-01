// Copyright 2018-2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package rules

import (
	"fmt"
	"gopkg.in/ini.v1"
	"net"
	"os"
	"sort"
	"strconv"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
)

//constants for adc filter
const (
	LblNumAdcRules = "NUM_ADC_RULES"
	LblAdcRule     = "ADC_RULE"

	LblAdcType = "ADC_TYPE"
	LblIP      = "IP"
	LblPrefix  = "PREFIX"
	LblDomain  = "DOMAIN"
)

//ADCFilter ...
type ADCFilter struct {
	ADCFilterIdx int
	ADCType      int //: 1-IP, 2-IP+Prefix, 3-Domain name

	IP     string //(IP Address)
	Prefix int

	IPPrefixNW net.IPNet //lookup ease

	Domain string
}

//ParseADCRules ...
func ParseADCRules(filepath string) []ADCFilter {
	common.LogInfo(common.Info, "Loading ADC Rules...")
	cfg, err := ini.Load(filepath)
	flow.CheckFatal(err)

	noOfFilters, err := cfg.Section(LblGlobal).Key(LblNumAdcRules).Int()
	flow.CheckFatal(err)
	adcFilters := []ADCFilter{}
	for i := 1; i <= noOfFilters; i++ {
		strVal := strconv.Itoa(i)
		section := cfg.Section(LblAdcRule + "_" + strVal)
		adcFilter := ADCFilter{ADCFilterIdx: i}

		if section.HasKey(LblAdcType) {
			adcFilter.ADCType, err = section.Key(LblAdcType).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblIP) {
			adcFilter.IP = section.Key(LblIP).String()

		}
		if section.HasKey(LblPrefix) {
			adcFilter.Prefix, err = section.Key(LblPrefix).Int()
			adcFilter.IP = section.Key(LblIP).String()

			_, ipnet, err := net.ParseCIDR(adcFilter.IP + "/" + strconv.Itoa(adcFilter.Prefix))
			flow.CheckFatal(err)

			adcFilter.IPPrefixNW = *ipnet //ip-net will ease the lookup
		}
		if section.HasKey(LblDomain) {
			adcFilter.Domain = section.Key(LblDomain).String()

		}
		common.LogInfo(common.Info, "ADC filter: ", adcFilter)
		adcFilters = append(adcFilters, adcFilter)
	} //for
	return adcFilters
} //

//PrepareAdcACL ... generate  ACL from ADC rules
func PrepareAdcACL(adcFilters []ADCFilter) {

	common.LogInfo(common.Info, "Generating ADC ACL Rules...")

	//adc_filters
	dumpFile, err := os.Create(AdcACLFilePath)
	if err != nil {
		fmt.Errorf("Error while creating acl file ", err)
	}
	defer dumpFile.Close()

	for _, adcFilter := range adcFilters {

		var ipAddr string
		switch adcFilter.ADCType {
		//IP
		case 1:
			ipAddr = adcFilter.IP + "/32"
			fmt.Println(adcFilter.ADCFilterIdx, " IP ", ipAddr)
		//IP+Prefix
		case 2:
			ipAddr = adcFilter.IPPrefixNW.String()
			fmt.Println(adcFilter.ADCFilterIdx, " IP_PREFIX ", ipAddr)
		//Domain
		case 0:

			fmt.Println(adcFilter.ADCFilterIdx, " DOMAIN ", adcFilter.Domain)
			//TODO resolve domain
			continue
		}
		var aclStr string

		aclStr = fmt.Sprintf("0.0.0.0/0 %s ANY 0:65535 0:65535 %d", ipAddr, adcFilter.ADCFilterIdx)
		common.LogInfo(common.Info, aclStr)
		dumpFile.WriteString(aclStr + "\n")
		aclStr = fmt.Sprintf("%s 0.0.0.0/0 ANY 0:65535 0:65535 %d", ipAddr, adcFilter.ADCFilterIdx)
		common.LogInfo(common.Info, aclStr)
		dumpFile.WriteString(aclStr + "\n")

		dumpFile.Sync()
	}

} //

//BuildPCCADCMap ... build pcc map where key = adc index for easy lookup
func BuildPCCADCMap(pccFilters []PCCFilter) map[int][]PCCFilter {
	common.LogInfo(common.Info, "Populating PCC ADC Map ...")

	pccAdcMap := make(map[int][]PCCFilter)
	for _, pccFilter := range pccFilters {

		idx := pccFilter.ADCFilterIdx
		if idx > 0 {
			val, ok := pccAdcMap[idx]
			if ok {
				common.LogInfo(common.Info, "value exist")
				val = append(val, pccFilter)

				//sort in ascending order
				sort.Slice(val, func(i, j int) bool {
					return val[i].Precedence < val[j].Precedence
				})
				pccAdcMap[idx] = val
			} else {
				var nval []PCCFilter
				nval = append(nval, pccFilter)
				pccAdcMap[idx] = nval
			} //
		} //fi
	} //for

	for key, value := range pccAdcMap {
		common.LogInfo(common.Info, "Key = ", key, ", Value = ", value)
	} //
	return pccAdcMap
}
