//Package rule ...
// Copyright (c) 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package rule

import (
	"errors"
	"github.com/intel-go/nff-go/common"
)

var (
	pccFilters []PCCFilter
	adcFilters []ADCFilter
	sdfFilters []SDFFilter
)

var (
	pccSDFMap map[int][]PCCFilter
	pccADCMap map[int][]PCCFilter
)

//Init ... initial rules and prepare and install acl
func Init() {
	pccFilters = ParsePCCRules(PccRulesFilePath)
	sdfFilters = ParseSDFRules(SdfRulesFilePath)
	adcFilters = ParseADCRules(AdcRulesFilePath)
	PrepareSdfUlACL(sdfFilters)
	PrepareSdfDlACL(sdfFilters)
	PrepareAdcACL(adcFilters)
	pccSDFMap = BuildPCCSDFMap(pccFilters)
	pccADCMap = BuildPCCADCMap(pccFilters)
}

//LookUpPCCRuleBySDF ...
func LookUpPCCRuleBySDF(sdfIdx int) PCCFilter {
	pccFilters := pccSDFMap[sdfIdx]

	common.LogInfo(common.Info, "LookUpPCCRuleBySDF No of rules found : ", len(pccFilters))
	if len(pccFilters) == 0 {
		return DefaultPccFilter
	}

	return pccFilters[0]
}

//LookUpPCCRuleByADC ...
func LookUpPCCRuleByADC(adcIdx int) (PCCFilter, error) {
	var pccFilter PCCFilter
	pccFilters := pccADCMap[adcIdx]

	common.LogInfo(common.Info, "LookUpPCCRuleByADC No of rules found : ", len(pccFilters))
	if len(pccFilters) == 0 {
		return pccFilter, errors.New("No PCC rule matched ")
	}

	return pccFilters[0], nil
}
