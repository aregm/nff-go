//Package rules ...
// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package rules

import (
	"errors"
	"github.com/intel-go/nff-go/common"
)

//constants globals
const (
	LblGlobal = "GLOBAL"
)

//generated ACLs file path
var (
	SdfUlACLFilePath = "/tmp/sdf_ul_acl.cfg"
	SdfDlACLFilePath = "/tmp/sdf_dl_acl.cfg"
	AdcACLFilePath   = "/tmp/adc_acl.cfg"
)

var (
	pccSDFMap map[int][]PCCFilter
	pccADCMap map[int][]PCCFilter
)

//LookUpPCCRuleBySDF ...
func LookUpPCCRuleBySDF(sdfIdx int) PCCFilter {
	pccFilters := pccSDFMap[sdfIdx]

	common.LogInfo(common.Debug, "LookUpPCCRuleBySDF No of rules for index", sdfIdx, " found : ", len(pccFilters))
	if len(pccFilters) == 0 {
		return DefaultPccFilter
	}

	return pccFilters[0]
}

//LookUpPCCRuleByADC ...
func LookUpPCCRuleByADC(adcIdx int) (PCCFilter, error) {
	var pccFilter PCCFilter
	pccFilters := pccADCMap[adcIdx]

	common.LogInfo(common.Debug, "LookUpPCCRuleByADC No of rules for index", adcIdx, " found : ", len(pccFilters))
	if len(pccFilters) == 0 {
		return pccFilter, errors.New("No PCC rule matched ")
	}

	return pccFilters[0], nil
}
