// Copyright 2018-2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package rules

import (
	"gopkg.in/ini.v1"
	"strconv"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
)

// constants for pcc filter
const (
	LblNumPccFilters = "NUM_PCC_FILTERS"
	LblPccFilter     = "PCC_FILTER"

	LblUlAmbrMtrProfileIdx = "UL_AMBR_MTR_PROFILE_IDX"
	LblDlAmbrMtrProfileIdx = "DL_AMBR_MTR_PROFILE_IDX"
	LblReportLevel         = "REPORT_LEVEL"
	LblPrecedence          = "PRECEDENCE"
	LblRulename            = "RULE_NAME"
	LblRatingGroup         = "RATING_GROUP"
	LblServiceID           = "SERVICE_ID"
	LblRuleStatus          = "RULE_STATUS"
	LblChargingMode        = "CHARGING_MODE"
	LblGateSatus           = "GATE_STATUS"
	LblMeteringMethod      = "METERING_METHOD"
	LblMuleNotify          = "MUTE_NOTIFY"
	LblMonitoringKey       = "MONITORING_KEY"
	LblSponsorID           = "SPONSOR_ID"
	LblRedirectInfo        = "REDIRECT_INFO"
	LblSessionCont         = "SESSION_CONT"
	LblDropPktCount        = "DROP_PKT_COUNT"
	LblSdfFilterIdx        = "SDF_FILTER_IDX"
	LblAdcFilterIdx        = "ADC_FILTER_IDX"
)

//PCCFilter ...
type PCCFilter struct {
	PCCFilterIdx       int
	RuleName           string
	RatingGroup        int
	ServiceID          string //int
	RuleStatus         int
	GateStatus         int //1-Accept, 0-Drop
	SessionCont        int
	ReportLevel        int
	ChargingMode       int
	MeteringMethod     int
	MuteNotify         int
	MonitoringKey      int
	SponsorID          string //int
	RedirectInfo       int
	Precedence         int //(0-255, 255 is lowest)
	DropPktCount       int
	UlMbrMtrProfileIdx int //- Specify the meter profile index from meter_profile.cfg
	DlMbrMtrProfileIdx int
	SDFFilterIdx       []int
	ADCFilterIdx       int
}

//DefaultPccFilter ... default pcc rule all all traffic
var DefaultPccFilter = PCCFilter{
	PCCFilterIdx: 0,
	Precedence:   255,
	GateStatus:   1,
}

//ParsePCCRules ...
func ParsePCCRules(filepath string) []PCCFilter {
	common.LogInfo(common.Info, "Loading PCC Rules...")
	var pccFilters []PCCFilter
	cfg, err := ini.Load(filepath)
	flow.CheckFatal(err)

	noOfFilters, err := cfg.Section(LblGlobal).Key(LblNumPccFilters).Int()
	flow.CheckFatal(err)

	for i := 1; i <= noOfFilters; i++ {
		strVal := strconv.Itoa(i)

		section := cfg.Section(LblPccFilter + "_" + strVal)
		pccFilter := PCCFilter{PCCFilterIdx: i}

		if section.HasKey(LblUlAmbrMtrProfileIdx) {
			pccFilter.UlMbrMtrProfileIdx, err = section.Key(LblUlAmbrMtrProfileIdx).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblDlAmbrMtrProfileIdx) {
			pccFilter.DlMbrMtrProfileIdx, err = section.Key(LblDlAmbrMtrProfileIdx).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblReportLevel) {
			pccFilter.ReportLevel, err = section.Key(LblReportLevel).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblPrecedence) {
			pccFilter.Precedence, err = section.Key(LblPrecedence).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblRulename) {
			pccFilter.RuleName = section.Key(LblRulename).String()

		}
		if section.HasKey(LblRatingGroup) {

			strRg := section.Key(LblRatingGroup).String()
			pccFilter.RatingGroup = 0
			if strRg != "Zero-Rate" {
				pccFilter.RatingGroup, err = strconv.Atoi(strRg)
				flow.CheckFatal(err)
			}
		}
		if section.HasKey(LblServiceID) {
			pccFilter.ServiceID = section.Key(LblServiceID).String()
		}
		if section.HasKey(LblRuleStatus) {
			pccFilter.RuleStatus, err = section.Key(LblRuleStatus).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblChargingMode) {
			pccFilter.ChargingMode, err = section.Key(LblChargingMode).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblGateSatus) {
			pccFilter.GateStatus, err = section.Key(LblGateSatus).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblMeteringMethod) {
			pccFilter.MeteringMethod, err = section.Key(LblMeteringMethod).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblMuleNotify) {
			pccFilter.MuteNotify, err = section.Key(LblMuleNotify).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblMonitoringKey) {
			pccFilter.MonitoringKey, err = section.Key(LblMonitoringKey).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblSponsorID) {
			pccFilter.SponsorID = section.Key(LblSponsorID).String()
		}
		if section.HasKey(LblRedirectInfo) {
			pccFilter.RedirectInfo, err = section.Key(LblRedirectInfo).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblSessionCont) {
			pccFilter.SessionCont, err = section.Key(LblSessionCont).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblDropPktCount) {
			pccFilter.DropPktCount, err = section.Key(LblDropPktCount).Int()
			flow.CheckFatal(err)
		}
		if section.HasKey(LblSdfFilterIdx) {
			pccFilter.SDFFilterIdx = section.Key(LblSdfFilterIdx).Ints(",")

		}
		if section.HasKey(LblAdcFilterIdx) {
			pccFilter.ADCFilterIdx, err = section.Key(LblAdcFilterIdx).Int()
			flow.CheckFatal(err)
		}

		common.LogInfo(common.Info, "PCC filter: ", pccFilter)
		pccFilters = append(pccFilters, pccFilter)
	} //for
	return pccFilters
}
