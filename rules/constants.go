//Package rules ...
// Copyright (c) 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package rules

// constants for rule file paths
const (
	PccRulesFilePath = "config/pcc_rules.cfg"
	SdfRulesFilePath = "config/sdf_rules.cfg"
	AdcRulesFilePath = "config/adc_rules.cfg"
	SdfUlACLFilePath = "/tmp/sdf_ul_acl.cfg"
	SdfDlACLFilePath = "/tmp/sdf_dl_acl.cfg"
	AdcACLFilePath   = "/tmp/adc_acl.cfg"
)

//constants globals
const (
	LblGlobal = "GLOBAL"
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

//constants for adc filter
const (
	LblNumAdcRules = "NUM_ADC_RULES"
	LblAdcRule     = "ADC_RULE"

	LblAdcType = "ADC_TYPE"
	LblIP      = "IP"
	LblPrefix  = "PREFIX"
	LblDomain  = "DOMAIN"
)
