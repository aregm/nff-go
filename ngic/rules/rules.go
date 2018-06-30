package rules

import (
	"errors"
	"fmt"
	"github.com/intel-go/nff-go/ngic/utils"
	"gopkg.in/ini.v1"
	"net"
	"os"
	"sort"
	"strconv"
)

//PCC filter
type PCC_FILTER struct {
	PCC_FILTER_IDX         int
	RULE_NAME              string
	RATING_GROUP           int
	SERVICE_ID             string //int
	RULE_STATUS            int
	GATE_STATUS            int //1-Accept, 0-Drop
	SESSION_CONT           int
	REPORT_LEVEL           int
	CHARGING_MODE          int
	METERING_METHOD        int
	MUTE_NOTIFY            int
	MONITORING_KEY         int
	SPONSOR_ID             string //int
	REDIRECT_INFO          int
	PRECEDENCE             int //(0-255, 255 is lowest)
	DROP_PKT_COUNT         int
	UL_MBR_MTR_PROFILE_IDX int //- Specify the meter profile index from meter_profile.cfg
	DL_MBR_MTR_PROFILE_IDX int
	SDF_FILTER_IDX         []int
	ADC_FILTER_IDX         int
}

//SDF filter
type SDF_FILTER struct {
	SDF_FILTER_IDX   int
	DIRECTION        string //(Bidirectional, Uplink, Downlink)
	IPV4_REMOTE      string //(IP Address)
	IPV4_REMOTE_MASK string

	IPV4_REMOTE_NW net.IPNet //lookup ease

	IPV4_LOCAL      string //(IP Address)
	IPV4_LOCAL_MASK string

	IPV4_LOCAL_NW net.IPNet //lookup ease

	PROTOCOL               int
	REMOTE_LOW_LIMIT_PORT  int
	REMOTE_HIGH_LIMIT_PORT int

	LOCAL_LOW_LIMIT_PORT  int
	LOCAL_HIGH_LIMIT_PORT int
}

// ADC filter
type ADC_FILTER struct {
	ADC_FILTER_IDX int
	ADC_TYPE       int //: 1-IP, 2-IP+Prefix, 3-Domain name

	IP     string //(IP Address)
	PREFIX int

	IP_PREFIX_NW net.IPNet //lookup ease

	DOMAIN string
}

var pcc_filters []PCC_FILTER
var adc_filters []ADC_FILTER
var sdf_filters []SDF_FILTER

// map , key = sdf_index , value = sort list of pcc rules on precedence
var pcc_sdf_map map[int][]PCC_FILTER

func buildPCCSDFMap() {
	utils.LogInfo(utils.Info, " Populating PCC SDF Map ...")

	pcc_sdf_map = make(map[int][]PCC_FILTER)
	for _, pcc_filter := range pcc_filters {
		for _, idx := range pcc_filter.SDF_FILTER_IDX {
			val, ok := pcc_sdf_map[idx]
			if ok {
				utils.LogDebug(utils.Debug, "value exist")
				val = append(val, pcc_filter)

				//sort in ascending order
				sort.Slice(val, func(i, j int) bool {
					return val[i].PRECEDENCE < val[j].PRECEDENCE
				})
				pcc_sdf_map[idx] = val

			} else {
				var nval []PCC_FILTER
				nval = append(nval, pcc_filter)
				pcc_sdf_map[idx] = nval
			} //

		} //for
	} //for

	for key, value := range pcc_sdf_map {
		utils.LogDebug(utils.Debug, "Key = ", key, ", Value = ", value)
	} //
}

var pcc_adc_map map[int][]PCC_FILTER

//
// Method : Build PCC ADC Map for key = <ADC idx> and value = List <PCC>
//
func buildPCCADCMap() {
	utils.LogInfo(utils.Info, "Populating PCC ADC Map ...")

	pcc_adc_map = make(map[int][]PCC_FILTER)
	for _, pcc_filter := range pcc_filters {

		idx := pcc_filter.ADC_FILTER_IDX
		if idx > 0 {
			val, ok := pcc_adc_map[idx]
			if ok {
				utils.LogDebug(utils.Debug, "value exist")
				val = append(val, pcc_filter)

				//sort in ascending order
				sort.Slice(val, func(i, j int) bool {
					return val[i].PRECEDENCE < val[j].PRECEDENCE
				})
				pcc_adc_map[idx] = val
			} else {
				var nval []PCC_FILTER
				nval = append(nval, pcc_filter)
				pcc_adc_map[idx] = nval
			} //
		} //fi
	} //for

	for key, value := range pcc_adc_map {
		utils.LogDebug(utils.Debug, "Key = ", key, ", Value = ", value)
	} //
}

//
// Method: Parsse PCC rules
//
func parsePCCRules(filepath string) {
	utils.LogInfo(utils.Info, "Loading PCC Rules...")
	cfg, err := ini.Load(filepath)
	utils.CheckFatal(err)

	no_of_filters, err := cfg.Section(GLOBAL).Key(NUM_PCC_FILTERS).Int()
	utils.CheckFatal(err)

	for i := 1; i <= no_of_filters; i++ {
		strVal := strconv.Itoa(i)

		section := cfg.Section(STR_PCC_FILTER + "_" + strVal)
		pcc_filter := PCC_FILTER{PCC_FILTER_IDX: i}

		if section.HasKey(UL_AMBR_MTR_PROFILE_IDX) {
			pcc_filter.UL_MBR_MTR_PROFILE_IDX, err = section.Key(UL_AMBR_MTR_PROFILE_IDX).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(DL_AMBR_MTR_PROFILE_IDX) {
			pcc_filter.DL_MBR_MTR_PROFILE_IDX, err = section.Key(DL_AMBR_MTR_PROFILE_IDX).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(REPORT_LEVEL) {
			pcc_filter.REPORT_LEVEL, err = section.Key(REPORT_LEVEL).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(PRECEDENCE) {
			pcc_filter.PRECEDENCE, err = section.Key(PRECEDENCE).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(RULE_NAME) {
			pcc_filter.RULE_NAME = section.Key(RULE_NAME).String()

		}
		if section.HasKey(RATING_GROUP) {

			str_rg := section.Key(RATING_GROUP).String()
			if str_rg == "Zero-Rate" {
				pcc_filter.RATING_GROUP = 0
			} else {
				pcc_filter.RATING_GROUP, err = strconv.Atoi(str_rg)
				utils.CheckFatal(err)
			}
		}
		if section.HasKey(SERVICE_ID) {
			pcc_filter.SERVICE_ID = section.Key(SERVICE_ID).String()
		}
		if section.HasKey(RULE_STATUS) {
			pcc_filter.RULE_STATUS, err = section.Key(RULE_STATUS).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(CHARGING_MODE) {
			pcc_filter.CHARGING_MODE, err = section.Key(CHARGING_MODE).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(GATE_STATUS) {
			pcc_filter.GATE_STATUS, err = section.Key(GATE_STATUS).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(METERING_METHOD) {
			pcc_filter.METERING_METHOD, err = section.Key(METERING_METHOD).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(MUTE_NOTIFY) {
			pcc_filter.MUTE_NOTIFY, err = section.Key(MUTE_NOTIFY).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(MONITORING_KEY) {
			pcc_filter.MONITORING_KEY, err = section.Key(MONITORING_KEY).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(SPONSOR_ID) {
			pcc_filter.SPONSOR_ID = section.Key(SPONSOR_ID).String()
		}
		if section.HasKey(REDIRECT_INFO) {
			pcc_filter.REDIRECT_INFO, err = section.Key(REDIRECT_INFO).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(SESSION_CONT) {
			pcc_filter.SESSION_CONT, err = section.Key(SESSION_CONT).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(DROP_PKT_COUNT) {
			pcc_filter.DROP_PKT_COUNT, err = section.Key(DROP_PKT_COUNT).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(SDF_FILTER_IDX) {
			pcc_filter.SDF_FILTER_IDX = section.Key(SDF_FILTER_IDX).Ints(",")

		}
		if section.HasKey(ADC_FILTER_IDX) {
			pcc_filter.ADC_FILTER_IDX, err = section.Key(ADC_FILTER_IDX).Int()
			utils.CheckFatal(err)
		}

		utils.LogDebug(utils.Debug, "PCC filter: ", pcc_filter)
		pcc_filters = append(pcc_filters, pcc_filter)
	} //for

}

//
// Method : Parse SDF rules
//
func parseSDFRules(filepath string) {
	utils.LogInfo(utils.Info, "Loading SDF Rules...")
	cfg, err := ini.Load(filepath)
	utils.CheckFatal(err)

	no_of_filters, err := cfg.Section(GLOBAL).Key(NUM_SDF_FILTERS).Int()
	utils.CheckFatal(err)

	for i := 1; i <= no_of_filters; i++ {
		strVal := strconv.Itoa(i)
		section := cfg.Section(STR_SDF_FILTER + "_" + strVal)
		sdf_filter := SDF_FILTER{SDF_FILTER_IDX: i}

		sdf_filter.LOCAL_HIGH_LIMIT_PORT = 65535
		sdf_filter.LOCAL_LOW_LIMIT_PORT = 0
		sdf_filter.REMOTE_HIGH_LIMIT_PORT = 65535
		sdf_filter.REMOTE_LOW_LIMIT_PORT = 0

		if section.HasKey(DIRECTION) {
			sdf_filter.DIRECTION = section.Key(DIRECTION).String()

		}

		// TODO remove these fields IPV4_REMOTE/IPV4_REMOTE_MASK instead use IPV4_REMOTE_NW
		if section.HasKey(IPV4_LOCAL) {
			sdf_filter.IPV4_LOCAL = section.Key(IPV4_LOCAL).String()

		}
		if section.HasKey(IPV4_LOCAL_MASK) {
			sdf_filter.IPV4_LOCAL_MASK = section.Key(IPV4_LOCAL_MASK).String()
		}
		//--end
		if section.HasKey(IPV4_LOCAL) && section.HasKey(IPV4_LOCAL_MASK) {
			ip := net.ParseIP(section.Key(IPV4_LOCAL).String())
			mask := net.IPMask(net.ParseIP(section.Key(IPV4_LOCAL_MASK).String()))
			sdf_filter.IPV4_LOCAL_NW = net.IPNet{IP: ip, Mask: mask}
		}
		//using IPNet will ease look of ip
		if section.HasKey(IPV4_REMOTE) {
			sdf_filter.IPV4_REMOTE = section.Key(IPV4_REMOTE).String()

		}
		if section.HasKey(IPV4_REMOTE_MASK) {
			sdf_filter.IPV4_REMOTE_MASK = section.Key(IPV4_REMOTE_MASK).String()

		}
		//--end
		if section.HasKey(IPV4_REMOTE) && section.HasKey(IPV4_REMOTE_MASK) {
			ip := net.ParseIP(section.Key(IPV4_REMOTE).String())
			mask := net.IPMask(net.ParseIP(section.Key(IPV4_REMOTE_MASK).String()))
			sdf_filter.IPV4_REMOTE_NW = net.IPNet{IP: ip, Mask: mask}
		}
		if section.HasKey(PROTOCOL) {
			sdf_filter.PROTOCOL, err = section.Key(PROTOCOL).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(REMOTE_LOW_LIMIT_PORT) {
			sdf_filter.REMOTE_LOW_LIMIT_PORT, err = section.Key(REMOTE_LOW_LIMIT_PORT).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(REMOTE_HIGH_LIMIT_PORT) {
			sdf_filter.REMOTE_HIGH_LIMIT_PORT, err = section.Key(REMOTE_HIGH_LIMIT_PORT).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(LOCAL_LOW_LIMIT_PORT) {
			sdf_filter.LOCAL_LOW_LIMIT_PORT, err = section.Key(LOCAL_LOW_LIMIT_PORT).Int()
			utils.CheckFatal(err)
		}
		if section.HasKey(LOCAL_HIGH_LIMIT_PORT) {
			sdf_filter.LOCAL_HIGH_LIMIT_PORT, err = section.Key(LOCAL_HIGH_LIMIT_PORT).Int()
			utils.CheckFatal(err)
		}

		utils.LogDebug(utils.Debug, "SDF filter: ", sdf_filter)
		sdf_filters = append(sdf_filters, sdf_filter)
	} //for

}

//
//Method : parse ADC rules
//
func parseADCRules(filepath string) {
	utils.LogInfo(utils.Info, "Loading ADC Rules...")
	cfg, err := ini.Load(filepath)
	utils.CheckFatal(err)

	no_of_filters, err := cfg.Section(GLOBAL).Key(NUM_ADC_RULES).Int()
	utils.CheckFatal(err)

	for i := 1; i <= no_of_filters; i++ {
		strVal := strconv.Itoa(i)
		section := cfg.Section(ADC_RULE + "_" + strVal)

		adc_filter := ADC_FILTER{ADC_FILTER_IDX: i}

		if section.HasKey(ADC_TYPE) {
			adc_filter.ADC_TYPE, err = section.Key(ADC_TYPE).Int()
			utils.CheckFatal(err)
		}

		if section.HasKey(IP) {
			adc_filter.IP = section.Key(IP).String()

		}
		if section.HasKey(PREFIX) {
			adc_filter.PREFIX, err = section.Key(PREFIX).Int()
			adc_filter.IP = section.Key(IP).String()

			_, ipnet, err := net.ParseCIDR(adc_filter.IP + "/" + strconv.Itoa(adc_filter.PREFIX))
			utils.CheckFatal(err)

			adc_filter.IP_PREFIX_NW = *ipnet //ip-net will ease the lookup
		}

		if section.HasKey(DOMAIN) {
			adc_filter.DOMAIN = section.Key(DOMAIN).String()

		}
		utils.LogDebug(utils.Debug, "ADC filter: ", adc_filter)
		adc_filters = append(adc_filters, adc_filter)
	} //for

}

// default pcc rule

var pcc_filter = PCC_FILTER{
	PCC_FILTER_IDX: 0,
	PRECEDENCE:     255,
	GATE_STATUS:    1,
}

//
// Method : Lookup PCC rule by SDF rule index
//
func LookUpPCCRuleBySDF(sdf_idx int) PCC_FILTER {
	pcc_filters := pcc_sdf_map[sdf_idx]

	utils.LogDebug(utils.Debug, "LookUpPCCRuleBySDF No of rules found : ", len(pcc_filters))
	if len(pcc_filters) == 0 {
		return pcc_filter
	}

	return pcc_filters[0]
}

//
// Method :  Lookup PCC rules by ADC rule index
//
func LookUpPCCRuleByADC(adc_idx int) (PCC_FILTER, error) {
	var pcc_filter PCC_FILTER
	pcc_filters := pcc_adc_map[adc_idx]

	utils.LogDebug(utils.Debug, "LookUpPCCRuleByADC No of rules found : ", len(pcc_filters))
	if len(pcc_filters) == 0 {
		return pcc_filter, errors.New("No PCC rule matched ")
	}

	return pcc_filters[0], nil
}

//
//  Method : generate ACLs from SDF rules
//
//	#  Source address, Destination address, L4 protocol ID, Source port, Destination port, Output flow
//   111.2.0.0/31            ANY              ANY            ANY            ANY              1
//
func prepareSDF_UL_ACL() {

	utils.LogInfo(utils.Info, "Generating ACL Rules...")

	dumpFile, err := os.Create(SDF_UL_ACL_FILE_PATH)
	if err != nil {
		fmt.Errorf("Error while creating acl file ", err)
		//		utils.LogFatal(utils.No,"Error while creating acl file ", err)
	}
	defer dumpFile.Close()

	for _, sdf_filter := range sdf_filters {

		if sdf_filter.DIRECTION == DIRECTION_UL || sdf_filter.DIRECTION == DIRECTION_BI {
			ip_addr_local := sdf_filter.IPV4_LOCAL_NW.String()
			if ip_addr_local == "<nil>" {
				ip_addr_local = "ANY"
			}
			ip_addr := sdf_filter.IPV4_REMOTE_NW.String()
			if ip_addr == "<nil>" {
				ip_addr = "ANY"
			}
			acl_str := fmt.Sprintf("%s %s %d %d:%d %d:%d %d", ip_addr_local, ip_addr, sdf_filter.PROTOCOL, sdf_filter.LOCAL_LOW_LIMIT_PORT, sdf_filter.LOCAL_HIGH_LIMIT_PORT, sdf_filter.REMOTE_LOW_LIMIT_PORT, sdf_filter.REMOTE_HIGH_LIMIT_PORT, sdf_filter.SDF_FILTER_IDX)
			fmt.Println("Installing  ", sdf_filter.DIRECTION, " ACL : ", acl_str)
			utils.LogDebug(utils.Info, "Installing  ", sdf_filter.DIRECTION, " ACL : ", acl_str)
			dumpFile.WriteString(acl_str + "\n")
			dumpFile.Sync()
		}
	} //

} //

//
// Method : generate ACL from SDF rules
//
func prepareSDF_DL_ACL() {

	utils.LogInfo(utils.Info, "Generating ACL Rules...")

	dumpFile, err := os.Create(SDF_DL_ACL_FILE_PATH)
	if err != nil {
		fmt.Errorf("Error while creating acl file ", err)
	}
	defer dumpFile.Close()

	for _, sdf_filter := range sdf_filters {

		utils.LogDebug(utils.Debug, sdf_filter.DIRECTION)
		if sdf_filter.DIRECTION == DIRECTION_DL || sdf_filter.DIRECTION == DIRECTION_BI {
			ip_addr_local := sdf_filter.IPV4_LOCAL_NW.String()
			if ip_addr_local == "<nil>" {
				ip_addr_local = "ANY"
			}
			ip_addr := sdf_filter.IPV4_REMOTE_NW.String()
			if ip_addr == "<nil>" {
				ip_addr = "ANY"
			}
			acl_str := fmt.Sprintf("%s %s %d %d:%d %d:%d %d", ip_addr, ip_addr_local, sdf_filter.PROTOCOL, sdf_filter.LOCAL_LOW_LIMIT_PORT, sdf_filter.LOCAL_HIGH_LIMIT_PORT, sdf_filter.REMOTE_LOW_LIMIT_PORT, sdf_filter.REMOTE_HIGH_LIMIT_PORT, sdf_filter.SDF_FILTER_IDX)
			fmt.Println("Installing  ", sdf_filter.DIRECTION, " ACL : ", acl_str)
			utils.LogDebug(utils.Info, "Installing  ", sdf_filter.DIRECTION, " ACL : ", acl_str)
			dumpFile.WriteString(acl_str + "\n")
			dumpFile.Sync()
		}
	}

} //

//
// Method : generate  ACL from ADC rules
//
func prepareADC_ACL() {

	utils.LogInfo(utils.Info, "Generating ADC ACL Rules...")

	//adc_filters
	dumpFile, err := os.Create(ADC_ACL_FILE_PATH)
	if err != nil {
		fmt.Errorf("Error while creating acl file ", err)
	}
	defer dumpFile.Close()

	for _, adc_filter := range adc_filters {

		var ip_addr string
		switch adc_filter.ADC_TYPE {
		//IP
		case 1:
			ip_addr = adc_filter.IP + "/32"
			fmt.Println(adc_filter.ADC_FILTER_IDX, " IP ", ip_addr)
		//IP+Prefix
		case 2:
			ip_addr = adc_filter.IP_PREFIX_NW.String()
			fmt.Println(adc_filter.ADC_FILTER_IDX, " IP_PREFIX ", ip_addr)
		//Domain
		case 0:

			fmt.Println(adc_filter.ADC_FILTER_IDX, " DOMAIN ", adc_filter.DOMAIN)
			//TODO resolve domain
			continue
		}
		var acl_str string

		acl_str = fmt.Sprintf("0.0.0.0/0 %s ANY 0:65535 0:65535 %d", ip_addr, adc_filter.ADC_FILTER_IDX)
		utils.LogDebug(utils.Debug, acl_str)
		dumpFile.WriteString(acl_str + "\n")
		acl_str = fmt.Sprintf("%s 0.0.0.0/0 ANY 0:65535 0:65535 %d", ip_addr, adc_filter.ADC_FILTER_IDX)
		utils.LogDebug(utils.Debug, acl_str)
		dumpFile.WriteString(acl_str + "\n")

		dumpFile.Sync()
	}

} //

//
// Method : Init rules from the configuration files
// --prepareSDF ACL
// --build PCC SDF Map
// --build PCC ADC Map
func Init() {
	parsePCCRules(PCC_RULES_FILE_PATH)
	parseSDFRules(SDF_RULES_FILE_PATH)
	parseADCRules(ADC_RULES_FILE_PATH)
	prepareSDF_UL_ACL()
	prepareSDF_DL_ACL()
	prepareADC_ACL()
	buildPCCSDFMap()
	buildPCCADCMap()
}
