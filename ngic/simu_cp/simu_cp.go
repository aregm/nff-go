package simu_cp

import (
	"fmt"
	"github.com/intel-go/nff-go/ngic/utils"
	"gopkg.in/ini.v1"
	"net"
	"strconv"
)

var CONFIG_SIMU_FILE_PATH string = "config/simu_cp.cfg"

//
// Simu CP config structure
//
type SimuConfig struct {
	StartUEIP        string
	StartENBIP       string
	StartAPPServerIP string
	ENBCount         int
	FlowCount        int
	StartS1U_TEID    uint32
	StartENB_TEID    uint32
}

//
// ENB mapping structure
//
type ENB_fteid struct {
	ENB_TEID uint32
	ENB_IP   uint32
}

//
// Method : initialize the simu configuration
//
func initConfig() SimuConfig {
	config := SimuConfig{}
	cfg, err := ini.Load(CONFIG_SIMU_FILE_PATH)
	utils.CheckFatal(err)

	for key, value := range cfg.Section("0").KeysHash() {
		utils.LogDebug(utils.Debug, key, "=", value)
		if key == "StartS1U_TEID" {
			tmpVal, err := strconv.ParseUint(value, 10, 32)
			utils.CheckFatal(err)
			config.StartS1U_TEID = uint32(tmpVal)
		} else if key == "StartUEIP" {
			config.StartUEIP = value
		} else if key == "StartENBIP" {
			config.StartENBIP = value
		} else if key == "StartAPPServerIP" {
			config.StartAPPServerIP = value
		} else if key == "ENBCount" {
			config.ENBCount, err = strconv.Atoi(value)
			utils.CheckFatal(err)

		} else if key == "FlowCount" {
			config.FlowCount, err = strconv.Atoi(value)
			utils.CheckFatal(err)

		} else if key == "StartENB_TEID" {
			tmpVal, err := strconv.ParseUint(value, 10, 32)
			utils.CheckFatal(err)
			config.StartENB_TEID = uint32(tmpVal)
		}

	}
	return config
}

//
// Method : repopulate the UL and DL maps
//
func TrainDP() (map[uint32]uint32, map[uint32]*ENB_fteid) {
	config := initConfig()
	ul_map := populateULTable(&config)
	dl_map := populateDLTable(&config)

	fmt.Println("-------------------------------")
	fmt.Println(" MAX_NUM_CS = ", config.FlowCount)
	fmt.Println(" MAX_NUM_MB = ", config.FlowCount)
	fmt.Println(" NUM_CS_SEND = ", config.FlowCount)
	fmt.Println(" NUM_MB_SEND = ", config.FlowCount)
	fmt.Println(" NUM_CS_FAILED = ", (config.FlowCount - len(ul_map)))
	fmt.Println(" NUM_MB_FAILED = ", (config.FlowCount - len(dl_map)))
	fmt.Println("-------------------------------")

	return ul_map, dl_map
}

//
// Method : populate UL tales
//
func populateULTable(config *SimuConfig) map[uint32]uint32 {
	ul_map := make(map[uint32]uint32)
	start_ue_ip := net.ParseIP(config.StartUEIP)
	for i := 0; i < config.FlowCount; i++ {
		ul_map[config.StartS1U_TEID] = utils.StringToIPv4(utils.NextIP(start_ue_ip, uint(i)).String())
		config.StartS1U_TEID++
	}
	return ul_map
}

//
// Method : populate DL map
//
func populateDLTable(config *SimuConfig) map[uint32]*ENB_fteid {
	dl_map := make(map[uint32]*ENB_fteid)
	start_ue_ip := net.ParseIP(config.StartUEIP)
	for i := 0; i < config.FlowCount; i++ {

		enb_fteid := ENB_fteid{
			ENB_TEID: config.StartENB_TEID,
			ENB_IP:   utils.StringToIPv4(config.StartENBIP),
		}
		dl_map[utils.StringToIPv4(utils.NextIP(start_ue_ip, uint(i)).String())] = &enb_fteid

		//  startENB_TEID++  //CHANGEME
	}
	return dl_map
}
