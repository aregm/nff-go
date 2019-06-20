package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

const (
	script1 = `set 0 dst mac %s
set 1 dst mac %s
set 0 size 1500
set 1 size 1500
`
	script2 = `set 0 size 1500
set 1 size 1500
range 0 dst mac start %s
range 1 dst mac start %s
range 0 size start 1500
range 0 size min 1500
range 0 size max 1500
range 0 dst port start 50
range 0 dst port min 50
range 0 dst port max 60
range 0 dst port inc 1
enable 0 range
`
	script3 = `set 0 size 1500
set 1 size 1500
range 0 dst mac start %s
range 1 dst mac start %s
range 0 size start 1500
range 0 size min 1500
range 0 size max 1500
range 0 src ip start 111.2.0.0
range 0 src ip min 111.2.0.0
range 0 src ip max 111.2.0.3
range 0 src ip inc 0.0.0.1
enable 0 range
`
	scriptNat = `set 0 size 1500
set 1 size 1500
range 0 dst mac start %s
range 1 dst mac start %s
range 0 size start 1500
range 0 size min 1500
range 0 size max 1500
range 1 size start 1500
range 1 size min 1500
range 1 size max 1500
range 0 src ip start 192.168.1.2
range 0 src ip min 192.168.1.2
range 0 src ip max 192.168.1.12
range 0 src ip inc 0.0.0.1
range 0 dst ip start 10.1.1.2
range 0 dst ip inc 0.0.0.0
range 0 src port start 1234
range 0 src port inc 0
range 1 src ip start 10.1.1.2
range 1 src ip inc 0.0.0.0
range 1 dst ip start 10.1.1.1
range 1 dst ip inc 0.0.0.0
range 1 dst port start 1024
range 1 dst port inc 0
enable 0 range
enable 1 range
`
	jsonNat = `{
    "port-pairs": [
        {
            "private-port": {
                "index": 0,
                "dst_mac": "%s",
                "subnet": "192.168.1.1/24"
            },
            "public-port": {
                "index": 1,
                "dst_mac": "%s",
                "subnet": "10.1.1.1"
            }
        }
    ]
}
`
	workaroundScript = `
start 1
sleep 1
stop 1
`
)

var workaroundTargets = map[string]struct{}{
	"dbdw14": {},
	"dbdw15": {},
	"dbdw16": {},
	"dbdw17": {},
}

func genScript(hostdir string, hosts []string, format, mac0, mac1 string, workaround bool) {
	for _, hostname := range hosts {
		if hostdir != "" {
			hostname = hostdir + string(os.PathSeparator) + hostname
		}
		file, err := os.Create(hostname)
		if err != nil {
			log.Fatal(err)
		} else {
			defer file.Close()
		}

		fmt.Fprintf(file, format, mac0, mac1)
		if workaround {
			fmt.Fprintf(file, workaroundScript)
		}
	}
}

func main() {
	// Parse arguments
	pktgenDir := flag.String("pgdir", "../../dpdk", "Specify directory where to put pktgen script files")
	configFile := flag.String("config", "config.json", "Specify config file name")
	target := flag.String("target", "", "Target host name from config file")
	pktgen := flag.String("pktgen", "", "Pktgen host name from config file")
	flag.Parse()

	// Read config
	err := readConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	if *target == "" && *pktgen == "" {
		target = &direct
		println("Generating scripts for -target direct")
	}

	_, needWO := workaroundTargets[*target]

	if *target != "" {
		genScript(*pktgenDir, []string{"step02.pg", "step03.pg"}, script1, config[*target][0], config[*target][1], needWO)
		genScript(*pktgenDir, []string{"step04.pg"}, script2, config[*target][0], config[*target][1], needWO)
		genScript(*pktgenDir, []string{"step05.pg", "step06.pg", "step07.pg", "step08.pg", "step09.pg", "step10.pg", "step11.pg"},
			script3, config[*target][0], config[*target][1], needWO)
		genScript(*pktgenDir, []string{"nat.pg"}, scriptNat, config[*target][0], config[*target][1], needWO)
	}

	if *pktgen != "" {
		// Write NAT config file
		genScript("", []string{"nat.json"}, jsonNat, config[*pktgen][0], config[*pktgen][1], false)
	}
}
