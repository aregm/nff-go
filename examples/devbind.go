package main

import (
	"flag"
	"log"

	"github.com/intel-go/nff-go/devices"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

// Example that shows how to bind a driver to a NIC
func main() {
	nic := flag.String("nic", "enp0s9", "network interface to run DPDK")
	bind := flag.String("bind", "igb_uio", "dpdk uio driver")
	flag.Parse()

	device, err := devices.New(*nic)
	flow.CheckFatal(err)

	driver, err := device.CurrentDriver()
	if err != nil {
		log.Println("Failed to get CurrentDriver:", err)
		return
	}

	defer func() {
		flow.SystemStop()

		// Re-Bind to original driver
		device.Bind(driver)
	}()

	// Bind to new user specified driver
	device.Bind(*bind)

	config := &flow.Config{
		HWTXChecksum: true,
	}
	flow.SystemInit(config)

	var port uint16 = 0

	mainFlow, err := flow.SetReceiver(port)
	if err != nil {
		log.Println("Failed to SetReceiver:", err)
		return
	}

	err = flow.SetHandlerDrop(mainFlow, handler, nil)
	if err != nil {
		log.Println("Failed to SetHandlerDrop:", err)
		return
	}

	err = flow.SetSender(mainFlow, port)
	if err != nil {
		log.Println("Failed to SetSender:", err)
		return
	}

	err = flow.SystemStart()
	if err != nil {
		log.Println("Failed to SystemStart:", err)
		return
	}
}

func handler(*packet.Packet, flow.UserContext) bool {
	return true
}
