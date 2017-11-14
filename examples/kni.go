// Call insmod ./dpdk/dpdk-17.08/x86_64-native-linuxapp-gcc/kmod/rte_kni.ko lo_mode=lo_mode_fifo_skb
// before this. It will make a loop of packets inside KNI device and "send" will send received packets.
// Other variants of rte_kni.ko configuration can be found here:
// http://dpdk.org/doc/guides/sample_app_ug/kernel_nic_interface.html

// Need to call "ifconfig myKNI 111.111.11.11" while running this example to allow other applications
// to receive packets from "111.111.11.11" address

package main

import "github.com/intel-go/yanff/flow"

func main() {
	config := flow.Config{
		// Is required for KNI
		NeedKNI: true,
		CPUList: "0-7",
	}

	flow.SystemInit(&config)
	// (port of device, core (not from YANFF set) which will handle device, name of device)
	kni := flow.CreateKniDevice(1, 20, "myKNI")

	fromEthFlow := flow.SetReceiver(0)
	flow.SetSender(fromEthFlow, kni)

	fromKNIFlow := flow.SetReceiver(kni)
	flow.SetSender(fromKNIFlow, 1)

	flow.SystemStart()
}
