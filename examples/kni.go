// For forwarding testing call
// "insmod ./x86_64-native-linuxapp-gcc/kmod/rte_kni.ko lo_mode=lo_mode_fifo_skb"
// from DPDK directory before compiling this test. It will make a loop of packets
// inside KNI device and receive from KNI will receive all packets that were sent to KNI.

// For ping testing call
// "insmod ./x86_64-native-linuxapp-gcc/kmod/rte_kni.ko"
// from DPDK directory before compiling this test. Use --ping option.

// Other variants of rte_kni.ko configuration can be found here:
// http://dpdk.org/doc/guides/sample_app_ug/kernel_nic_interface.html

// Need to call "ifconfig myKNI 111.111.11.11" while running this example to allow other applications
// to receive packets from "111.111.11.11" address

package main

import (
	"flag"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

var ping bool

func main() {
	inport := flag.Uint("inport", 0, "port for receiver")
	outport := flag.Uint("outport", 0, "port for sender")
	kniport := flag.Uint("kniport", 0, "port for kni")
	mode := flag.Uint("mode", 0, "0 - for three cores for KNI send/receive/Linux, 1 - for single core for KNI send/receive, 2 - for one core for all KNI")
	flag.BoolVar(&ping, "ping", false, "use this for pushing only ARP and ICMP packets to KNI")
	flag.Parse()

	config := flow.Config{
		// Is required for KNI
		NeedKNI: true,
		CPUList: "0-7",
	}

	flow.CheckFatal(flow.SystemInit(&config))
	// port of device, name of device
	kni, err := flow.CreateKniDevice(uint16(*kniport), "myKNI")
	flow.CheckFatal(err)

	inputFlow, err := flow.SetReceiver(uint16(*inport))
	flow.CheckFatal(err)

	toKNIFlow, err := flow.SetSeparator(inputFlow, pingSeparator, nil)
	flow.CheckFatal(err)

	var fromKNIFlow *flow.Flow
	switch *mode {
	case 0:
		flow.CheckFatal(flow.SetSenderKNI(toKNIFlow, kni))
		fromKNIFlow = flow.SetReceiverKNI(kni)
	case 1:
		fromKNIFlow, err = flow.SetSenderReceiverKNI(toKNIFlow, kni, false)
		flow.CheckFatal(err)
	case 2:
		fromKNIFlow, err = flow.SetSenderReceiverKNI(toKNIFlow, kni, true)
		flow.CheckFatal(err)
	}

	outputFlow, err := flow.SetMerger(inputFlow, fromKNIFlow)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetSender(outputFlow, uint16(*outport)))

	flow.CheckFatal(flow.SystemStart())
}

func pingSeparator(current *packet.Packet, ctx flow.UserContext) bool {
	if ping == false {
		// All packets will go to KNI.
		// You should use lo_mode=lo_mode_fifo_skb for looping back these packets.
		return false
	}
	ipv4, ipv6, arp := current.ParseAllKnownL3()
	if arp != nil {
		return false
	} else if ipv4 != nil {
		if ipv4.NextProtoID == types.ICMPNumber {
			return false
		}
	} else if ipv6 != nil {
		if ipv6.Proto == types.ICMPNumber {
			return false
		}
	}
	return true
}
