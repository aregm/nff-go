// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/test/stability/stabilityCommon"
)

// Test runs at one machine with go test.
// Packets are got from source and checked.
const (
	gotest uint = iota
)

const (
	// run only with gotest
	generate uint = iota
	fastGenerate
	vectorFastGenerate
	receiveFile
	receiveKni
	sendFile
	sendKni
)

const (
	payloadSize uint   = 16
	notCountF2  uint64 = 101102
	payloadF2   uint64 = 203204
	dstPort     uint16 = 5678

	recvFileInfile  = "iotest.pcap"
	sendFileOutfile = "iotest_out.pcap"
	sendKniFile     = "sendkni_dump.pcap"
	kniName         = "myKNI"
)

var (
	totalPackets uint64 = 1000000
	speed        uint64 = 1000000
	speedFile    uint64 = 1000
	l4Number            = common.TCPNumber

	// Reader test settings
	packetsInFile    uint64 = 1000 // number of packets in recvFileInfile
	nReadsFile       int32  = 5
	totalPacketsFile        = packetsInFile * uint64(nReadsFile)
	totalPacketsSend uint64 = 160
	checkSliceFile   []uint8

	countRes      uint64
	recvPackets   uint64
	brokenPackets uint64

	pipelineDoneEvent    *sync.Cond
	dumpProcessExitEvent *sync.Cond
	progStart            time.Time

	tcpdumpPid int

	// T second timeout is used to let generator reach required speed
	// During timeout packets are skipped and not counted
	T = 10 * time.Second

	outport1     uint
	outport2     uint
	inport1      uint
	inport2      uint
	kniport      uint = 0
	dpdkLogLevel      = "--log-level=3"

	gTestType   uint
	passedLimit uint64
)

type packetData struct {
	F1, F2 uint64
}

func initDPDK() error {
	// Init NFF-GO system
	config := flow.Config{
		NeedKNI:  true,
		DPDKArgs: []string{dpdkLogLevel},
	}
	if err := flow.SystemInit(&config); err != nil {
		return err
	}
	return nil
}

func executeTest(configFile, target string, testScenario uint, testType uint) error {
	if testScenario > 3 || testScenario < 0 {
		return errors.New("testScenario should be in interval [0, 3]")
	}
	gTestType = testType
	countRes = 0
	recvPackets = 0
	brokenPackets = 0

	setParameters(testType)

	if testScenario == gotest {

		var m sync.Mutex
		var d sync.Mutex

		pipelineDoneEvent = sync.NewCond(&m)
		dumpProcessExitEvent = sync.NewCond(&d)

		// In pipeline0: sendFile and sendKni will generate file
		// In pipeline1: file will be read and checked
		if testType == sendFile || testType == sendKni {
			if err := setupPipeline0(testType); err != nil {
				return err
			}

			if testType == sendKni {
				// Wait until KNI is up, then start tcpdump on it
				go runTcpdumpOnKni()
			}

			// Start pipeline
			go func() {
				err := flow.SystemStart()
				if err != nil {
					fmt.Printf("Cannot start system, error: %v\n", err)
					os.Exit(1)
				}
			}()

			// Wait for enough packets to arrive
			pipelineDoneEvent.L.Lock()
			pipelineDoneEvent.Wait()
			pipelineDoneEvent.L.Unlock()

			flow.SystemStop()

			if testType == sendKni {
				if killTcpdump() {
					println("After some delay tcpdump will finish......")
				} else {
					println("Cannot kill TCPDUMP!")
					os.Exit(1)
				}
				dumpProcessExitEvent.L.Lock()
				dumpProcessExitEvent.Wait()
				dumpProcessExitEvent.L.Unlock()
			}
			atomic.StoreUint64(&recvPackets, 0) // TODO
		}

		// Create packet flow
		inputFlow, err := setupPipeline1(testType)
		if err != nil {
			return err
		}
		// Check flow
		if err := setFlowCheck(inputFlow, testType); err != nil {
			return err
		}
		// Stop flow
		if err := flow.SetStopper(inputFlow); err != nil {
			return err
		}

		// Wait for enough packets to arrive
		pipelineDoneEvent.L.Lock()

		progStart = time.Now()
		// Start pipeline
		go func() {
			println("Starting system...")
			err := flow.SystemStart()
			if err != nil {
				fmt.Printf("System started with error: %v\n", err)
				os.Exit(1)
			}
		}()

		if testType == receiveKni {
			time.Sleep(5 * time.Second)
			runTcpreplayOnKni()
		}

		pipelineDoneEvent.Wait()
		pipelineDoneEvent.L.Unlock()

		flow.SystemStop()

		if testType == sendKni || testType == receiveKni {
			flow.DeleteKniDevice(uint16(kniport))
		}

		return composeStatistics()
	}
	return nil
}

func setParameters(testType uint) {
	switch testType {
	case receiveFile:
		totalPackets = totalPacketsFile
		checkSliceFile = make([]uint8, packetsInFile, packetsInFile)
	case receiveKni:
		totalPackets = packetsInFile
		checkSliceFile = make([]uint8, packetsInFile, packetsInFile)
		nReadsFile = 1
	case sendFile, sendKni:
		totalPackets = totalPacketsSend
		checkSliceFile = make([]uint8, 2*totalPacketsSend, 2*totalPacketsSend)
		if testType == sendKni {
			nReadsFile = 1
		}
	}
}

func setupPipeline0(testType uint) error {
	var err error
	switch testType {
	case sendFile:
		genFlow, err := flow.SetFastGenerator(generatePacket, speedFile, nil)
		if err != nil {
			return err
		}
		flow.SetHandlerDrop(genFlow, drop, nil)
		flow.SetSenderFile(genFlow, sendFileOutfile)
	case sendKni:
		kni, err := flow.CreateKniDevice(uint16(kniport), kniName)
		if err != nil {
			return err
		}
		genFlow := flow.SetGenerator(generatePacket, nil)
		flow.SetHandlerDrop(genFlow, drop, nil)
		if err := flow.SetSenderKNI(genFlow, kni); err != nil {
			return err
		}
		// TODO: can initialize only SenderKni here?
		fromKNIFlow := flow.SetReceiverKNI(kni)
		if err := flow.SetStopper(fromKNIFlow); err != nil {
			return err
		}
	}
	return err
}

func setupPipeline1(testType uint) (*flow.Flow, error) {
	var inputFlow *flow.Flow
	var err error
	switch testType {
	case generate:
		inputFlow = flow.SetGenerator(generatePacket, nil)
	case fastGenerate:
		inputFlow, err = flow.SetFastGenerator(generatePacket, speed, nil)
	case vectorFastGenerate:
		inputFlow, err = flow.SetVectorFastGenerator(generatePacketVector, speed, nil)
	case receiveFile:
		inputFlow = flow.SetReceiverFile(recvFileInfile, nReadsFile)
	case receiveKni:
		kni, err := flow.CreateKniDevice(uint16(kniport), kniName)
		if err != nil {
			return nil, err
		}
		// TODO: can initialize only ReceiverKni here?
		stubFlow, err := flow.SetReceiver(uint16(inport1))
		if err != nil {
			return nil, err
		}
		if err := flow.SetSenderKNI(stubFlow, kni); err != nil {
			return nil, err
		}
		inputFlow = flow.SetReceiverKNI(kni)
	case sendFile:
		inputFlow = flow.SetReceiverFile(sendFileOutfile, 1)
	case sendKni:
		inputFlow = flow.SetReceiverFile(sendKniFile, 1)
	}
	return inputFlow, err
}

func setFlowCheck(inputFlow *flow.Flow, testType uint) error {
	switch testType {
	case generate, fastGenerate, vectorFastGenerate:
		if err := flow.SetHandler(inputFlow, checkFlow, nil); err != nil {
			return err
		}
	case receiveFile, sendFile, receiveKni, sendKni:
		if err := flow.SetHandler(inputFlow, checkFlowFile, nil); err != nil {
			return err
		}
	}
	return nil
}

func runTcpreplay() {
	cmd := exec.Command("tcpreplay", "-i", kniName, recvFileInfile)
	err := cmd.Start()
	if err != nil {
		fmt.Println("runTcpreplay: Failed to execute command", err)
		println("TEST FAILED")
		os.Exit(1)
	}
}

func dumpStartKniTcpdump(file string) {
	cmd := exec.Command("tcpdump", "-x", "-i", kniName, "-w", file)
	err := cmd.Start()
	if err != nil {
		fmt.Println("dumpStartKniTcpdump: Failed to start tcpdump process", err)
		println("TEST FAILED")
		os.Exit(1)
	}
	tcpdumpPid = cmd.Process.Pid

	println("Waiting for command to finish...")
	err = cmd.Wait()
	if err != nil {
		fmt.Println("DUMP process finished with error=", err)
		println("TEST FAILED")
		os.Exit(1)
	}
	dumpProcessExitEvent.Signal()
}

func killTcpdump() bool {
	output, err := exec.Command("kill", strconv.Itoa(tcpdumpPid)).CombinedOutput()
	if string(output) == "" && err == nil {
		return true
	}
	return false
}

func isKNIup() bool {
	cmd := "ifconfig | grep " + kniName
	output, _ := exec.Command("bash", "-c", cmd).CombinedOutput()
	if string(output) != "" {
		return true
	}
	return false
}

func runTcpdumpOnKni() {
	for isKNIup() == false {
		time.Sleep(100 * time.Millisecond)
	}
	dumpStartKniTcpdump(sendKniFile)
}

func runTcpreplayOnKni() {
	for isKNIup() == false {
		time.Sleep(100 * time.Millisecond)
	}
	runTcpreplay()
}

func composeStatistics() error {
	// Compose statistics
	var read uint64
	if gTestType == receiveFile {
		read = totalPacketsFile
	} else if gTestType == receiveKni {
		read = packetsInFile
	}
	sent := atomic.LoadUint64(&countRes)
	received := atomic.LoadUint64(&recvPackets)
	broken := atomic.LoadUint64(&brokenPackets)

	// Print report
	println("Received", received, "packets")
	if gTestType == receiveFile || gTestType == receiveKni {
		println("Expected to read", read, "packets")
		println("Ratio read/expected =", received*100/read, "%")
	} else {
		println("Sent", sent, "packets")
		println("Ratio =", received*100/sent, "%")
	}
	println("Broken = ", broken, "packets")

	// Test is passed if no broken and if total receive/send rate is high
	if broken == 0 && gTestType != receiveFile && gTestType != receiveKni && received*100/sent > passedLimit {
		println("TEST PASSED")
		return nil
	}
	if broken == 0 && (gTestType == receiveFile || gTestType == receiveKni) && received*100/read > passedLimit {
		ok := true
		for i, v := range checkSliceFile {
			if int32(v) != nReadsFile {
				println("Packet", i, "read", v, "times (instead of", nReadsFile, ")")
				ok = false
			}
		}
		if ok {
			println("TEST PASSED")
			return nil
		}
	}
	println("TEST FAILED")
	return errors.New("final statistics check failed")
}

// Function to use in generator
func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	if gTestType == sendKni {
		// TODO: check
		// Need delay to decrease speed, otherwise packets are dropped in kernel
		time.Sleep(50 * time.Millisecond)
	}
	if pkt == nil {
		log.Fatal("Failed to create new packet")
	}
	if packet.InitEmptyIPv4TCPPacket(pkt, payloadSize) == false {
		log.Fatal("Failed to create new packet")
	}
	ipv4 := pkt.GetIPv4()
	tcp := pkt.GetTCPForIPv4()

	// Generate identical packets
	tcp.DstPort = packet.SwapBytesUint16(dstPort)

	// Put a unique non-zero value
	ptr := (*packetData)(pkt.Data)
	ptr.F2 = notCountF2

	// We do not consider the start time of the system in this test
	if gTestType == sendKni || time.Since(progStart) >= T && atomic.LoadUint64(&recvPackets) < totalPackets {
		atomic.AddUint64(&countRes, 1)
		ptr.F2 = payloadF2
	}
	ptr.F1 = atomic.LoadUint64(&countRes) + 1

	// Put checksums
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	tcp.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(ipv4, tcp, pkt.Data))
}

// Generate packets
func drop(pkt *packet.Packet, context flow.UserContext) bool {
	// TODO do not parse packet again
	pkt.ParseL3()
	if pkt.GetIPv4() == nil {
		return false
	}
	pkt.ParseL4ForIPv4()
	if pkt.GetTCPForIPv4() == nil {
		return false
	}

	if pkt.ParseData() < 0 {
		println("ParseData returned negative value")
		atomic.AddUint64(&brokenPackets, 1)
		return false
	}
	ptr := (*packetData)(pkt.Data)
	if ptr.F2 == payloadF2 {
		if atomic.AddUint64(&recvPackets, 1) >= totalPackets {
			pipelineDoneEvent.Signal()
		}
		return true
	}
	return false
}

func generatePacketVector(pkts []*packet.Packet, smth uint, context flow.UserContext) {
	for _, pkt := range pkts {
		generatePacket(pkt, context)
	}
}

func shouldBeChecked(pkt *packet.Packet) bool {
	return !(time.Since(progStart) < T || stabilityCommon.ShouldBeSkipped(pkt, l4Number))
}

func checkFlow(pkt *packet.Packet, context flow.UserContext) {
	if commonFlowCheck(pkt) == false {
		return
	}
	ptr := (*packetData)(pkt.Data)
	if atomic.AddUint64(&recvPackets, 1) >= totalPackets {
		pipelineDoneEvent.Signal()
	}
	if ptr.F2 != notCountF2 && ptr.F2 != payloadF2 ||
		ptr.F2 == notCountF2 && ptr.F1 != 1 {
		println("Packet contents are incorrect: F1=", ptr.F1, "F2=", ptr.F2)
		atomic.AddUint64(&brokenPackets, 1)
		return
	}
}

func checkFlowFile(pkt *packet.Packet, context flow.UserContext) {
	if commonFlowCheck(pkt) == false {
		return
	}
	if atomic.AddUint64(&recvPackets, 1) >= totalPackets {
		pipelineDoneEvent.Signal()
	}
	ptr := (*packetData)(pkt.Data)
	if ptr.F1 >= totalPackets*2 {
		println("Packet contents are incorrect: F1=", ptr.F1, " too high (expect totalPackets=", totalPackets, ")")
		println("TEST FAILED")
		atomic.AddUint64(&brokenPackets, 1)
		os.Exit(1)
	}
	checkSliceFile[ptr.F1]++
	checkPktNreadsMore(ptr.F1, nReadsFile)
}

func checkPktNreadsMore(f1 uint64, expectedN int32) {
	if int32(checkSliceFile[f1]) > expectedN {
		println("Packet f1=", f1, "is read", checkSliceFile[f1], "times (instead of", expectedN, ")")
		println("TEST FAILED")
		return
	}
}

func checkPktNreadsNeq(f1 uint64, expectedN int32) {
	if int32(checkSliceFile[f1]) != expectedN {
		println("Packet f1=", f1, "is read", checkSliceFile[f1], "times (instead of", expectedN, ")")
		println("TEST FAILED")
		return
	}
}

func commonFlowCheck(pkt *packet.Packet) bool {
	if (gTestType == generate || gTestType == fastGenerate ||
		gTestType == vectorFastGenerate) && !shouldBeChecked(pkt) {
		return false
	}
	if stabilityCommon.ShouldBeSkipped(pkt, l4Number) {
		return false
	}
	if pkt.ParseData() < 0 {
		println("ParseData returned negative value")
		atomic.AddUint64(&brokenPackets, 1)
		return false
	}

	ipv4 := pkt.GetIPv4()
	tcp := pkt.GetTCPForIPv4()
	if tcp.DstPort != packet.SwapBytesUint16(dstPort) {
		println("Unexpected packet in inputFlow", tcp.DstPort)
		atomic.AddUint64(&brokenPackets, 1)
		return false
	}

	ptr := (*packetData)(pkt.Data)
	if ptr.F2 == notCountF2 {
		return false
	}

	recvIPv4Cksum := packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	recvTCPCksum := packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(ipv4, tcp, pkt.Data))
	if recvIPv4Cksum != ipv4.HdrChecksum || recvTCPCksum != tcp.Cksum || ptr.F2 != payloadF2 {
		println("Incorrect data in packet: F1=", ptr.F1, ", F2=", ptr.F2, ", cksums=", recvIPv4Cksum, ipv4.HdrChecksum, recvTCPCksum, tcp.Cksum)
		atomic.AddUint64(&brokenPackets, 1)
		return false
	}
	return true
}
