// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package flow provides functionality for constructing packet processing graph

// Preparations of construction:
// All construction should be between SystemInit and SystemStart functions.
// User command line options should be added as flags before SystemInit option - it will
// parse them as well as internal library options.

// Packet processing graph construction:
// NFF-GO library provides nine so-called Flow Functions for packet processing graph
// construction. They operate term "flow" however it is just abstraction for connecting
// them. Not anything beyond this. These nine flow functions are:
// Receive, Generate - for adding packets to graph
// Send, Stop - for removing packets from graph
// Handle - for handling packets inside graph
// Separate, Split, Count, Merge for combining flows inside graph
// All this functions can be added to the graph be "Set" functions like
// SetReceiver, SetSplitter, etc.

// Flow functions Generate, Handle, Separate and Split use user defined functions
// for processing. These functions are received each packet from flow (or new
// allocated packet in generate). Function types of user defined functions are
// also defined in this file.

// Package flow is the main package of NFF-GO library and should be always imported by
// user application.
package flow

import (
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/asm"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/low"
	"github.com/intel-go/nff-go/packet"
)

var openFlowsNumber = uint32(0)
var ringName = 1
var createdPorts []port
var schedState *scheduler
var vEach [10][burstSize]uint8

type processSegment struct {
	out      []*low.Ring
	contexts []UserContext
	stype    uint8
}

// Flow is an abstraction for connecting flow functions with each other.
// Flow shouldn't be understood in any way beyond this.
type Flow struct {
	current  *low.Ring
	segment  *processSegment
	previous **Func
}

type partitionCtx struct {
	currentAnswer       uint8
	currentCompare      uint64
	currentPacketNumber uint64
	N                   uint64
	M                   uint64
}

func (c partitionCtx) Copy() interface{} {
	return &partitionCtx{N: c.N, M: c.M, currentCompare: c.N}
}

func (c partitionCtx) Delete() {
}

type Func struct {
	sHandleFunction   HandleFunction
	sSeparateFunction SeparateFunction
	sSplitFunction    SplitFunction
	sFunc             func(*packet.Packet, *Func, UserContext) uint
	vHandleFunction   VectorHandleFunction
	vSeparateFunction VectorSeparateFunction
	vSplitFunction    VectorSplitFunction
	vFunc             func([]*packet.Packet, *[burstSize]bool, *[burstSize]uint8, *Func, UserContext)

	next            [](*Func)
	bufIndex        uint
	contextIndex    int
	followingNumber uint8
}

// GenerateFunction is a function type for user defined function which generates packets.
// Function receives preallocated packet where user should add
// its size and content.
type GenerateFunction func(*packet.Packet, UserContext)

// VectorGenerateFunction is a function type like GenerateFunction for vector generating
type VectorGenerateFunction func([]*packet.Packet, uint, UserContext)

// HandleFunction is a function type for user defined function which handles packets.
// Function receives a packet from flow. User should parse it
// and make necessary changes. It is prohibit to free packet in this
// function.
type HandleFunction func(*packet.Packet, UserContext)

// VectorHandleFunction is a function type like HandleFunction for vector handling
type VectorHandleFunction func([]*packet.Packet, *[burstSize]bool, UserContext)

// SeparateFunction is a function type for user defined function which separates packets
// based on some rule for two flows. Functions receives a packet from flow.
// User should parse it and decide whether this packet should remains in
// this flow - return true, or should be sent to new added flow - return false.
type SeparateFunction func(*packet.Packet, UserContext) bool

// VectorSeparateFunction is a function type like SeparateFunction for vector separation
type VectorSeparateFunction func([]*packet.Packet, *[burstSize]bool, *[burstSize]uint8, UserContext)

// SplitFunction is a function type for user defined function which splits packets
// based in some rule for multiple flows. Function receives a packet from
// flow. User should parse it and decide in which output flows this packet
// should be sent. Return number of flow shouldn't exceed target number
// which was put to SetSplitter function. Also it is assumed that "0"
// output flow is used for dropping packets - "Stop" function should be
// set after "Split" function in it.
type SplitFunction func(*packet.Packet, UserContext) uint

// VectorSplitFunction is a function type like SplitFunction for vector splitting
type VectorSplitFunction func([]*packet.Packet, *[burstSize]bool, *[burstSize]uint8, UserContext)

// Kni is a high level struct of KNI device. The device itself is stored
// in C memory in low.c and is defined by its port which is equal to port
// in this structure
type Kni struct {
	portId uint16
}

type receiveParameters struct {
	out  *low.Ring
	port *low.Port
	kni  bool
}

func addReceiver(portId uint16, kni bool, out *low.Ring) {
	par := new(receiveParameters)
	par.port = low.GetPort(portId)
	par.out = out
	par.kni = kni
	if kni {
		schedState.addFF("receiver", nil, recvKNI, nil, par, nil, nil, sendReceiveKNI)
	} else {
		schedState.addFF("receiver", nil, recvRSS, nil, par, nil, nil, receiveRSS)
	}
}

type generateParameters struct {
	out                    *low.Ring
	generateFunction       GenerateFunction
	vectorGenerateFunction VectorGenerateFunction
	mempool                *low.Mempool
	targetSpeed            float64
}

func addGenerator(out *low.Ring, generateFunction GenerateFunction) {
	par := new(generateParameters)
	par.out = out
	par.generateFunction = generateFunction
	schedState.addFF("generator", generateOne, nil, nil, par, nil, nil, other)
}

func addFastGenerator(out *low.Ring, generateFunction GenerateFunction,
	vectorGenerateFunction VectorGenerateFunction, targetSpeed uint64, context UserContext) {
	par := new(generateParameters)
	par.out = out
	par.generateFunction = generateFunction
	par.mempool = low.CreateMempool()
	par.vectorGenerateFunction = vectorGenerateFunction
	par.targetSpeed = float64(targetSpeed)
	ctx := make([]UserContext, 1, 1)
	ctx[0] = context
	schedState.addFF("fast generator", nil, nil, generatePerf, par, make(chan uint64, 50), &ctx, fastGenerate)
}

type sendParameters struct {
	in    *low.Ring
	queue int16
	port  uint16
}

func addSender(port uint16, queue int16, in *low.Ring) {
	par := new(sendParameters)
	par.port = port
	par.queue = queue
	par.in = in
	schedState.addFF("sender", nil, send, nil, par, nil, nil, sendReceiveKNI)
}

type copyParameters struct {
	in      *low.Ring
	out     *low.Ring
	outCopy *low.Ring
	mempool *low.Mempool
}

func addCopier(in *low.Ring, out *low.Ring, outCopy *low.Ring) {
	par := new(copyParameters)
	par.in = in
	par.out = out
	par.outCopy = outCopy
	par.mempool = low.CreateMempool()
	schedState.addFF("copy", nil, nil, pcopy, par, make(chan uint64, 50), nil, segmentCopy)
}

func makePartitioner(N uint64, M uint64) *Func {
	f := new(Func)
	f.sFunc = partition
	f.vFunc = vPartition
	f.next = make([]*Func, 2, 2)
	f.followingNumber = 2
	return f
}

func makeSeparator(separateFunction SeparateFunction, vectorSeparateFunction VectorSeparateFunction) *Func {
	f := new(Func)
	f.sSeparateFunction = separateFunction
	f.vSeparateFunction = vectorSeparateFunction
	f.sFunc = separate
	f.vFunc = vSeparate
	f.next = make([]*Func, 2, 2)
	f.followingNumber = 2
	return f
}

func makeSplitter(splitFunction SplitFunction, vectorSplitFunction VectorSplitFunction, n uint8) *Func {
	f := new(Func)
	f.sSplitFunction = splitFunction
	f.vSplitFunction = vectorSplitFunction
	f.sFunc = split
	f.vFunc = vSplit
	f.next = make([]*Func, n, n)
	f.followingNumber = n
	return f
}

func makeHandler(handleFunction HandleFunction, vectorHandleFunction VectorHandleFunction) *Func {
	f := new(Func)
	f.sHandleFunction = handleFunction
	f.vHandleFunction = vectorHandleFunction
	f.sFunc = handle
	f.vFunc = vHandle
	f.next = make([]*Func, 1, 1)
	f.followingNumber = 1
	return f
}

type writeParameters struct {
	in       *low.Ring
	filename string
}

func addWriter(filename string, in *low.Ring) {
	par := new(writeParameters)
	par.in = in
	par.filename = filename
	schedState.addFF("writer", write, nil, nil, par, nil, nil, other)
}

type readParameters struct {
	out      *low.Ring
	filename string
	repcount int32
}

func addReader(filename string, out *low.Ring, repcount int32) {
	par := new(readParameters)
	par.out = out
	par.filename = filename
	par.repcount = repcount
	schedState.addFF("reader", read, nil, nil, par, nil, nil, other)
}

func makeSlice(out *low.Ring, segment *processSegment) *Func {
	f := new(Func)
	f.sFunc = constructSlice
	f.vFunc = vConstructSlice
	segment.out = append(segment.out, out)
	f.bufIndex = uint(len(segment.out) - 1)
	f.followingNumber = 0
	return f
}

type segmentParameters struct {
	in        *low.Ring
	out       *([](*low.Ring))
	firstFunc *Func
	stype     *uint8
}

func addSegment(in *low.Ring, first *Func) *processSegment {
	par := new(segmentParameters)
	par.in = in
	par.firstFunc = first
	segment := new(processSegment)
	segment.out = make([](*low.Ring), 0, 0)
	segment.contexts = make([](UserContext), 0, 0)
	par.out = &segment.out
	par.stype = &segment.stype
	schedState.addFF("segment", nil, nil, segmentProcess, par, make(chan uint64, 50), &segment.contexts, segmentCopy)
	return segment
}

const burstSize = 32

var sizeMultiplier uint
var schedTime uint
var hwtxchecksum bool

type port struct {
	wasRequested   bool // has user requested any send/receive operations at this port
	txQueuesNumber int16
	willReceive    bool // will this port receive packets
	port           uint8
}

// Config is a struct with all parameters, which user can pass to NFF-GO library
type Config struct {
	// Specifies cores which will be available for scheduler to place
	// flow functions and their clones.
	CPUList string
	// If true, scheduler is disabled entirely. Default value is false.
	DisableScheduler bool
	// If true, scheduler does not stop any previously cloned flow
	// function threads. Default value is false.
	PersistentClones bool
	// If true, Stop routine gets a dedicated CPU core instead of
	// running together with scheduler. Default value is false.
	StopOnDedicatedCore bool
	// Calculate IPv4, UDP and TCP checksums in hardware. This flag
	// slows down general TX processing, so it should be enabled if
	// applications intends to modify packets often, and therefore
	// needs to recalculate their checksums. If application doesn't
	// modify many packets, it may chose to calculate checksums in SW
	// and leave this flag off. Default value is false.
	HWTXChecksum bool
	// Specifies number of mbufs in mempool per port. Default value is
	// 8191.
	MbufNumber uint
	// Specifies number of mbufs in per-CPU core cache in
	// mempool. Default value is 250.
	MbufCacheSize uint
	// Number of burstSize groups in all rings. This should be power
	// of 2. Default value is 256.
	RingSize uint
	// Time between scheduler actions in miliseconds. Default value is
	// 1500.
	ScaleTime uint
	// Time in miliseconds for scheduler to check changing of flow
	// function behaviour. Default value is 10000.
	CheckTime uint
	// Time in miliseconds for scheduler to display statistics.
	// Default value is 1000.
	DebugTime uint
	// Specifies logging type. Default value is common.No |
	// common.Initialization | common.Debug.
	LogType common.LogType
	// Command line arguments to pass to DPDK initialization.
	DPDKArgs []string
	// Is user going to use KNI
	NeedKNI bool
}

// SystemInit is initialization of system. This function should be always called before graph construction.
func SystemInit(args *Config) error {
	CPUCoresNumber := runtime.NumCPU()
	var cpus []int
	var err error
	if args.CPUList != "" {
		if cpus, err = common.HandleCPUList(args.CPUList, CPUCoresNumber); err != nil {
			return err
		}
	} else {
		cpus = common.GetDefaultCPUs(CPUCoresNumber)
	}

	schedulerOff := args.DisableScheduler
	schedulerOffRemove := args.PersistentClones
	stopDedicatedCore := args.StopOnDedicatedCore
	hwtxchecksum = args.HWTXChecksum

	mbufNumber := uint(4 * 8191)
	if args.MbufNumber != 0 {
		mbufNumber = args.MbufNumber
	}

	mbufCacheSize := uint(250)
	if args.MbufCacheSize != 0 {
		mbufCacheSize = args.MbufCacheSize
	}

	sizeMultiplier = 256
	if args.RingSize != 0 {
		sizeMultiplier = args.RingSize
	}

	schedTime = 500
	if args.ScaleTime != 0 {
		schedTime = args.ScaleTime
	}

	checkTime := uint(10000)
	if args.CheckTime != 0 {
		checkTime = args.CheckTime
	}

	debugTime := uint(1000)
	if args.DebugTime != 0 {
		debugTime = args.DebugTime
	}

	if debugTime < schedTime {
		common.LogFatal(common.Initialization, "debugTime should be larger or equal to schedTime")
	}

	needKNI := 0
	if args.NeedKNI != false {
		needKNI = 1
	}

	logType := common.No | common.Initialization | common.Debug
	if args.LogType != 0 {
		logType = args.LogType
	}
	common.SetLogType(logType)

	argc, argv := low.InitDPDKArguments(args.DPDKArgs)
	// We want to add new clone if input ring is approximately 80% full
	maxPacketsToClone := uint32(sizeMultiplier * burstSize / 5 * 4)
	// TODO all low level initialization here! Now everything is default.
	// Init eal
	common.LogTitle(common.Initialization, "------------***-------- Initializing DPDK --------***------------")
	low.InitDPDK(argc, argv, burstSize, mbufNumber, mbufCacheSize, needKNI)
	// Init Ports
	common.LogTitle(common.Initialization, "------------***-------- Initializing ports -------***------------")
	createdPorts = make([]port, low.GetPortsNumber(), low.GetPortsNumber())
	for i := range createdPorts {
		createdPorts[i].port = uint8(i)
	}
	// Init scheduler
	common.LogTitle(common.Initialization, "------------***------ Initializing scheduler -----***------------")
	StopRing := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	common.LogDebug(common.Initialization, "Scheduler can use cores:", cpus)
	schedState = newScheduler(cpus, schedulerOff, schedulerOffRemove, stopDedicatedCore, StopRing, checkTime, debugTime, maxPacketsToClone)
	common.LogTitle(common.Initialization, "------------***------ Filling FlowFunctions ------***------------")
	// Init packet processing
	packet.SetHWTXChecksumFlag(hwtxchecksum)
	for i := 0; i < 10; i++ {
		for j := 0; j < burstSize; j++ {
			vEach[i][j] = uint8(i)
		}
	}
	return nil
}

// SystemStart starts system - begin packet receiving and packet sending.
// This functions should be always called after flow graph construction.
// Function can panic during execution.
func SystemStart() error {
	common.LogTitle(common.Initialization, "------------***--------- Checking system ---------***------------")
	if openFlowsNumber != 0 {
		return common.WrapWithNFError(nil, "Some flows are left open at the end of configuration!", common.OpenedFlowAtTheEnd)
	}
	common.LogTitle(common.Initialization, "------------***---------- Creating ports ---------***------------")
	for i := range createdPorts {
		if createdPorts[i].wasRequested {
			if err := low.CreatePort(createdPorts[i].port, createdPorts[i].willReceive,
				uint16(createdPorts[i].txQueuesNumber), hwtxchecksum); err != nil {
				return err
			}
		}
	}
	// Timeout is needed for ports to start up. This way is used in pktgen.
	// Pktgen also has checks for link status for all ports, but we compensate it
	// by additional time.
	// Timeout prevents loss of starting packets in generated flow.
	time.Sleep(time.Second * 2)

	common.LogTitle(common.Initialization, "------------***------ Starting FlowFunctions -----***------------")
	// Init low performance mempool
	packet.SetNonPerfMempool(low.CreateMempool())
	if err := schedState.systemStart(); err != nil {
		return common.WrapWithNFError(err, "scheduler start failed", common.Fail)
	}
	common.LogTitle(common.Initialization, "------------***--------- NFF-GO-GO Started --------***------------")
	schedState.schedule(schedTime)
	return nil
}

// SystemStop stops the system. All Flow functions plus resource releasing
// Doesn't cleanup DPDK
func SystemStop() {
	schedState.systemStop()
	for i := range createdPorts {
		if createdPorts[i].wasRequested {
			low.StopPort(createdPorts[i].port)
			createdPorts[i].wasRequested = false
			createdPorts[i].txQueuesNumber = 0
			createdPorts[i].willReceive = false
		}
	}
	low.FreeMempools()
}

// SystemReset stops whole framework plus cleanup DPDK
// TODO DPDK cleanup is now incomplete at DPDK side
// It is n't able to re-init after it and also is
// under deprecated pragma. Need to fix after DPDK changes.
func SystemReset() {
	SystemStop()
	low.StopDPDK()
}

func generateRingName() string {
	s := strconv.Itoa(ringName)
	ringName++
	return s
}

// SetSenderFile adds write function to flow graph.
// Gets flow which packets will be written to file and
// target file name.
func SetSenderFile(IN *Flow, filename string) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	addWriter(filename, finishFlow(IN))
	return nil
}

// SetReceiverFile adds read function to flow graph.
// Gets name of pcap formatted file and number of reads. If repcount = -1,
// file is read infinitely in circle.
// Returns new opened flow with read packets.
func SetReceiverFile(filename string, repcount int32) (OUT *Flow) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	addReader(filename, ring, repcount)
	return newFlow(ring)
}

// SetReceiver adds receive function to flow graph.
// Gets port number from which packets will be received.
// Receive queue will be added to port automatically.
// Returns new opened flow with received packets
func SetReceiver(portId uint16) (OUT *Flow, err error) {
	if portId >= uint16(len(createdPorts)) {
		return nil, common.WrapWithNFError(nil, "Requested receive port exceeds number of ports which can be used by DPDK (bind to DPDK).", common.ReqTooManyPorts)
	}
	if createdPorts[portId].willReceive {
		return nil, common.WrapWithNFError(nil, "Requested receive port was already set to receive. Two receives from one port are prohibited.", common.MultipleReceivePort)
	}
	createdPorts[portId].wasRequested = true
	createdPorts[portId].willReceive = true
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	addReceiver(portId, false, ring)
	return newFlow(ring), nil
}

// SetReceiverKNI adds function receive from KNI to flow graph.
// Gets KNI device from which packets will be received.
// Receive queue will be added to port automatically.
// Returns new opened flow with received packets
func SetReceiverKNI(kni *Kni) (OUT *Flow) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	addReceiver(kni.portId, true, ring)
	return newFlow(ring)
}

// SetFastGenerator adds clonable generate function to flow graph.
// Gets user-defined generate function, target speed of generation user wants to achieve and context.
// Returns new open flow with generated packets.
// Function tries to achieve target speed by cloning.
func SetFastGenerator(f func(*packet.Packet, UserContext), targetSpeed uint64, context UserContext) (OUT *Flow, err error) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	if targetSpeed > 0 {
		addFastGenerator(ring, GenerateFunction(f), nil, targetSpeed, context)
	} else {
		return nil, common.WrapWithNFError(nil, "Target speed value should be > 0", common.BadArgument)
	}
	return newFlow(ring), nil
}

// SetVectorFastGenerator adds clonable vector generate function to flow graph.
// Gets user-defined vector generate function, target speed of generation user wants to achieve and context.
// Returns new open flow with generated packets.
// Function tries to achieve target speed by cloning.
func SetVectorFastGenerator(f func([]*packet.Packet, uint, UserContext), targetSpeed uint64, context UserContext) (OUT *Flow, err error) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	if targetSpeed > 0 {
		addFastGenerator(ring, nil, VectorGenerateFunction(f), targetSpeed, context)
	} else {
		return nil, common.WrapWithNFError(nil, "Target speed value should be > 0", common.BadArgument)
	}
	return newFlow(ring), nil
}

// SetGenerator adds non-clonable generate flow function to flow graph.
// Gets user-defined generate function and context.
// Returns new open flow with generated packets.
// Single packet non-clonable flow function will be added. It can be used for waiting of
// input user packets.
func SetGenerator(f func(*packet.Packet, UserContext), context UserContext) (OUT *Flow) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	addGenerator(ring, GenerateFunction(f))
	return newFlow(ring)
}

// SetSender adds send function to flow graph.
// Gets flow which will be closed and its packets will be send and port number for which packets will be sent.
// Send queue will be added to port automatically.
func SetSender(IN *Flow, portId uint16) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	if portId >= uint16(len(createdPorts)) {
		return common.WrapWithNFError(nil, "Requested send port exceeds number of ports which can be used by DPDK (bind to DPDK).", common.ReqTooManyPorts)
	}
	createdPorts[portId].wasRequested = true
	addSender(portId, createdPorts[portId].txQueuesNumber, finishFlow(IN))
	createdPorts[portId].txQueuesNumber++
	return nil
}

// SetSenderKNI adds function sending to KNI to flow graph.
// Gets flow which will be closed and its packets will be send to given KNI device.
// Send queue will be added to port automatically.
func SetSenderKNI(IN *Flow, kni *Kni) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	addSender(kni.portId, -1, finishFlow(IN))
	return nil
}

// SetCopier adds copy function to flow graph.
// Gets flow which will be copied.
func SetCopier(IN *Flow) (OUT *Flow, err error) {
	if err := checkFlow(IN); err != nil {
		return nil, err
	}
	ringFirst := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	ringSecond := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	addCopier(IN.current, ringFirst, ringSecond)
	IN.current = ringFirst
	return newFlow(ringSecond), nil
}

// SetPartitioner adds partition function to flow graph.
// Gets input flow and N and M constants. Returns new opened flow.
// Each loop N packets will be remained in input flow, next M packets will be sent to new flow.
// It is advised not to use this function less then (75, 75) for performance reasons.
// We make partition function unclonable. The most complex task is (1,1).
// It means that if you would like to simply divide a flow
// it is recommended to use (75,75) instead of (1,1) for performance reasons.
func SetPartitioner(IN *Flow, N uint64, M uint64) (OUT *Flow, err error) {
	if N == 0 || M == 0 {
		common.LogWarning(common.Initialization, "One of SetPartitioner function's arguments is zero.")
	}
	partition := makePartitioner(N, M)
	ctx := new(partitionCtx)
	ctx.N = N
	ctx.M = M
	if err := segmentInsert(IN, partition, false, *ctx, 0); err != nil {
		return nil, err
	}
	return newFlowSegment(IN.segment, &partition.next[1]), nil
}

// SetSeparator adds separate function to flow graph.
// Gets flow, user defined separate function and context. Returns new opened flow.
// Each packet from input flow will be remain inside input packet if
// user defined function returns "true" and is sent to new flow otherwise.
func SetSeparator(IN *Flow, separateFunction SeparateFunction, context UserContext) (OUT *Flow, err error) {
	separate := makeSeparator(separateFunction, nil)
	if err := segmentInsert(IN, separate, false, context, 1); err != nil {
		return nil, err
	}
	return newFlowSegment(IN.segment, &separate.next[1]), nil
}

// SetVectorSeparator adds vector separate function to flow graph.
// Gets flow, user defined vector separate function and context. Returns new opened flow.
// Each packet from input flow will be remain inside input packet if
// user defined function returns "true" and is sent to new flow otherwise.
func SetVectorSeparator(IN *Flow, vectorSeparateFunction VectorSeparateFunction, context UserContext) (OUT *Flow, err error) {
	separate := makeSeparator(nil, vectorSeparateFunction)
	if err := segmentInsert(IN, separate, false, context, 2); err != nil {
		return nil, err
	}
	return newFlowSegment(IN.segment, &separate.next[1]), nil
}

// SetSplitter adds split function to flow graph.
// Gets flow, user defined split function, flowNumber of new flows and context.
// Returns array of new opened flows with corresponding length.
// Each packet from input flow will be sent to one of new flows based on
// user defined function output for this packet.
func SetSplitter(IN *Flow, splitFunction SplitFunction, flowNumber uint, context UserContext) (OutArray [](*Flow), err error) {
	if err := checkFlow(IN); err != nil {
		return nil, err
	}
	split := makeSplitter(splitFunction, nil, uint8(flowNumber))
	segmentInsert(IN, split, true, context, 1)
	OutArray = make([](*Flow), flowNumber, flowNumber)
	for i := range OutArray {
		OutArray[i] = newFlowSegment(IN.segment, &split.next[i])
	}
	return OutArray, nil
}

// SetVectorSplitter adds vector split function to flow graph.
// Gets flow, user defined vector split function, flowNumber of new flows and context.
// Returns array of new opened flows with corresponding length.
// Each packet from input flow will be sent to one of new flows based on
// user defined function output for this packet.
func SetVectorSplitter(IN *Flow, vectorSplitFunction VectorSplitFunction, flowNumber uint, context UserContext) (OutArray [](*Flow), err error) {
	if err := checkFlow(IN); err != nil {
		return nil, err
	}
	split := makeSplitter(nil, vectorSplitFunction, uint8(flowNumber))
	segmentInsert(IN, split, true, context, 2)
	OutArray = make([](*Flow), flowNumber, flowNumber)
	for i := range OutArray {
		OutArray[i] = newFlowSegment(IN.segment, &split.next[i])
	}
	return OutArray, nil
}

// SetStopper adds stop function to flow graph.
// Gets flow which will be closed and all packets from each will be dropped.
func SetStopper(IN *Flow) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	if IN.segment == nil {
		merge(IN.current, schedState.StopRing)
		closeFlow(IN)
	} else {
		ms := makeSlice(schedState.StopRing, IN.segment)
		segmentInsert(IN, ms, true, nil, 0)
	}
	return nil
}

// SetHandler adds handle function to flow graph.
// Gets flow, user defined handle function and context.
// Each packet from input flow will be handle inside user defined function
// and sent further in the same flow.
func SetHandler(IN *Flow, handleFunction HandleFunction, context UserContext) error {
	handle := makeHandler(handleFunction, nil)
	return segmentInsert(IN, handle, false, context, 1)
}

// SetVectorHandler adds vector handle function to flow graph.
// Gets flow, user defined vector handle function and context.
// Each packet from input flow will be handle inside user defined function
// and sent further in the same flow.
func SetVectorHandler(IN *Flow, vectorHandleFunction VectorHandleFunction, context UserContext) error {
	handle := makeHandler(nil, vectorHandleFunction)
	return segmentInsert(IN, handle, false, context, 2)
}

// SetHandlerDrop adds vector handle function to flow graph.
// Gets flow, user defined handle function and context.
// User defined function can return boolean value.
// If user function returns false after handling a packet it is dropped automatically.
func SetHandlerDrop(IN *Flow, separateFunction SeparateFunction, context UserContext) error {
	separate := makeSeparator(separateFunction, nil)
	if err := segmentInsert(IN, separate, false, context, 1); err != nil {
		return err
	}
	return SetStopper(newFlowSegment(IN.segment, &separate.next[1]))
}

// SetVectorHandlerDrop adds vector handle function to flow graph.
// Gets flow, user defined vector handle function and context.
// User defined function can return boolean value.
// If user function returns false after handling a packet it is dropped automatically.
func SetVectorHandlerDrop(IN *Flow, vectorSeparateFunction VectorSeparateFunction, context UserContext) error {
	separate := makeSeparator(nil, vectorSeparateFunction)
	if err := segmentInsert(IN, separate, false, context, 2); err != nil {
		return err
	}
	return SetStopper(newFlowSegment(IN.segment, &separate.next[1]))
}

// SetMerger adds merge function to flow graph.
// Gets any number of flows. Returns new opened flow.
// All input flows will be closed. All packets from all these flows will be sent to new flow.
// This function isn't use any cores. It changes output flows of other functions at initialization stage.
func SetMerger(InArray ...*Flow) (OUT *Flow, err error) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	for i := range InArray {
		if err := checkFlow(InArray[i]); err != nil {
			return nil, err
		}
		if InArray[i].segment == nil {
			merge(InArray[i].current, ring)
			closeFlow(InArray[i])
		} else {
			// TODO merge finishes segment even if this is merge inside it. Need to optimize.
			ms := makeSlice(ring, InArray[i].segment)
			segmentInsert(InArray[i], ms, true, nil, 0)
		}
	}
	return newFlow(ring), nil
}

// GetPortMACAddress returns default MAC address of an Ethernet port.
func GetPortMACAddress(port uint16) [common.EtherAddrLen]uint8 {
	return low.GetPortMACAddress(port)
}

// Service functions for Flow
func newFlow(ring *low.Ring) *Flow {
	OUT := new(Flow)
	OUT.current = ring
	openFlowsNumber++
	return OUT
}

func newFlowSegment(segment *processSegment, previous **Func) *Flow {
	OUT := newFlow(nil)
	OUT.segment = segment
	OUT.previous = previous
	return OUT
}

func finishFlow(IN *Flow) *low.Ring {
	var ring *low.Ring
	if IN.segment == nil {
		ring = IN.current
		closeFlow(IN)
	} else {
		ring = low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
		ms := makeSlice(ring, IN.segment)
		segmentInsert(IN, ms, true, nil, 0)
	}
	return ring
}

func closeFlow(IN *Flow) {
	IN.current = nil
	IN.previous = nil
	openFlowsNumber--
}

func segmentInsert(IN *Flow, f *Func, willClose bool, context UserContext, setType uint8) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	if IN.segment == nil {
		IN.segment = addSegment(IN.current, f)
		IN.segment.stype = setType
	} else {
		if setType > 0 && IN.segment.stype > 0 && setType != IN.segment.stype {
			ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
			ms := makeSlice(ring, IN.segment)
			segmentInsert(IN, ms, false, nil, 0)
			IN.segment = nil
			IN.current = ring
			segmentInsert(IN, f, willClose, context, setType)
			return nil
		}
		if setType > 0 && IN.segment.stype == 0 {
			IN.segment.stype = setType
		}
		*IN.previous = f
	}
	if willClose {
		closeFlow(IN)
	} else if f.next != nil {
		IN.previous = &f.next[0]
	}
	IN.segment.contexts = append(IN.segment.contexts, context)
	f.contextIndex = len(IN.segment.contexts) - 1
	return nil
}

func segmentProcess(parameters interface{}, stopper [2]chan int, report chan uint64, context []UserContext) {
	// For scalar and vector parts
	lp := parameters.(*segmentParameters)
	IN := lp.in
	OUT := *lp.out
	scalar := (*lp.stype != 2)
	outNumber := len(*lp.out)
	InputMbufs := make([]uintptr, burstSize, burstSize)
	OutputMbufs := make([][]uintptr, outNumber)
	countOfPackets := make([]int, outNumber)
	for index := range OutputMbufs {
		OutputMbufs[index] = make([]uintptr, burstSize)
		countOfPackets[index] = 0
	}
	var currentSpeed uint64
	tick := time.Tick(time.Duration(schedTime) * time.Millisecond)
	var pause int
	firstFunc := lp.firstFunc
	// For scalar part
	var tempPacket *packet.Packet
	var tempPacketAddr uintptr
	// For vector part
	tempPackets := make([]*packet.Packet, burstSize)
	type pair struct {
		f    *Func
		mask [burstSize]bool
	}
	def := make([]pair, 30, 30)
	var answers [burstSize]uint8

	for {
		select {
		case pause = <-stopper[0]:
			if pause == -1 {
				// It is time to close this clone
				for i := range context {
					if context[i] != nil {
						context[i].Delete()
					}
				}
				stopper[1] <- 1
				return
			}
		case <-tick:
			report <- currentSpeed
			currentSpeed = 0
		default:
			n := IN.DequeueBurst(InputMbufs, burstSize)
			if n == 0 {
				if pause != 0 {
					time.Sleep(time.Duration(pause) * time.Nanosecond)
				}
				continue
			}
			// TODO prefetch
			if scalar { // Scalar code
				for i := uint(0); i < n; i++ {
					currentFunc := firstFunc
					tempPacketAddr = packet.ExtractPacketAddr(InputMbufs[i])
					tempPacket = packet.ToPacket(tempPacketAddr)
					for {
						nextIndex := currentFunc.sFunc(tempPacket, currentFunc, context[currentFunc.contextIndex])
						if currentFunc.followingNumber == 0 {
							// We have constructSlice -> put packets to output slices
							OutputMbufs[nextIndex][countOfPackets[nextIndex]] = InputMbufs[i]
							countOfPackets[nextIndex]++
							break
						}
						currentFunc = currentFunc.next[nextIndex]
					}
				}
				for index := 0; index < outNumber; index++ {
					if countOfPackets[index] == 0 {
						continue
					}
					safeEnqueue(OUT[index], OutputMbufs[index], uint(countOfPackets[index]))
					currentSpeed += uint64(countOfPackets[index])
					countOfPackets[index] = 0
				}
			} else { // Vector code
				packet.ExtractPackets(tempPackets, InputMbufs, n)
				def[0].f = firstFunc
				for i := uint(0); i < burstSize; i++ {
					def[0].mask[i] = (i < n)
				}
				st := 0
				for st != -1 {
					cur := def[st].f
					cur.vFunc(tempPackets, &def[st].mask, &answers, cur, context[cur.contextIndex])
					if cur.followingNumber == 0 {
						// We have constructSlice -> put packets inside ring, it is an end of segment
						count := FillSliceFromMask(InputMbufs, &def[st].mask, OutputMbufs[0])
						safeEnqueue(OUT[answers[0]], OutputMbufs[0], uint(count))
						currentSpeed += uint64(count)
					} else if cur.followingNumber == 1 {
						// We have simple handle. Mask will remain the same, currect function will be changed
						def[st].f = cur.next[0]
						st++
					} else {
						step := 0
						for i := int(cur.followingNumber - 1); i >= 0; i-- {
							cont := asm.GenerateMask(&answers, &(vEach[i]), &def[st].mask, &def[st+i].mask)
							if !cont {
								def[st+i].f = cur.next[i]
								step++
							}
						}
						st += step
					}
					st--
				}
			}
		}
	}
}

func recvRSS(parameters interface{}, flag *int32, coreID int) {
	srp := parameters.(*receiveParameters)
	low.Receive(uint16(srp.port.PortId), int16(srp.port.QueuesNumber-1), srp.out, flag, coreID)
}

func recvKNI(parameters interface{}, flag *int32, coreID int) {
	srp := parameters.(*receiveParameters)
	low.Receive(uint16(srp.port.PortId), -1, srp.out, flag, coreID)
}

func generateOne(parameters interface{}, stopper [2]chan int) {
	gp := parameters.(*generateParameters)
	OUT := gp.out
	generateFunction := gp.generateFunction
	for {
		select {
		case <-stopper[0]:
			// It is time to close this clone
			stopper[1] <- 1
			return
		default:
			tempPacket, err := packet.NewPacket()
			if err != nil {
				common.LogFatal(common.Debug, err)
			}
			generateFunction(tempPacket, nil)
			safeEnqueueOne(OUT, tempPacket.ToUintptr())
		}
	}
}

func generatePerf(parameters interface{}, stopper [2]chan int, report chan uint64, context []UserContext) {
	gp := parameters.(*generateParameters)
	OUT := gp.out
	generateFunction := gp.generateFunction
	vectorGenerateFunction := gp.vectorGenerateFunction
	mempool := gp.mempool
	vector := (vectorGenerateFunction != nil)

	bufs := make([]uintptr, burstSize)
	var tempPacket *packet.Packet
	tempPackets := make([]*packet.Packet, burstSize)
	var currentSpeed uint64
	tick := time.Tick(time.Duration(schedTime) * time.Millisecond)
	var pause int
	for {
		select {
		case pause = <-stopper[0]:
			if pause == -1 {
				// It is time to close this clone
				if context[0] != nil {
					context[0].Delete()
				}
				stopper[1] <- 1
				return
			}
		case <-tick:
			report <- currentSpeed
			currentSpeed = 0
		default:
			err := low.AllocateMbufs(bufs, mempool, burstSize)
			if err != nil {
				common.LogFatal(common.Debug, err)
			}
			if vector == false {
				for i := range bufs {
					// TODO Maybe we need to prefetcht here?
					tempPacket = packet.ExtractPacket(bufs[i])
					generateFunction(tempPacket, context[0])
				}
			} else {
				packet.ExtractPackets(tempPackets, bufs, burstSize)
				vectorGenerateFunction(tempPackets, burstSize, context[0])
			}
			safeEnqueue(OUT, bufs, burstSize)
			currentSpeed = currentSpeed + uint64(burstSize)
			// GO parks goroutines while Sleep. So Sleep lasts more time than our precision
			// we just want to slow goroutine down without parking, so loop is OK for this.
			// time.Now lasts approximately 70ns and this satisfies us
			if pause != 0 {
				a := time.Now()
				for time.Since(a) < time.Duration(pause*int(burstSize))*time.Nanosecond {
				}
			}
		}
	}
}

// TODO reassembled packets are not supported
func pcopy(parameters interface{}, stopper [2]chan int, report chan uint64, context []UserContext) {
	cp := parameters.(*copyParameters)
	IN := cp.in
	OUT := cp.out
	OUTCopy := cp.outCopy
	mempool := cp.mempool

	bufs1 := make([]uintptr, burstSize)
	bufs2 := make([]uintptr, burstSize)
	var tempPacket1 *packet.Packet
	var tempPacket2 *packet.Packet
	var currentSpeed uint64
	tick := time.Tick(time.Duration(schedTime) * time.Millisecond)
	var pause int

	for {
		select {
		case pause = <-stopper[0]:
			if pause == -1 {
				// It is time to remove this clone
				stopper[1] <- 1
				return
			}
		case <-tick:
			report <- currentSpeed
			currentSpeed = 0
		default:
			n := IN.DequeueBurst(bufs1, burstSize)
			if n != 0 {
				if err := low.AllocateMbufs(bufs2, mempool, n); err != nil {
					common.LogFatal(common.Debug, err)
				}
				for i := range bufs1 {
					// TODO Maybe we need to prefetcht here?
					tempPacket1 = packet.ExtractPacket(bufs1[i])
					tempPacket2 = packet.ExtractPacket(bufs2[i])
					packet.GeneratePacketFromByte(tempPacket2, tempPacket1.GetRawPacketBytes())
				}
				safeEnqueue(OUT, bufs1, uint(n))
				safeEnqueue(OUTCopy, bufs2, uint(n))
				currentSpeed = currentSpeed + uint64(n)
			}
			// GO parks goroutines while Sleep. So Sleep lasts more time than our precision
			// we just want to slow goroutine down without parking, so loop is OK for this.
			// time.Now lasts approximately 70ns and this satisfies us
			if pause != 0 {
				a := time.Now()
				for time.Since(a) < time.Duration(pause*int(burstSize))*time.Nanosecond {
				}
			}
		}
	}
}

func send(parameters interface{}, flag *int32, coreID int) {
	srp := parameters.(*sendParameters)
	low.Send(srp.port, srp.queue, srp.in, flag, coreID)
}

func merge(from *low.Ring, to *low.Ring) {
	// We should change out rings in all flow functions which we added before
	// and change them to one "after merge" ring.
	// We don't proceed stop and send functions here because they don't have
	// out rings. Also we don't proceed merge function because they are added
	// strictly one after another. The next merge will change previous "after merge"
	// ring automatically.
	for i := range schedState.ff {
		switch schedState.ff[i].Parameters.(type) {
		case *receiveParameters:
			if schedState.ff[i].Parameters.(*receiveParameters).out == from {
				schedState.ff[i].Parameters.(*receiveParameters).out = to
			}
		case *generateParameters:
			if schedState.ff[i].Parameters.(*generateParameters).out == from {
				schedState.ff[i].Parameters.(*generateParameters).out = to
			}
		case *readParameters:
			if schedState.ff[i].Parameters.(*readParameters).out == from {
				schedState.ff[i].Parameters.(*readParameters).out = to
			}
		case *copyParameters:
			if schedState.ff[i].Parameters.(*copyParameters).out == from {
				schedState.ff[i].Parameters.(*copyParameters).out = to
			}
			if schedState.ff[i].Parameters.(*copyParameters).outCopy == from {
				schedState.ff[i].Parameters.(*copyParameters).outCopy = to
			}
		}
	}
}

func separate(packet *packet.Packet, sc *Func, ctx UserContext) uint {
	if sc.sSeparateFunction(packet, ctx) == true {
		return 0
	}
	return 1
}

func vSeparate(packets []*packet.Packet, mask *[burstSize]bool, answers *[burstSize]uint8, ve *Func, ctx UserContext) {
	ve.vSeparateFunction(packets, mask, answers, ctx)
}

// partition doesn't need packets - just mbufs. However it will probably be
// among other functions. So this overhead is not much.
func partition(packet *packet.Packet, sc *Func, ctx UserContext) uint {
	context := ctx.(*partitionCtx)
	context.currentPacketNumber++
	if context.currentPacketNumber == context.currentCompare {
		context.currentAnswer = context.currentAnswer ^ 1
		context.currentCompare = context.N + context.M - context.currentCompare
		context.currentPacketNumber = 0
	}
	return uint(context.currentAnswer)
}

func vPartition(packets []*packet.Packet, mask *[burstSize]bool, answers *[burstSize]uint8, ve *Func, ctx UserContext) {
	context := ctx.(*partitionCtx)
	for i := 0; i < burstSize; i++ {
		if (*mask)[i] {
			context.currentPacketNumber++
			if context.currentPacketNumber == context.currentCompare {
				context.currentAnswer = context.currentAnswer ^ 1
				context.currentCompare = context.N + context.M - context.currentCompare
				context.currentPacketNumber = 0
				answers[i] = context.currentAnswer
			}
		}
	}
}

func split(packet *packet.Packet, sc *Func, ctx UserContext) uint {
	return sc.sSplitFunction(packet, ctx)
}

func vSplit(packets []*packet.Packet, mask *[burstSize]bool, answers *[burstSize]uint8, ve *Func, ctx UserContext) {
	ve.vSplitFunction(packets, mask, answers, ctx)
}

func handle(packet *packet.Packet, sc *Func, ctx UserContext) uint {
	sc.sHandleFunction(packet, ctx)
	return 0
}

func vHandle(packets []*packet.Packet, mask *[burstSize]bool, answers *[burstSize]uint8, ve *Func, ctx UserContext) {
	ve.vHandleFunction(packets, mask, ctx)
}

func constructSlice(packet *packet.Packet, sc *Func, ctx UserContext) uint {
	return sc.bufIndex
}

func vConstructSlice(packets []*packet.Packet, mask *[burstSize]bool, answers *[burstSize]uint8, ve *Func, ctx UserContext) {
	answers[0] = uint8(ve.bufIndex)
}

func write(parameters interface{}, stopper [2]chan int) {
	wp := parameters.(*writeParameters)
	IN := wp.in
	filename := wp.filename

	bufIn := make([]uintptr, 1)
	var tempPacket *packet.Packet

	f, err := os.Create(filename)
	if err != nil {
		common.LogFatal(common.Debug, err)
	}
	defer f.Close()

	err = packet.WritePcapGlobalHdr(f)
	if err != nil {
		common.LogFatal(common.Debug, err)
	}
	for {
		select {
		case <-stopper[0]:
			// It is time to close this clone
			stopper[1] <- 1
			return
		default:
			n := IN.DequeueBurst(bufIn, 1)
			if n == 0 {
				continue
			}
			tempPacket = packet.ExtractPacket(bufIn[0])
			err := tempPacket.WritePcapOnePacket(f)
			if err != nil {
				common.LogFatal(common.Debug, err)
			}
			low.DirectStop(1, bufIn)
		}
	}
}

func read(parameters interface{}, stopper [2]chan int) {
	rp := parameters.(*readParameters)
	OUT := rp.out
	filename := rp.filename
	repcount := rp.repcount

	f, err := os.Open(filename)
	if err != nil {
		common.LogFatal(common.Debug, err)
	}
	defer f.Close()

	// Read pcap global header once
	var glHdr packet.PcapGlobHdr
	if err := packet.ReadPcapGlobalHdr(f, &glHdr); err != nil {
		common.LogFatal(common.Debug, err)
	}

	count := int32(0)

	for {
		select {
		case <-stopper[0]:
			// It is time to close this clone
			stopper[1] <- 1
			return
		default:
			tempPacket, err := packet.NewPacket()
			if err != nil {
				common.LogFatal(common.Debug, err)
			}
			isEOF, err := tempPacket.ReadPcapOnePacket(f)
			if err != nil {
				common.LogFatal(common.Debug, err)
			}
			if isEOF {
				atomic.AddInt32(&count, 1)
				if count == repcount {
					break
				}
				if _, err := f.Seek(packet.PcapGlobHdrSize, 0); err != nil {
					common.LogFatal(common.Debug, err)
				}
				if _, err := tempPacket.ReadPcapOnePacket(f); err != nil {
					common.LogFatal(common.Debug, err)
				}
			}
			// TODO we need packet reassembly here. However we don't
			// use mbuf packet_type here, so it is impossible.
			safeEnqueueOne(OUT, tempPacket.ToUintptr())
		}
	}
}

// This function tries to write elements to input ring. However
// if this ring can't get these elements they will be placed
// inside stop ring which is emptied in separate thread.
func safeEnqueue(place *low.Ring, data []uintptr, number uint) {
	done := place.EnqueueBurst(data, number)
	if done < number {
		schedState.Dropped += number - uint(done)
		done2 := schedState.StopRing.EnqueueBurst(data[done:number], number-uint(done))
		// If stop ring is crowded a function will call C stop directly without
		// moving forward. It prevents constant crowd stop and increases
		// performance on "long accelerating" topologies in 1.5x times.
		if done2 < number-uint(done) {
			common.LogWarning(common.Verbose, "Normal fast stop is crowded. Use slow C stop instead.")
			low.DirectStop(int(number-uint(done)-uint(done2)), data[done+done2:number])
		}
	}
	// TODO we need to investigate whether we need to return actual number of enqueued packets.
	// We can use this number if controlling speed, however it is not clear what is better:
	// to use actual number or to use simply number of packets processed by a function like now.
}

// This function makes []uintptr and is inefficient. Only for non-performance critical tasks
func safeEnqueueOne(place *low.Ring, data uintptr) {
	slice := make([]uintptr, 1, 1)
	slice[0] = data
	safeEnqueue(place, slice, 1)
}

func checkFlow(f *Flow) error {
	if f == nil {
		return common.WrapWithNFError(nil, "One of the flows is nil!", common.UseNilFlowErr)
	}
	if f.current == nil && f.previous == nil {
		return common.WrapWithNFError(nil, "One of the flows is used after it was closed!", common.UseClosedFlowErr)
	}
	return nil
}

// CreateKniDevice creates KNI device for using in receive or send functions.
// Gets port, core (not from NFF-GO list), and unique name of future KNI device.
func CreateKniDevice(portId uint16, core uint8, name string) *Kni {
	low.CreateKni(portId, core, name)
	kni := new(Kni)
	// Port will be identifier of this KNI
	// KNI structure itself is stored inside low.c
	kni.portId = portId
	return kni
}

func FillSliceFromMask(input []uintptr, mask *[burstSize]bool, output []uintptr) uint8 {
	count := 0
	for i := 0; i < burstSize; i++ {
		if (*mask)[i] != false {
			output[count] = input[i]
			count++
		}
	}
	return uint8(count)
}

// CheckFatal is a default error handling function, which prints error message and
// makes os.Exit in case of non nil error. Any other error handler can be used instead.
func CheckFatal(err error) {
	if err != nil {
		common.LogFatal(common.Debug, "fail with error: %+v\n", err)
	}
}
