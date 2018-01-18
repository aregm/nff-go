// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package flow provides functionality for constructing packet processing graph

// Preparations of construction:
// All construction should be between SystemInit and SystemStart functions.
// User command line options should be added as flags before SystemInit option - it will
// parse them as well as internal library options.

// Packet processing graph construction:
// YANFF library provides nine so-called Flow Functions for packet processing graph
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

// Package flow is the main package of YANFF library and should be always imported by
// user application.
package flow

import (
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/intel-go/yanff/asm"
	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/low"
	"github.com/intel-go/yanff/packet"
	"github.com/intel-go/yanff/scheduler"
)

var openFlowsNumber = uint32(0)
var ringName = 1
var ffCount = 0
var createdPorts []port

// UserContext is a type which should be passed to all flow functions.
type UserContext scheduler.UserContext

// Flow is an abstraction for connecting flow functions with each other.
// Flow shouldn't be understood in any way beyond this.
type Flow struct {
	current *low.Ring
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

// VectorHandleFunction is a function type like GenerateFunction for vector handling
type VectorHandleFunction func([]*packet.Packet, uint, UserContext)

// SeparateFunction is a function type for user defined function which separates packets
// based on some rule for two flows. Functions receives a packet from flow.
// User should parse it and decide whether this packet should remains in
// this flow - return true, or should be sent to new added flow - return false.
type SeparateFunction func(*packet.Packet, UserContext) bool

// VectorSeparateFunction is a function type like GenerateFunction for vector separation
type VectorSeparateFunction func([]*packet.Packet, []bool, uint, UserContext)

// SplitFunction is a function type for user defined function which splits packets
// based in some rule for multiple flows. Function receives a packet from
// flow. User should parse it and decide in which output flows this packet
// should be sent. Return number of flow shouldn't exceed target number
// which was put to SetSplitter function. Also it is assumed that "0"
// output flow is used for dropping packets - "Stop" function should be
// set after "Split" function in it.
type SplitFunction func(*packet.Packet, UserContext) uint

// Kni is a high level struct of KNI device. The device itself is stored
// in C memory in low.c and is defined by its port which is equal to port
// in this structure
type Kni struct {
	port uint8
}

type receiveParameters struct {
	out   *low.Ring
	queue int16
	port  uint8
}

func makeReceiver(port uint8, queue int16, out *low.Ring) *scheduler.FlowFunction {
	par := new(receiveParameters)
	par.port = port
	par.queue = queue
	par.out = out
	ffCount++
	return schedState.NewUnclonableFlowFunction("receiver", ffCount, receive, par)
}

type generateParameters struct {
	out                    *low.Ring
	generateFunction       GenerateFunction
	vectorGenerateFunction VectorGenerateFunction
	mempool                *low.Mempool
}

func makeGenerator(out *low.Ring, generateFunction GenerateFunction) *scheduler.FlowFunction {
	par := new(generateParameters)
	par.out = out
	par.generateFunction = generateFunction
	par.mempool = low.CreateMempool()
	ffCount++
	return schedState.NewUnclonableFlowFunction("generator", ffCount, generateOne, par)
}

func makeFastGenerator(out *low.Ring, generateFunction GenerateFunction,
	vectorGenerateFunction VectorGenerateFunction, targetSpeed uint64, context UserContext) *scheduler.FlowFunction {
	par := new(generateParameters)
	par.out = out
	par.generateFunction = generateFunction
	par.mempool = low.CreateMempool()
	par.vectorGenerateFunction = vectorGenerateFunction
	ffCount++
	return schedState.NewGenerateFlowFunction("fast generator", ffCount, generatePerf, par, float64(targetSpeed), make(chan uint64, 50), context)
}

type sendParameters struct {
	in    *low.Ring
	queue int16
	port  uint8
}

func makeSender(port uint8, queue int16, in *low.Ring) *scheduler.FlowFunction {
	par := new(sendParameters)
	par.port = port
	par.queue = queue
	par.in = in
	ffCount++
	return schedState.NewUnclonableFlowFunction("sender", ffCount, send, par)
}

type copyParameters struct {
	in      *low.Ring
	out     *low.Ring
	outCopy *low.Ring
	mempool *low.Mempool
}

func makeCopier(in *low.Ring, out *low.Ring, outCopy *low.Ring) *scheduler.FlowFunction {
	par := new(copyParameters)
	par.in = in
	par.out = out
	par.outCopy = outCopy
	par.mempool = low.CreateMempool()
	ffCount++
	return schedState.NewClonableFlowFunction("copy", ffCount, pcopy, par, copyCheck, make(chan uint64, 50), nil)
}

type partitionParameters struct {
	in        *low.Ring
	outFirst  *low.Ring
	outSecond *low.Ring
	N         uint64
	M         uint64
}

func makePartitioner(in *low.Ring, outFirst *low.Ring, outSecond *low.Ring, N uint64, M uint64) *scheduler.FlowFunction {
	par := new(partitionParameters)
	par.in = in
	par.outFirst = outFirst
	par.outSecond = outSecond
	par.N = N
	par.M = M
	ffCount++
	return schedState.NewUnclonableFlowFunction("partitioner", ffCount, partition, par)
}

type separateParameters struct {
	in                     *low.Ring
	outTrue                *low.Ring
	outFalse               *low.Ring
	separateFunction       SeparateFunction
	vectorSeparateFunction VectorSeparateFunction
}

func makeSeparator(in *low.Ring, outTrue *low.Ring, outFalse *low.Ring,
	separateFunction SeparateFunction, vectorSeparateFunction VectorSeparateFunction,
	name string, context UserContext) *scheduler.FlowFunction {
	par := new(separateParameters)
	par.in = in
	par.outTrue = outTrue
	par.outFalse = outFalse
	par.separateFunction = separateFunction
	par.vectorSeparateFunction = vectorSeparateFunction
	ffCount++
	return schedState.NewClonableFlowFunction(name, ffCount, separate, par, separateCheck, make(chan uint64, 50), context)
}

type splitParameters struct {
	in            *low.Ring
	outs          []*low.Ring
	splitFunction SplitFunction
	flowNumber    uint
}

func makeSplitter(in *low.Ring, outs []*low.Ring,
	splitFunction SplitFunction, flowNumber uint, context UserContext) *scheduler.FlowFunction {
	par := new(splitParameters)
	par.in = in
	par.outs = outs
	par.splitFunction = splitFunction
	par.flowNumber = flowNumber
	ffCount++
	return schedState.NewClonableFlowFunction("splitter", ffCount, split, par, splitCheck, make(chan uint64, 50), context)
}

type handleParameters struct {
	in                   *low.Ring
	out                  *low.Ring
	handleFunction       HandleFunction
	vectorHandleFunction VectorHandleFunction
}

func makeHandler(in *low.Ring, out *low.Ring,
	handleFunction HandleFunction, vectorHandleFunction VectorHandleFunction,
	name string, context UserContext) *scheduler.FlowFunction {
	par := new(handleParameters)
	par.in = in
	par.out = out
	par.handleFunction = handleFunction
	par.vectorHandleFunction = vectorHandleFunction
	ffCount++
	return schedState.NewClonableFlowFunction(name, ffCount, handle, par, handleCheck, make(chan uint64, 50), context)
}

type writeParameters struct {
	in       *low.Ring
	filename string
}

func makeWriter(filename string, in *low.Ring) *scheduler.FlowFunction {
	par := new(writeParameters)
	par.in = in
	par.filename = filename
	ffCount++
	return schedState.NewUnclonableFlowFunction("writer", ffCount, write, par)
}

type readParameters struct {
	out      *low.Ring
	filename string
	mempool  *low.Mempool
	repcount int32
}

func makeReader(filename string, out *low.Ring, repcount int32) *scheduler.FlowFunction {
	par := new(readParameters)
	par.out = out
	par.filename = filename
	par.mempool = low.CreateMempool()
	par.repcount = repcount
	ffCount++
	return schedState.NewUnclonableFlowFunction("reader", ffCount, read, par)
}

var burstSize uint
var sizeMultiplier uint
var schedTime uint
var maxPacketsToClone uint32
var hwtxchecksum bool

type port struct {
	rxQueues       []bool
	txQueues       []bool
	config         int
	rxQueuesNumber int16
	txQueuesNumber int16
	port           uint8
}

var schedState scheduler.Scheduler

// Flow port types
const (
	inactivePort = iota
	autoPort
)

// Config is a struct with all parameters, which user can pass to YANFF library
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
	// Number of BurstSize groups in all rings. This should be power
	// of 2. Default value is 256.
	RingSize uint
	// Time between scheduler actions in miliseconds. Default value is
	// 1500.
	ScaleTime uint
	// Number of mbufs per one enqueue / dequeue from ring. Default
	// value is tested for performance and not recommended to
	// change. Default value is 32.
	BurstSize uint
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
// Function can panic during execution.
func SystemInit(args *Config) error {
	CPUCoresNumber := uint(runtime.GOMAXPROCS(0))
	var cpus []uint
	var err error
	if args.CPUList != "" {
		if cpus, err = common.ParseCPUs(args.CPUList, CPUCoresNumber); err != nil {
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

	burstSize = 32
	if args.BurstSize != 0 {
		burstSize = args.BurstSize
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
	maxPacketsToClone = uint32(sizeMultiplier * burstSize / 5 * 4)
	// TODO all low level initialization here! Now everything is default.
	// Init eal
	common.LogTitle(common.Initialization, "------------***-------- Initializing DPDK --------***------------")
	low.InitDPDK(argc, argv, burstSize, mbufNumber, mbufCacheSize, needKNI)
	// Init Ports
	common.LogTitle(common.Initialization, "------------***-------- Initializing ports -------***------------")
	createdPorts = make([]port, low.GetPortsNumber(), low.GetPortsNumber())
	for i := range createdPorts {
		createdPorts[i].port = uint8(i)
		createdPorts[i].config = inactivePort
	}
	// Init scheduler
	common.LogTitle(common.Initialization, "------------***------ Initializing scheduler -----***------------")
	StopRing := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	common.LogDebug(common.Initialization, "Scheduler can use cores:", cpus)
	schedState = scheduler.NewScheduler(cpus, schedulerOff, schedulerOffRemove, stopDedicatedCore, StopRing, checkTime, debugTime)
	common.LogTitle(common.Initialization, "------------***------ Filling FlowFunctions ------***------------")
	// Init packet processing
	packet.SetHWTXChecksumFlag(hwtxchecksum)
	return nil
}

// SystemStart starts system - begin packet receiving and packet sending.
// This functions should be always called after flow graph construction.
// Function can panic during execution.
func SystemStart() error {
	common.LogTitle(common.Initialization, "------------***--------- Checking system ---------***------------")
	if err := checkSystem(); err != nil {
		return err
	}
	common.LogTitle(common.Initialization, "------------***---------- Creating ports ---------***------------")
	for i := range createdPorts {
		if createdPorts[i].config != inactivePort {
			if err := low.CreatePort(createdPorts[i].port, uint16(createdPorts[i].rxQueuesNumber),
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
	if err := schedState.SystemStart(); err != nil {
		return common.WrapWithNFError(err, "scheduler start failed", common.Fail)
	}
	common.LogTitle(common.Initialization, "------------***--------- YANFF-GO Started --------***------------")
	schedState.Schedule(schedTime)
	return nil
}

func generateRingName() string {
	s := strconv.Itoa(ringName)
	ringName++
	return s
}

// SetSenderFile adds write function to flow graph.
// Gets flow which packets will be written to file and
// target file name.
// Function can panic during execution.
func SetSenderFile(IN *Flow, filename string) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	write := makeWriter(filename, IN.current)
	schedState.UnClonable = append(schedState.UnClonable, write)
	IN.current = nil
	openFlowsNumber--
	return nil
}

// SetReceiverFile adds read function to flow graph.
// Gets name of pcap formatted file and number of reads. If repcount = -1,
// file is read infinitely in circle.
// Returns new opened flow with read packets.
// Function can panic during execution.
func SetReceiverFile(filename string, repcount int32) (OUT *Flow) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	read := makeReader(filename, ring, repcount)
	schedState.UnClonable = append(schedState.UnClonable, read)
	OUT = new(Flow)
	OUT.current = ring
	openFlowsNumber++
	return OUT
}

// SetReceiver adds receive function to flow graph.
// Gets port number from which packets will be received.
// Receive queue will be added to port automatically.
// Returns new opened flow with received packets
// Function can panic during execution.
func SetReceiver(port uint8) (OUT *Flow, err error) {
	if port >= uint8(len(createdPorts)) {
		return nil, common.WrapWithNFError(nil, "Requested receive port exceeds number of ports which can be used by DPDK (bind to DPDK).", common.ReqTooManyPorts)
	}
	createdPorts[port].config = autoPort
	createdPorts[port].rxQueues = append(createdPorts[port].rxQueues, true)
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	recv := makeReceiver(port, createdPorts[port].rxQueuesNumber, ring)
	schedState.UnClonable = append(schedState.UnClonable, recv)
	OUT = new(Flow)
	OUT.current = ring
	openFlowsNumber++
	createdPorts[port].rxQueuesNumber++
	return OUT, nil
}

// SetReceiverKNI adds function receive from KNI to flow graph.
// Gets KNI device from which packets will be received.
// Receive queue will be added to port automatically.
// Returns new opened flow with received packets
// Function can panic during execution.
func SetReceiverKNI(kni *Kni) (OUT *Flow) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	recvKni := makeReceiver(kni.port, -1, ring)
	schedState.UnClonable = append(schedState.UnClonable, recvKni)
	OUT = new(Flow)
	OUT.current = ring
	openFlowsNumber++
	return OUT
}

// SetFastGenerator adds clonable generate function to flow graph.
// Gets user-defined generate function, target speed of generation user wants to achieve and context.
// Returns new open flow with generated packets.
// Function tries to achieve target speed by cloning.
// Function can panic during execution.
func SetFastGenerator(f func(*packet.Packet, UserContext), targetSpeed uint64, context UserContext) (OUT *Flow, err error) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	var generate *scheduler.FlowFunction
	if targetSpeed > 0 {
		generate = makeFastGenerator(ring, GenerateFunction(f), nil, targetSpeed, context)
	} else {
		return nil, common.WrapWithNFError(nil, "Target speed value should be > 0", common.BadArgument)
	}
	schedState.Generate = append(schedState.Generate, generate)
	OUT = new(Flow)
	OUT.current = ring
	openFlowsNumber++
	return OUT, nil
}

// SetVectorFastGenerator adds clonable vector generate function to flow graph.
// Gets user-defined vector generate function, target speed of generation user wants to achieve and context.
// Returns new open flow with generated packets.
// Function tries to achieve target speed by cloning.
// Function can panic during execution.
func SetVectorFastGenerator(f func([]*packet.Packet, uint, UserContext), targetSpeed uint64, context UserContext) (OUT *Flow, err error) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	var generate *scheduler.FlowFunction
	if targetSpeed > 0 {
		generate = makeFastGenerator(ring, nil, VectorGenerateFunction(f), targetSpeed, context)
	} else {
		return nil, common.WrapWithNFError(nil, "Target speed value should be > 0", common.BadArgument)
	}
	schedState.Generate = append(schedState.Generate, generate)
	OUT = new(Flow)
	OUT.current = ring
	openFlowsNumber++
	return OUT, nil
}

// SetGenerator adds non-clonable generate flow function to flow graph.
// Gets user-defined generate function and context.
// Returns new open flow with generated packets.
// Single packet non-clonable flow function will be added. It can be used for waiting of
// input user packets.
// Function can panic during execution.
func SetGenerator(f func(*packet.Packet, UserContext), context UserContext) (OUT *Flow) {
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	generate := makeGenerator(ring, GenerateFunction(f))
	schedState.UnClonable = append(schedState.UnClonable, generate)
	OUT = new(Flow)
	OUT.current = ring
	openFlowsNumber++
	return OUT
}

// SetSender adds send function to flow graph.
// Gets flow which will be closed and its packets will be send and port number for which packets will be sent.
// Send queue will be added to port automatically.
// Function can panic during execution.
func SetSender(IN *Flow, port uint8) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	if port >= uint8(len(createdPorts)) {
		return common.WrapWithNFError(nil, "Requested send port exceeds number of ports which can be used by DPDK (bind to DPDK).", common.ReqTooManyPorts)
	}
	createdPorts[port].config = autoPort
	createdPorts[port].txQueues = append(createdPorts[port].txQueues, true)
	send := makeSender(port, createdPorts[port].txQueuesNumber, IN.current)
	createdPorts[port].txQueuesNumber++
	schedState.UnClonable = append(schedState.UnClonable, send)
	IN.current = nil
	openFlowsNumber--
	return nil
}

// SetSenderKNI adds function sending to KNI to flow graph.
// Gets flow which will be closed and its packets will be send to given KNI device.
// Send queue will be added to port automatically.
// Function can panic during execution.
func SetSenderKNI(IN *Flow, kni *Kni) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	sendKni := makeSender(kni.port, -1, IN.current)
	schedState.UnClonable = append(schedState.UnClonable, sendKni)
	IN.current = nil
	openFlowsNumber--
	return nil
}

// SetCopier adds copy function to flow graph.
// Gets flow which will be copied.
// Function can panic during execution.
func SetCopier(IN *Flow) (OUT *Flow, err error) {
	if err := checkFlow(IN); err != nil {
		return nil, err
	}
	OUT = new(Flow)

	ringFirst := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	ringSecond := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	openFlowsNumber++
	pcopy := makeCopier(IN.current, ringFirst, ringSecond)

	schedState.Clonable = append(schedState.Clonable, pcopy)
	IN.current = ringFirst
	OUT.current = ringSecond
	return OUT, nil
}

// SetPartitioner adds partition function to flow graph.
// Gets input flow and N and M constants. Returns new opened flow.
// Each loop N packets will be remained in input flow, next M packets will be sent to new flow.
// It is advised not to use this function less then (75, 75) for performance reasons.
// Function can panic during execution.
func SetPartitioner(IN *Flow, N uint64, M uint64) (OUT *Flow, err error) {
	if err := checkFlow(IN); err != nil {
		return nil, err
	}
	OUT = new(Flow)
	if N == 0 || M == 0 {
		common.LogWarning(common.Initialization, "One of SetPartitioner function's arguments is zero.")
	}
	ringFirst := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	ringSecond := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	openFlowsNumber++
	partition := makePartitioner(IN.current, ringFirst, ringSecond, N, M)
	// We make partition function unclonable. The most complex task is (1,1).
	// It means that if you would like to simply divide a flow
	// it is recommended to use (75,75) instead of (1,1) for performance reasons.
	schedState.UnClonable = append(schedState.UnClonable, partition)
	IN.current = ringFirst
	OUT.current = ringSecond
	return OUT, nil
}

// SetSeparator adds separate function to flow graph.
// Gets flow, user defined separate function and context. Returns new opened flow.
// Each packet from input flow will be remain inside input packet if
// user defined function returns "true" and is sent to new flow otherwise.
// Function can panic during execution.
func SetSeparator(IN *Flow, f func(*packet.Packet, UserContext) bool, context UserContext) (OUT *Flow, err error) {
	if err := checkFlow(IN); err != nil {
		return nil, err
	}
	OUT = new(Flow)
	ringTrue := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	ringFalse := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	openFlowsNumber++

	separate := makeSeparator(IN.current, ringTrue, ringFalse, SeparateFunction(f), nil, "separator", context)
	schedState.Clonable = append(schedState.Clonable, separate)
	IN.current = ringTrue
	OUT.current = ringFalse
	return OUT, nil
}

// SetVectorSeparator adds vector separate function to flow graph.
// Gets flow, user defined vector separate function and context. Returns new opened flow.
// Each packet from input flow will be remain inside input packet if
// user defined function returns "true" and is sent to new flow otherwise.
// Function can panic during execution.
func SetVectorSeparator(IN *Flow, f func([]*packet.Packet, []bool, uint, UserContext), context UserContext) (OUT *Flow, err error) {
	if err := checkFlow(IN); err != nil {
		return nil, err
	}
	OUT = new(Flow)
	ringTrue := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	ringFalse := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	openFlowsNumber++

	separate := makeSeparator(IN.current, ringTrue, ringFalse, nil, VectorSeparateFunction(f), "vector separator", context)
	schedState.Clonable = append(schedState.Clonable, separate)
	IN.current = ringTrue
	OUT.current = ringFalse
	return OUT, nil
}

// SetSplitter adds split function to flow graph.
// Gets flow, user defined split function, flowNumber of new flows and context.
// Returns array of new opened flows with corresponding length.
// Each packet from input flow will be sent to one of new flows based on
// user defined function output for this packet.
// Function can panic during execution.
func SetSplitter(IN *Flow, splitFunction SplitFunction, flowNumber uint, context UserContext) (OutArray [](*Flow), err error) {
	if err := checkFlow(IN); err != nil {
		return nil, err
	}
	OutArray = make([](*Flow), flowNumber, flowNumber)
	rings := make([](*low.Ring), flowNumber, flowNumber)
	for i := range OutArray {
		OutArray[i] = new(Flow)
		openFlowsNumber++
		rings[i] = low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
		OutArray[i].current = rings[i]
	}
	split := makeSplitter(IN.current, rings, splitFunction, flowNumber, context)
	schedState.Clonable = append(schedState.Clonable, split)
	IN.current = nil
	openFlowsNumber--
	return OutArray, nil
}

// SetStopper adds stop function to flow graph.
// Gets flow which will be closed and all packets from each will be dropped.
// Function can panic during execution.
func SetStopper(IN *Flow) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	merge(IN.current, schedState.StopRing)
	IN.current = nil
	openFlowsNumber--
	return nil
}

// SetHandler adds handle function to flow graph.
// Gets flow, user defined handle function and context.
// Each packet from input flow will be handle inside user defined function
// and sent further in the same flow.
// Function can panic during execution.
func SetHandler(IN *Flow, f func(*packet.Packet, UserContext), context UserContext) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	handle := makeHandler(IN.current, ring, HandleFunction(f), nil, "handler", context)
	schedState.Clonable = append(schedState.Clonable, handle)
	IN.current = ring
	return nil
}

// SetVectorHandler adds vector handle function to flow graph.
// Gets flow, user defined vector handle function and context.
// Each packet from input flow will be handle inside user defined function
// and sent further in the same flow.
// Function can panic during execution.
func SetVectorHandler(IN *Flow, f func([]*packet.Packet, uint, UserContext), context UserContext) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	handle := makeHandler(IN.current, ring, nil, VectorHandleFunction(f), "vector handler", context)
	schedState.Clonable = append(schedState.Clonable, handle)
	IN.current = ring
	return nil
}

// SetHandlerDrop adds vector handle function to flow graph.
// Gets flow, user defined handle function and context.
// User defined function can return boolean value.
// If user function returns false after handling a packet it is dropped automatically.
// Function can panic during execution.
func SetHandlerDrop(IN *Flow, f func(*packet.Packet, UserContext) bool, context UserContext) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	handle := makeSeparator(IN.current, ring, schedState.StopRing, SeparateFunction(f), nil, "handler", context)
	schedState.Clonable = append(schedState.Clonable, handle)
	IN.current = ring
	return nil
}

// SetVectorHandlerDrop adds vector handle function to flow graph.
// Gets flow, user defined vector handle function and context.
// User defined function can return boolean value.
// If user function returns false after handling a packet it is dropped automatically.
// Function can panic during execution.
func SetVectorHandlerDrop(IN *Flow, f func([]*packet.Packet, []bool, uint, UserContext), context UserContext) error {
	if err := checkFlow(IN); err != nil {
		return err
	}
	ring := low.CreateRing(generateRingName(), burstSize*sizeMultiplier)
	handle := makeSeparator(IN.current, ring, schedState.StopRing, nil, VectorSeparateFunction(f), "vector handler", context)
	schedState.Clonable = append(schedState.Clonable, handle)
	IN.current = ring
	return nil
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
		merge(InArray[i].current, ring)
		InArray[i].current = nil
		openFlowsNumber--
	}
	OUT = new(Flow)
	OUT.current = ring
	openFlowsNumber++
	return OUT, nil
}

// GetPortMACAddress returns default MAC address of an Ethernet port.
func GetPortMACAddress(port uint8) [common.EtherAddrLen]uint8 {
	return low.GetPortMACAddress(port)
}

func receive(parameters interface{}, coreID uint8) {
	srp := parameters.(*receiveParameters)
	low.Receive(srp.port, srp.queue, srp.out, coreID)
}

func generateOne(parameters interface{}, core uint8) {
	gp := parameters.(*generateParameters)
	OUT := gp.out
	generateFunction := gp.generateFunction
	mempool := gp.mempool
	low.SetAffinity(core)

	buf := make([]uintptr, 1)
	var tempPacket *packet.Packet

	for {
		err := low.AllocateMbufs(buf, mempool, 1)
		if err != nil {
			common.LogFatal(common.Debug, err)
		}
		tempPacket = packet.ExtractPacket(buf[0])
		generateFunction(tempPacket, nil)
		safeEnqueue(OUT, buf, 1)
	}
}

func generatePerf(parameters interface{}, stopper chan int, report chan uint64, context scheduler.UserContext) {
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
		case pause = <-stopper:
			if pause == -1 {
				// It is time to close this clone
				close(stopper)
				if context != nil {
					context.Delete()
				}
				// We don't close report channel because all clones of one function use it.
				// As one function entity will be working endlessly we don't close it anywhere.
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
					generateFunction(tempPacket, context)
				}
			} else {
				packet.ExtractPackets(tempPackets, bufs, burstSize)
				vectorGenerateFunction(tempPackets, burstSize, context)
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

func copyCheck(parameters interface{}, debug bool) bool {
	cp := parameters.(*copyParameters)
	IN := cp.in
	if debug == true {
		common.LogDebug(common.Debug, "Number of packets in queue for copy: ", IN.GetRingCount())
	}
	if IN.GetRingCount() > maxPacketsToClone {
		return true
	}
	return false
}

// TODO reassembled packets are not supported
func pcopy(parameters interface{}, stopper chan int, report chan uint64, context scheduler.UserContext) {
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
		case pause = <-stopper:
			if pause == -1 {
				// It is time to close this clone
				close(stopper)
				// We don't close report channel because all clones of one function use it.
				// As one function entity will be working endlessly we don't close it anywhere.
				return
			}
		case <-tick:
			report <- currentSpeed
			currentSpeed = 0
		default:
			n := IN.DequeueBurst(bufs1, burstSize)
			if n != 0 {
				low.AllocateMbufs(bufs2, mempool, n)
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

func send(parameters interface{}, coreID uint8) {
	srp := parameters.(*sendParameters)
	low.Send(srp.port, srp.queue, srp.in, coreID)
}

func merge(from *low.Ring, to *low.Ring) {
	// We should change out rings in all flow functions which we added before
	// and change them to one "after merge" ring.
	// We don't proceed stop and send functions here because they don't have
	// out rings. Also we don't proceed merge function because they are added
	// strictly one after another. The next merge will change previous "after merge"
	// ring automatically.
	for i := range schedState.UnClonable {
		switch schedState.UnClonable[i].Parameters.(type) {
		case *receiveParameters:
			if schedState.UnClonable[i].Parameters.(*receiveParameters).out == from {
				schedState.UnClonable[i].Parameters.(*receiveParameters).out = to
			}
		case *partitionParameters:
			if schedState.UnClonable[i].Parameters.(*partitionParameters).outFirst == from {
				schedState.UnClonable[i].Parameters.(*partitionParameters).outFirst = to
			}
			if schedState.UnClonable[i].Parameters.(*partitionParameters).outSecond == from {
				schedState.UnClonable[i].Parameters.(*partitionParameters).outSecond = to
			}
		case *generateParameters:
			if schedState.UnClonable[i].Parameters.(*generateParameters).out == from {
				schedState.UnClonable[i].Parameters.(*generateParameters).out = to
			}
		case *readParameters:
			if schedState.UnClonable[i].Parameters.(*readParameters).out == from {
				schedState.UnClonable[i].Parameters.(*readParameters).out = to
			}
		case *copyParameters:
			if schedState.UnClonable[i].Parameters.(*copyParameters).out == from {
				schedState.UnClonable[i].Parameters.(*copyParameters).out = to
			}
			if schedState.UnClonable[i].Parameters.(*copyParameters).outCopy == from {
				schedState.UnClonable[i].Parameters.(*copyParameters).outCopy = to
			}
		}
	}
	for i := range schedState.Clonable {
		switch schedState.Clonable[i].Parameters.(type) {
		case *splitParameters:
			for j := uint(0); j < schedState.Clonable[i].Parameters.(*splitParameters).flowNumber; j++ {
				if schedState.Clonable[i].Parameters.(*splitParameters).outs[j] == from {
					schedState.Clonable[i].Parameters.(*splitParameters).outs[j] = to
				}
			}
		case *separateParameters:
			if schedState.Clonable[i].Parameters.(*separateParameters).outTrue == from {
				schedState.Clonable[i].Parameters.(*separateParameters).outTrue = to
			}
			if schedState.Clonable[i].Parameters.(*separateParameters).outFalse == from {
				schedState.Clonable[i].Parameters.(*separateParameters).outFalse = to
			}
		case *handleParameters:
			if schedState.Clonable[i].Parameters.(*handleParameters).out == from {
				schedState.Clonable[i].Parameters.(*handleParameters).out = to
			}
		}
	}
	for i := range schedState.Generate {
		switch schedState.Generate[i].Parameters.(type) {
		case *generateParameters:
			if schedState.Generate[i].Parameters.(*generateParameters).out == from {
				schedState.Generate[i].Parameters.(*generateParameters).out = to
			}
		}
	}
}

func separateCheck(parameters interface{}, debug bool) bool {
	sp := parameters.(*separateParameters)
	IN := sp.in
	if debug == true {
		common.LogDebug(common.Debug, "Number of packets in queue for separate: ", IN.GetRingCount())
	}
	if IN.GetRingCount() > maxPacketsToClone {
		return true
	}
	return false
}

func separate(parameters interface{}, stopper chan int, report chan uint64, context scheduler.UserContext) {
	sp := parameters.(*separateParameters)
	IN := sp.in
	OUTTrue := sp.outTrue
	OUTFalse := sp.outFalse
	separateFunction := sp.separateFunction
	vectorSeparateFunction := sp.vectorSeparateFunction
	vector := (vectorSeparateFunction != nil)

	bufsIn := make([]uintptr, burstSize)
	bufsTrue := make([]uintptr, burstSize)
	bufsFalse := make([]uintptr, burstSize)
	ttt := make([]bool, burstSize)
	var countOfPackets uint
	var tempPacket *packet.Packet
	var tempPacketAddr uintptr
	tempPackets := make([]*packet.Packet, burstSize)
	var currentSpeed uint64
	tick := time.Tick(time.Duration(schedTime) * time.Millisecond)
	var pause int

	for {
		select {
		case pause = <-stopper:
			if pause == -1 {
				// It is time to close this clone
				close(stopper)
				if context != nil {
					context.Delete()
				}
				// We don't close report channel because all clones of one function use it.
				// As one function entity will be working endlessly we don't close it anywhere.
				return
			}
		case <-tick:
			report <- currentSpeed
			currentSpeed = 0
		default:
			n := IN.DequeueBurst(bufsIn, burstSize)
			if n == 0 {
				if pause != 0 {
					time.Sleep(time.Duration(pause) * time.Nanosecond)
				}
				continue
			}
			countOfPackets = 0
			if vector == false {
				tempPacketAddr = packet.ExtractPacketAddr(bufsIn[0])
				// TODO here and in following flow functions: Now prefetch by zero address is
				// slowing down the application. However we should use it in the future instead of code duplication.
				for i := uint(0); i < n-1; i++ {
					tempPacket = packet.ToPacket(tempPacketAddr)
					tempPacketAddr = packet.ExtractPacketAddr(bufsIn[i+1])
					asm.Prefetcht0(tempPacketAddr)
					if separateFunction(tempPacket, context) == false {
						bufsFalse[countOfPackets] = bufsIn[i]
						countOfPackets++
					} else {
						bufsTrue[uint(i)-countOfPackets] = bufsIn[i]
					}
				}
				if separateFunction(packet.ToPacket(tempPacketAddr), context) == false {
					bufsFalse[countOfPackets] = bufsIn[n-1]
					countOfPackets++
				} else {
					bufsTrue[uint(n-1)-countOfPackets] = bufsIn[n-1]
				}
			} else {
				// TODO add prefetch for vector functions
				packet.ExtractPackets(tempPackets, bufsIn, n)
				vectorSeparateFunction(tempPackets, ttt, n, context)
				for i := uint(0); i < n; i++ {
					if ttt[i] == false {
						bufsFalse[countOfPackets] = bufsIn[i]
						countOfPackets++
					} else {
						bufsTrue[uint(i)-countOfPackets] = bufsIn[i]
					}
				}
			}
			if countOfPackets != 0 {
				safeEnqueue(OUTFalse, bufsFalse, countOfPackets)
			}
			if countOfPackets != uint(n) {
				c := n - countOfPackets
				safeEnqueue(OUTTrue, bufsTrue, uint(c))
			}
			currentSpeed += uint64(n)
		}
	}
}

func partition(parameters interface{}, core uint8) {
	cp := parameters.(*partitionParameters)
	IN := cp.in
	OUTFirst := cp.outFirst
	OUTSecond := cp.outSecond
	N := cp.N
	M := cp.M

	low.SetAffinity(core)

	bufsIn := make([]uintptr, burstSize)
	bufsFirst := make([]uintptr, burstSize)
	bufsSecond := make([]uintptr, burstSize)
	var countOfPackets uint
	currentPacketNumber := uint64(0)
	sw := true
	for {
		n := IN.DequeueBurst(bufsIn, burstSize)
		if n == 0 {
			continue
		}
		countOfPackets = 0
		for i := uint(0); i < n; i++ {
			currentPacketNumber++
			if sw == true {
				bufsFirst[countOfPackets] = bufsIn[i]
				countOfPackets++
				if currentPacketNumber == N {
					sw = false
					currentPacketNumber = 0
				}
			} else {
				bufsSecond[uint(i)-countOfPackets] = bufsIn[i]
				if currentPacketNumber == M {
					sw = true
					currentPacketNumber = 0
				}
			}
		}
		if countOfPackets != 0 {
			safeEnqueue(OUTFirst, bufsFirst, countOfPackets)
		}
		if countOfPackets != uint(n) {
			c := n - countOfPackets
			safeEnqueue(OUTSecond, bufsSecond, uint(c))
		}
	}
}

func splitCheck(parameters interface{}, debug bool) bool {
	sp := parameters.(*splitParameters)
	IN := sp.in
	if debug == true {
		common.LogDebug(common.Debug, "Number of packets in queue for split: ", IN.GetRingCount())
	}
	if IN.GetRingCount() > maxPacketsToClone {
		return true
	}
	return false
}

func split(parameters interface{}, stopper chan int, report chan uint64, context scheduler.UserContext) {
	sp := parameters.(*splitParameters)
	IN := sp.in
	OUT := sp.outs
	splitFunction := sp.splitFunction
	flowNumber := sp.flowNumber

	InputMbufs := make([]uintptr, burstSize)
	OutputMbufs := make([][]uintptr, flowNumber)
	countOfPackets := make([]int, flowNumber)
	for index := range OutputMbufs {
		OutputMbufs[index] = make([]uintptr, burstSize)
		countOfPackets[index] = 0
	}
	var tempPacket *packet.Packet
	var tempPacketAddr uintptr
	var currentSpeed uint64
	tick := time.Tick(time.Duration(schedTime) * time.Millisecond)
	var pause int

	for {
		select {
		case pause = <-stopper:
			if pause == -1 {
				// It is time to close this clone
				close(stopper)
				if context != nil {
					context.Delete()
				}
				// We don't close report channel because all clones of one function use it.
				// As one function entity will be working endlessly we don't close it anywhere.
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
			tempPacketAddr = packet.ExtractPacketAddr(InputMbufs[0])
			for i := uint(0); i < n-1; i++ {
				tempPacket = packet.ToPacket(tempPacketAddr)
				tempPacketAddr = packet.ExtractPacketAddr(InputMbufs[i+1])
				asm.Prefetcht0(tempPacketAddr)
				index := splitFunction(tempPacket, context)
				OutputMbufs[index][countOfPackets[index]] = InputMbufs[i]
				countOfPackets[index]++
			}
			index := splitFunction(packet.ToPacket(tempPacketAddr), context)
			OutputMbufs[index][countOfPackets[index]] = InputMbufs[n-1]
			countOfPackets[index]++

			for index := uint(0); index < flowNumber; index++ {
				if countOfPackets[index] == 0 {
					continue
				}
				safeEnqueue(OUT[index], OutputMbufs[index], uint(countOfPackets[index]))
				currentSpeed += uint64(countOfPackets[index])
				countOfPackets[index] = 0
			}
		}
	}
}

func handleCheck(parameters interface{}, debug bool) bool {
	sp := parameters.(*handleParameters)
	IN := sp.in
	if debug == true {
		common.LogDebug(common.Debug, "Number of packets in queue for handle: ", IN.GetRingCount())
	}
	if IN.GetRingCount() > maxPacketsToClone {
		return true
	}
	return false
}

func handle(parameters interface{}, stopper chan int, report chan uint64, context scheduler.UserContext) {
	sp := parameters.(*handleParameters)
	IN := sp.in
	OUT := sp.out
	handleFunction := sp.handleFunction
	vectorHandleFunction := sp.vectorHandleFunction
	vector := (vectorHandleFunction != nil)

	bufs := make([]uintptr, burstSize)
	var tempPacket *packet.Packet
	var tempPacketAddr uintptr
	tempPackets := make([]*packet.Packet, burstSize)
	var currentSpeed uint64
	tick := time.Tick(time.Duration(schedTime) * time.Millisecond)
	var pause int

	for {
		select {
		case pause = <-stopper:
			if pause == -1 {
				// It is time to close this clone
				close(stopper)
				if context != nil {
					context.Delete()
				}
				// We don't close report channel because all clones of one function use it.
				// As one function entity will be working endlessly we don't close it anywhere.
				return
			}
		case <-tick:
			report <- currentSpeed
			currentSpeed = 0
		default:
			n := IN.DequeueBurst(bufs, burstSize)
			if n == 0 {
				if pause != 0 {
					time.Sleep(time.Duration(pause) * time.Nanosecond)
				}
				continue
			}
			if vector == false {
				tempPacketAddr = packet.ExtractPacketAddr(bufs[0])
				for i := uint(0); i < n-1; i++ {
					tempPacket = packet.ToPacket(tempPacketAddr)
					tempPacketAddr = packet.ExtractPacketAddr(bufs[i+1])
					asm.Prefetcht0(tempPacketAddr)
					handleFunction(tempPacket, context)
				}
				handleFunction(packet.ToPacket(tempPacketAddr), context)
			} else {
				// TODO add prefetch for vector functions
				packet.ExtractPackets(tempPackets, bufs, n)
				vectorHandleFunction(tempPackets, n, context)
			}
			safeEnqueue(OUT, bufs, uint(n))
			currentSpeed += uint64(n)
		}
	}
}

func write(parameters interface{}, coreID uint8) {
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

func read(parameters interface{}, coreID uint8) {
	rp := parameters.(*readParameters)
	OUT := rp.out
	filename := rp.filename
	mempool := rp.mempool
	repcount := rp.repcount

	buf := make([]uintptr, 1)
	var tempPacket *packet.Packet

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
		if err := low.AllocateMbufs(buf, mempool, 1); err != nil {
			common.LogFatal(common.Debug, err)
		}
		tempPacket = packet.ExtractPacket(buf[0])
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
		safeEnqueue(OUT, buf, 1)
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

func checkFlow(f *Flow) error {
	if f == nil {
		return common.WrapWithNFError(nil, "One of the flows is nil!", common.UseNilFlowErr)
	}
	if f.current == nil {
		return common.WrapWithNFError(nil, "One of the flows is used after it was closed!", common.UseClosedFlowErr)
	}
	return nil
}

func checkSystem() error {
	if openFlowsNumber != 0 {
		return common.WrapWithNFError(nil, "Some flows are left open at the end of configuration!", common.OpenedFlowAtTheEnd)
	}
	for i := range createdPorts {
		if createdPorts[i].config == inactivePort {
			continue
		}
		if createdPorts[i].rxQueuesNumber == 0 && createdPorts[i].txQueuesNumber == 0 {
			return common.WrapWithNFError(nil, "port has no send and receive queues. It is an error in DPDK.", common.PortHasNoQueues)
		}
		for j := range createdPorts[i].rxQueues {
			if createdPorts[i].rxQueues[j] != true {
				return common.WrapWithNFError(nil, "port doesn't use all receive queues, packets can be missed due to RSS!", common.NotAllQueuesUsed)
			}
		}
		for j := range createdPorts[i].txQueues {
			if createdPorts[i].txQueues[j] != true {
				return common.WrapWithNFError(nil, "port has unused send queue. Performance can be lower than it is expected!", common.NotAllQueuesUsed)
			}
		}
	}
	return nil
}

// CreateKniDevice creates KNI device for using in receive or send functions.
// Gets port, core (not from YANFF list), and unique name of future KNI device.
func CreateKniDevice(port uint8, core uint8, name string) *Kni {
	low.CreateKni(port, core, name)
	kni := new(Kni)
	// Port will be identifier of this KNI
	// KNI structure itself is stored inside low.c
	kni.port = port
	return kni
}
