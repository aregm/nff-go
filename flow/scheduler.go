// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// RSS scaling
// 1) Receive flow function can get packets from port or KNI. If function
// receives packets from port it has type receiveRSS and is clonable: clone
// is added if internal NIC queue is overloaded and removed otherwise.
// 2) Cloning of receiveRSS function is implemented as changes to RETA
// table. Reta table is a table which maps hardware counted packet tuple hash to
// real number of receive queues. Port with receive function has all receive
// queues running at the start stage. However RETA table has links only
// to first receive queue. When it is required to add a clone RETA table is
// changed to send packets to new number of receive queues. And new
// core with receive function from new receive queue is added.
// 3) As receive function is invocated in C it is unable to stop them via
// go channels functionality. So we use volatile flag otherwise. If we want
// to stop a clone we switch off this flag and change RETA table.

package flow

import (
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/internal/low"
)

const generatePauseStep = 0.1

// These consts are used for freeing resources.
// They are NOT pass to
const process = 1
const stopRequest = 2
const wasStopped = 9
const printPortStatistics = false

// TODO "5" and "39" constants derived empirically. Need to investigate more elegant thresholds.
const RSSCloneMin = 5
const RSSCloneMax = 39

// Tuple of current speed in packets and bytes
type speedPair struct {
	Packets uint64
	Bytes   uint64
}

type reportPair struct {
	V            speedPair
	ZeroAttempts [32]uint64
}

// Clones of flow functions. They are determined
// by their core and their stopper channel
type clonePair struct {
	index   int
	channel [2]chan int
	flag    int32
}

type instance struct {
	// Indexes of input rings that are handle by this instance
	// inIndex[0] - number of this input rings
	inIndex []int32
	// Clones of this instance
	clone []*clonePair
	// Channel for returning current state of this instance
	report chan reportPair
	// Current state of this instance, returned from working thread
	reportedState reportPair
	// Speed with "+1" number of clones. Set while removing clone
	increasedSpeed uint64
	// Speed with "-1" number of clones. Set while adding clone
	decreasedSpeed uint64
	// Number of clones of this instance
	cloneNumber int
	pause       int
	ff          *flowFunction
	removed     bool
}

// UserContext is used inside flow packet and is going for user via it
type UserContext interface {
	Copy() interface{}
	Delete()
}

// Function types which are used inside flow functions
type uncloneFlowFunction func(interface{}, []int32, [2]chan int)
type cloneFlowFunction func(interface{}, []int32, [2]chan int, chan reportPair, []UserContext)
type cFlowFunction func(interface{}, []int32, *int32, int)

type ffType int

const (
	segmentCopy ffType = iota
	fastGenerate
	receiveRSS     // receive from port
	sendReceiveKNI // send to port, send to KNI, receive from KNI
	generate
	readWrite
	comboKNI // KNI send/receive will use core assigned to Linux KNI device
)

// Flow function representation
type flowFunction struct {
	// All parameters which gets these flow function
	Parameters interface{}
	// Main body of unclonable flow function
	uncloneFunction uncloneFlowFunction
	// Main body of receive flow function
	cFunction cFlowFunction
	// Main body of clonable flow function
	cloneFunction cloneFlowFunction
	// Number of instances of this function
	instanceNumber int
	// Instances of this function
	instance     []*instance
	oneCoreSpeed reportPair
	// Name of flow function
	name          string
	context       *[]UserContext
	fType         ffType
	inIndexNumber int32
}

// Adding every flow function to scheduler list
func (scheduler *scheduler) addFF(name string, ucfn uncloneFlowFunction, Cfn cFlowFunction, cfn cloneFlowFunction,
	par interface{}, context *[]UserContext, fType ffType, inIndexNumber int32, rxtxstats *common.RXTXStats) {
	ff := new(flowFunction)
	nameC := 1
	tName := name + strconv.Itoa(nameC)
	for i := range scheduler.ff {
		if scheduler.ff[i].name == tName {
			nameC++
			tName = name + strconv.Itoa(nameC)
		}
	}
	ff.name = tName
	ff.uncloneFunction = ucfn
	ff.cFunction = Cfn
	ff.cloneFunction = cfn
	ff.Parameters = par
	ff.context = context
	ff.fType = fType
	ff.inIndexNumber = inIndexNumber
	if inIndexNumber > scheduler.maxInIndex {
		scheduler.maxInIndex = inIndexNumber
	}
	scheduler.ff = append(scheduler.ff, ff)
	if countersEnabledInFramework && rxtxstats != nil {
		registerRXTXStatitics(rxtxstats, tName)
	}
}

type scheduler struct {
	ff                 []*flowFunction
	cores              []core
	off                bool
	offRemove          bool
	unrestrictedClones bool
	stopDedicatedCore  bool
	StopRing           low.Rings
	usedCores          uint8
	checkTime          uint
	debugTime          uint
	Dropped            uint
	maxPacketsToClone  uint32
	stopFlag           int32
	maxRecv            int
	Timers             []*Timer
	nAttempts          []uint64
	pAttempts          []uint64
	maxInIndex         int32
	measureRings       low.Rings
	coreIndex          int
}

type core struct {
	id     int
	isfree bool
}

func newScheduler(cpus []int, schedulerOff bool, schedulerOffRemove bool, stopDedicatedCore bool,
	stopRing low.Rings, checkTime uint, debugTime uint, maxPacketsToClone uint32, maxRecv int, unrestrictedClones bool) *scheduler {
	coresNumber := len(cpus)
	// Init scheduler
	scheduler := new(scheduler)
	scheduler.cores = make([]core, coresNumber, coresNumber)
	for i, cpu := range cpus {
		scheduler.cores[i] = core{id: cpu, isfree: true}
	}
	scheduler.off = schedulerOff
	scheduler.offRemove = schedulerOff || schedulerOffRemove
	scheduler.stopDedicatedCore = stopDedicatedCore
	scheduler.StopRing = stopRing
	scheduler.checkTime = checkTime
	scheduler.debugTime = debugTime
	scheduler.maxPacketsToClone = maxPacketsToClone
	scheduler.maxRecv = maxRecv
	scheduler.unrestrictedClones = unrestrictedClones
	scheduler.pAttempts = make([]uint64, len(scheduler.cores), len(scheduler.cores))

	return scheduler
}

func (scheduler *scheduler) systemStart() (err error) {
	scheduler.stopFlag = process
	var core int
	if core, scheduler.coreIndex, err = scheduler.getCore(); err != nil {
		return err
	}
	common.LogDebug(common.Initialization, "Start SCHEDULER at", core, "core")
	if err = low.SetAffinity(core); err != nil {
		common.LogFatal(common.Initialization, "Failed to set affinity to", core, "core: ", err)
	}
	if scheduler.stopDedicatedCore {
		if core, _, err = scheduler.getCore(); err != nil {
			return err
		}
		common.LogDebug(common.Initialization, "Start STOP at", core, "core")
	} else {
		common.LogDebug(common.Initialization, "Start STOP at scheduler", core, "core")
	}
	var stopstats *common.RXTXStats
	if countersEnabledInFramework {
		stopstats = new(common.RXTXStats)
		registerRXTXStatitics(stopstats, "systemstop")
	}
	go func() {
		low.Stop(scheduler.StopRing, &scheduler.stopFlag, core, stopstats)
	}()
	for i := range scheduler.ff {
		if err = scheduler.ff[i].startNewInstance(constructNewIndex(scheduler.ff[i].inIndexNumber), scheduler); err != nil {
			return err
		}
	}
	scheduler.measureRings = low.CreateRings(burstSize*sizeMultiplier, scheduler.maxInIndex+1)
	scheduler.nAttempts = make([]uint64, scheduler.maxInIndex+1, scheduler.maxInIndex+1)
	for i := int32(1); i < scheduler.maxInIndex+1; i++ {
		scheduler.nAttempts[i] = scheduler.measure(int32(i), 1)
	}
	return nil
}

func (ff *flowFunction) startNewInstance(inIndex []int32, scheduler *scheduler) (err error) {
	ffi := new(instance)
	common.LogDebug(common.Debug, "Start new instance for", ff.name)
	ffi.inIndex = inIndex
	ffi.report = make(chan reportPair, len(scheduler.cores)-1)
	ffi.ff = ff
	err = ffi.startNewClone(scheduler, ff.instanceNumber)
	if err == nil {
		ff.instance = append(ff.instance, ffi)
		ff.instanceNumber++
	}
	return err
}

func (ffi *instance) startNewClone(scheduler *scheduler, n int) (err error) {
	ff := ffi.ff
	var core int
	var index int
	if ff.fType != comboKNI {
		core, index, err = scheduler.getCore()
		if err != nil {
			common.LogWarning(common.Debug, "Can't start new clone for", ff.name, "instance", n)
			return err
		}
		common.LogDebug(common.Debug, "Start new clone for", ff.name, "instance", n, "at", core, "core")
	} else {
		common.LogDebug(common.Debug, "Start new clone for", ff.name, "instance", n, "at KNI Linux core")
	}
	ffi.clone = append(ffi.clone, &clonePair{index, [2]chan int{nil, nil}, process})
	ffi.cloneNumber++
	if ff.fType != receiveRSS && ff.fType != sendReceiveKNI && ff.fType != comboKNI {
		ffi.clone[ffi.cloneNumber-1].channel[0] = make(chan int)
		ffi.clone[ffi.cloneNumber-1].channel[1] = make(chan int)
	}
	go func() {
		if ff.fType != receiveRSS && ff.fType != sendReceiveKNI && ff.fType != comboKNI {
			if err := low.SetAffinity(core); err != nil {
				common.LogFatal(common.Debug, "Failed to set affinity to", core, "core: ", err)
			}
			if ff.fType == segmentCopy || ff.fType == fastGenerate || ff.fType == generate {
				ff.cloneFunction(ff.Parameters, ffi.inIndex, ffi.clone[ffi.cloneNumber-1].channel, ffi.report, cloneContext(ff.context))
			} else {
				ff.uncloneFunction(ff.Parameters, ffi.inIndex, ffi.clone[ffi.cloneNumber-1].channel)
			}
		} else if ff.fType != comboKNI {
			ff.cFunction(ff.Parameters, ffi.inIndex, &ffi.clone[ffi.cloneNumber-1].flag, core)
		} else {
			ff.cFunction(ff.Parameters, ffi.inIndex, &ffi.clone[ffi.cloneNumber-1].flag, 0)
		}
	}()
	if ff.fType == segmentCopy || ff.fType == fastGenerate || ff.fType == generate {
		<-ffi.clone[ffi.cloneNumber-1].channel[1]
	}
	return nil
}

func (ff *flowFunction) stopClone(ffi *instance, scheduler *scheduler) {
	common.LogDebug(common.Debug, "Stop clone")
	if ffi.clone[ffi.cloneNumber-1].channel[0] != nil {
		ffi.clone[ffi.cloneNumber-1].channel[0] <- -1
		<-ffi.clone[ffi.cloneNumber-1].channel[1]
		close(ffi.clone[ffi.cloneNumber-1].channel[0])
		close(ffi.clone[ffi.cloneNumber-1].channel[1])
	} else {
		atomic.StoreInt32(&ffi.clone[ffi.cloneNumber-1].flag, stopRequest)
		for atomic.LoadInt32(&ffi.clone[ffi.cloneNumber-1].flag) != wasStopped {
			runtime.Gosched()
		}
	}
	if ffi.ff.fType != comboKNI {
		scheduler.setCoreByIndex(ffi.clone[ffi.cloneNumber-1].index)
	}
	ffi.clone = ffi.clone[:len(ffi.clone)-1]
	ffi.cloneNumber--
	ffi.removed = true
}

func (ff *flowFunction) stopInstance(from int, to int, scheduler *scheduler) {
	common.LogDebug(common.Debug, "Stop instance for", ff.name)
	fromInstance := ff.instance[from]
	for fromInstance.cloneNumber != 0 {
		ff.stopClone(fromInstance, scheduler)
	}
	if fromInstance.report != nil {
		close(fromInstance.report)
	}
	if to != -1 {
		toInstance := ff.instance[to]
		for q := int32(0); q < fromInstance.inIndex[0]; q++ {
			toInstance.inIndex[toInstance.inIndex[0]+q+1] = fromInstance.inIndex[q+1]
		}
		toInstance.inIndex[0] += fromInstance.inIndex[0]
		ff.instance = append(ff.instance[:from], ff.instance[from+1:]...)
	}
	ff.instanceNumber--
}

func (scheduler *scheduler) systemStop() {
	atomic.StoreInt32(&scheduler.stopFlag, stopRequest)
	for atomic.LoadInt32(&scheduler.stopFlag) != wasStopped {
		// We need to wait because scheduler can sleep at this moment
		runtime.Gosched()
	}
	for i := range scheduler.ff {
		for scheduler.ff[i].instanceNumber != 0 {
			scheduler.ff[i].stopInstance(0, -1, scheduler)
		}
	}
	scheduler.setCoreByIndex(scheduler.coreIndex)
	if scheduler.stopDedicatedCore {
		scheduler.setCoreByIndex(scheduler.coreIndex + 1)
	}
	scheduler.ff = nil
}

// Main loop after framework was started
func (scheduler *scheduler) schedule(schedTime uint) {
	tick := time.Tick(time.Duration(scheduler.checkTime) * time.Millisecond)
	debugTick := time.Tick(time.Duration(scheduler.debugTime) * time.Millisecond)
	checkRequired := false
	for atomic.LoadInt32(&scheduler.stopFlag) == process {
		time.Sleep(time.Millisecond * time.Duration(schedTime))
		// We have an array of Timers which can be increated by AddTimer function
		// Timer has duration and handler common for all Timer variants, so firstly
		// we check that timer ticker channel is ready:
		for _, t := range scheduler.Timers {
			select {
			case <-t.t.C:
				// If this timer was ticked we check all checks of all variants
				// Timer. We need variants because one TCP timer will handle
				// different TCP sessions. Variant's context is a difference of
				// current session from other sessions. Variant's check is a
				// variable that user will set to "true" if he wants to reset timer
				// for example if packet of this session was arrived.
				for i, c := range t.checks {
					// We set all checks to false. If we saw false check it means
					// that user didn't see any event and timer handler should be called.
					// We use boolean checks for performance reasons because reset timer
					// after each packet is quite slow.
					if *c == false {
						t.handler(t.contexts[i])
						// We remove current variant after handler calling, because this
						// session was finished.
						t.contexts = append(t.contexts[:i], t.contexts[i+1:]...)
						t.checks = append(t.checks[:i], t.checks[i+1:]...)
						continue
					}
					*c = false
				}
			default:
			}
		}
		select {
		case <-tick:
			checkRequired = true
		case <-debugTick:
			// Report current state of system
			common.LogDebug(common.Debug, "---------------")
			common.LogDebug(common.Debug, "System is using", scheduler.usedCores, "cores now.", uint8(len(scheduler.cores))-scheduler.usedCores, "cores are left available.")
			low.Statistics(float32(scheduler.debugTime) / 1000)
			if printPortStatistics {
				for i := range createdPorts {
					if createdPorts[i].wasRequested {
						low.PortStatistics(createdPorts[i].port)
					}
				}
			}
			for i := range scheduler.ff {
				scheduler.ff[i].printDebug(schedTime)
			}
			if scheduler.Dropped != 0 {
				common.LogDrop(common.Debug, "Flow functions together dropped", scheduler.Dropped, "packets")
				// It is race condition here, however it is just statistics.
				// It can be not accurate, but on the other hand doesn't influence performance
				scheduler.Dropped = 0
			}
			low.ReportMempoolsState()
		default:
		}
		// Procced with each flow function
		for i := range scheduler.ff {
			ff := scheduler.ff[i]
			if ff.fType == segmentCopy || ff.fType == fastGenerate {
				ff.updateReportedState() // TODO also for debug
			}
			if ff.fType == fastGenerate {
				select {
				case temp := <-(ff.Parameters.(*generateParameters)).targetChannel:
					if float64(temp)/(1000 /*milliseconds*/ /float64(schedTime)) < float64(burstSize) {
						// TargetSpeed per schedTime should be more than burstSize because one burstSize packets in
						// one schedTime seconds are out minimal scheduling part. We can't make generate speed less than this.
						common.LogWarning(common.Debug, "Target speed per schedTime should be more than burstSize - not changing")
					} else {
						(ff.Parameters.(*generateParameters)).targetSpeed = float64(temp)
					}
				default:
				}
			}
			// Firstly we check removing clones. We can remove one clone if:
			// 1. flow function has clones or it is fastGenerate
			// 2. scheduler removing is switched on
			if scheduler.offRemove == false {
				switch ff.fType {
				case segmentCopy: // Both instances and clones
					maxZeroAttempts0 := -1
					maxZeroAttempts1 := -1
					for q := 0; q < ff.instanceNumber; q++ {
						ffi := ff.instance[q]
						if ffi.cloneNumber > 1 {
							ffi.reportedState.ZeroAttempts[0] = ffi.reportedState.ZeroAttempts[0] * scheduler.pAttempts[ffi.cloneNumber]
							if ffi.reportedState.ZeroAttempts[0] > uint64(schedTime)*uint64(1000000*1.05) || ffi.decreasedSpeed > ffi.reportedState.V.Packets {
								// Save current speed as speed of flow function with this number of clones before removing
								ffi.increasedSpeed = ffi.reportedState.V.Packets
								ffi.decreasedSpeed = 0
								ff.stopClone(ffi, scheduler)
								ffi.updatePause(ffi.cloneNumber - 1)
							}
						} else {
							for z := int32(0); z < ffi.inIndex[0]; z++ {
								if ffi.reportedState.ZeroAttempts[z] < ffi.reportedState.ZeroAttempts[0] {
									ffi.reportedState.ZeroAttempts[0] = ffi.reportedState.ZeroAttempts[z]
								}
							}
							ffi.reportedState.ZeroAttempts[0] = ffi.reportedState.ZeroAttempts[0] * scheduler.nAttempts[ffi.inIndex[0]]
							if maxZeroAttempts0 == -1 || ffi.reportedState.ZeroAttempts[0] > ff.instance[maxZeroAttempts0].reportedState.ZeroAttempts[0] {
								maxZeroAttempts1 = maxZeroAttempts0
								maxZeroAttempts0 = q
							} else if maxZeroAttempts1 == -1 || ffi.reportedState.ZeroAttempts[0] > ff.instance[maxZeroAttempts1].reportedState.ZeroAttempts[0] {
								maxZeroAttempts1 = q
							}
						}
					}
					if maxZeroAttempts0 != -1 && maxZeroAttempts1 != -1 && ff.instance[maxZeroAttempts1].reportedState.ZeroAttempts[0] != 0 {
						if ff.instance[maxZeroAttempts0].reportedState.ZeroAttempts[0]+ff.instance[maxZeroAttempts1].reportedState.ZeroAttempts[0] > uint64(schedTime)*uint64(1.05*1000000) {
							toInstance := ff.instance[maxZeroAttempts1]
							ff.stopInstance(maxZeroAttempts0, maxZeroAttempts1, scheduler)
							toInstance.updatePause(0)
						}
					}
				case fastGenerate: // Only clones, no instances
					targetSpeed := (ff.Parameters.(*generateParameters)).targetSpeed
					speedPKTS := float64(ff.instance[0].reportedState.V.normalize(schedTime).Packets)
					// 3. Current speed is much bigger than target speed
					if speedPKTS > 1.1*targetSpeed {
						ffi := ff.instance[0]
						// 4. TODO strange heuristic, it is required to check this
						if ffi.cloneNumber > 1 && targetSpeed/float64(ffi.cloneNumber+1)*float64(ffi.cloneNumber) > speedPKTS {
							ff.stopClone(ffi, scheduler)
							ffi.updatePause(0)
							continue
						} else {
							if ffi.pause == 0 {
								// This is proportion between required and current speeds.
								// 1000000000 is converting to nanoseconds
								ffi.updatePause(int((speedPKTS - targetSpeed) / speedPKTS / targetSpeed * 1000000000))
							} else if float64(ffi.pause)*generatePauseStep < 2 {
								// Multiplying can't be used here due to integer truncation
								ffi.updatePause(ffi.pause + 3)
							} else {
								ffi.updatePause(int((1 + generatePauseStep) * float64(ffi.pause)))
							}
						}
					}
				case receiveRSS: // Only instances, no clones
					if ff.instanceNumber > 1 {
						first := -1
						for q := 0; q < ff.instanceNumber; q++ {
							var q1 int32
							for q1 = 1; q1 < ff.instance[q].inIndex[0]+1; q1++ {
								if low.CheckRSSPacketCount(ff.Parameters.(*receiveParameters).port, int16(ff.instance[q].inIndex[q1])) > int64(RSSCloneMin) {
									break
								}
							}
							if q1 == ff.instance[q].inIndex[0]+1 {
								if first == -1 {
									first = q
								} else {
									ff.stopInstance(first, q, scheduler)
									break
								}
							}
						}
					}
				case readWrite, generate, sendReceiveKNI:
				}
			}
			// Secondly we check adding clones. We can add one clone if:
			// 1. scheduler is switched on
			// 2. ouput ring is quite empty
			if scheduler.off == false {
				switch ff.fType {
				case segmentCopy: // Both instances and clones
					l := ff.instanceNumber
					a := true
					for q := 0; q < l; q++ {
						ffi := ff.instance[q]
						if ffi.inIndex[0] > 1 && ffi.checkInputRingClonable(scheduler.maxPacketsToClone) {
							if ff.startNewInstance(constructZeroIndex(ffi.inIndex), scheduler) == nil {
								constructDuplicatedIndex(ffi.inIndex, ff.instance[ff.instanceNumber-1].inIndex)
								a = false
								ffi.updatePause(0)
							}
						}
					}
					if a == true {
						for q := 0; q < l; q++ {
							ffi := ff.instance[q]
							if ffi.removed {
								ffi.removed = false
								continue
							}
							if ffi.inIndex[0] == 1 && scheduler.unrestrictedClones && ffi.checkInputRingClonable(scheduler.maxPacketsToClone) &&
								ffi.checkOutputRingClonable(scheduler.maxPacketsToClone) &&
								(ffi.increasedSpeed == 0 || ffi.increasedSpeed > ffi.reportedState.V.Packets) {
								if scheduler.pAttempts[ffi.cloneNumber+1] == 0 {
									scheduler.pAttempts[ffi.cloneNumber+1] = scheduler.measure(1, ffi.cloneNumber+1)
								}
								if ffi.startNewClone(scheduler, q) == nil {
									ffi.decreasedSpeed = ffi.reportedState.V.Packets
									ffi.increasedSpeed = 0
									ffi.updatePause(ffi.cloneNumber - 1)
									continue
								}
							}
							// Scheduler can't add new clones if saved instance speed with more
							// clones is slower than current. However this speed can be changed due to
							// external reasons. So flow function should "forget" this speed regularly
							// to try to clone function and get new increasedSpeed.
							if checkRequired == true {
								ffi.increasedSpeed = 0
							}
						}
					}
				case fastGenerate: // Only clones, no instances
					// 3. speed is not enough
					if float64(ff.instance[0].reportedState.V.normalize(schedTime).Packets) < (ff.Parameters.(*generateParameters)).targetSpeed {
						if ff.instance[0].pause != 0 {
							ff.instance[0].updatePause(int((1 - generatePauseStep) * float64(ff.instance[0].pause)))
						} else if ff.instance[0].checkOutputRingClonable(scheduler.maxPacketsToClone) {
							// 3. there is no pause
							if ff.instance[0].startNewClone(scheduler, 0) == nil {
								ff.instance[0].updatePause(0)
							}
							continue
						}
					}
				case receiveRSS: // Only instances, no clones
					// 3. Number of packets in RSS is big enogh to cause overwrite (drop) problems
					if ff.instanceNumber < scheduler.maxRecv && ff.inIndexNumber > 1 {
						for q := 0; q < ff.instanceNumber; q++ {
							if ff.instance[q].checkInputRingClonable(RSSCloneMax) && ff.instance[q].checkOutputRingClonable(scheduler.maxPacketsToClone) {
								if ff.startNewInstance(constructZeroIndex(ff.instance[q].inIndex), scheduler) == nil {
									constructDuplicatedIndex(ff.instance[q].inIndex, ff.instance[ff.instanceNumber-1].inIndex)
								}
								break
							}
						}
					}
				case readWrite, generate, sendReceiveKNI:
				}
			}
		}
		checkRequired = false
		runtime.Gosched()
	}
	atomic.StoreInt32(&scheduler.stopFlag, stopRequest+1)
}

func cloneContext(ctx *[]UserContext) []UserContext {
	if ctx == nil {
		return nil
	}
	ret := make([]UserContext, len(*ctx))
	for i := range *ctx {
		if (*ctx)[i] != nil {
			ret[i] = ((*ctx)[i].Copy()).(UserContext)
		}
	}
	return ret
}

func (ffi *instance) updatePause(pause int) {
	ffi.pause = pause
	for j := 0; j < ffi.cloneNumber; j++ {
		ffi.clone[j].channel[0] <- ffi.pause
	}
}

func (ff *flowFunction) printDebug(schedTime uint) {
	switch ff.fType {
	case segmentCopy:
		for q := 0; q < ff.instanceNumber; q++ {
			out := ff.instance[q].reportedState.V.normalize(schedTime)
			if reportMbits {
				common.LogDebug(common.Debug, "Current speed of", q, "instance of", ff.name, "is", out.Packets, "PKT/S,", out.Bytes, "Mbits/s")
			} else {
				common.LogDebug(common.Debug, "Current speed of", q, "instance of", ff.name, "is", out.Packets, "PKT/S, cloneNumber:", ff.instance[q].cloneNumber, "queue number:", ff.instance[q].inIndex[0])
			}
		}
	case fastGenerate:
		targetSpeed := (ff.Parameters.(*generateParameters)).targetSpeed
		out := ff.instance[0].reportedState.V.normalize(schedTime)
		if reportMbits {
			common.LogDebug(common.Debug, "Current speed of", ff.name, "is", out.Packets, "PKT/S,", out.Bytes, "Mbits/s, target speed is", uint64(targetSpeed), "PKT/S")
		} else {
			common.LogDebug(common.Debug, "Current speed of", ff.name, "is", out.Packets, "PKT/S, target speed is", uint64(targetSpeed), "PKT/S")
		}
	case readWrite, generate, sendReceiveKNI, receiveRSS:
	}
}

func (V speedPair) normalize(schedTime uint) speedPair {
	// We should multiply by 1000 because schedTime is in milliseconds
	// We multiply by 8 to translate bytes to bits
	// We add 24 because 4 is checksum + 20 is before/after packet gaps in 40GB ethernet
	// We divide by 1000 and 1000 because networking suppose that megabit has 1000 kilobits instead of 1024
	return speedPair{V.Packets * 1000 / uint64(schedTime), (V.Bytes + V.Packets*24) * 1000 / uint64(schedTime) * 8 / 1000 / 1000}
}

func (ff *flowFunction) updateReportedState() {
	// Gather and sum current speeds from all clones of current flow function
	// Flow function itself and all clones put their speeds in one channel
	for q := 0; q < ff.instanceNumber; q++ {
		ffi := ff.instance[q]
		ffi.reportedState = reportPair{}
		t := len(ffi.report) - ffi.cloneNumber
		for k := 0; k < t; k++ {
			<-ffi.report
		}
		for k := 0; k < ffi.cloneNumber; k++ {
			temp := <-ffi.report
			ffi.reportedState.V.Packets += temp.V.Packets
			ffi.reportedState.V.Bytes += temp.V.Bytes
			if ff.fType == segmentCopy {
				for z := int32(0); z < ffi.inIndex[0]; z++ {
					ffi.reportedState.ZeroAttempts[z] += temp.ZeroAttempts[z]
				}
			}
		}
		// If any flow functions wait in a queue to put their
		// reports immidiately after reading- we should remove them.
		// They will put reports again after scheduling time.
		t = len(ffi.report)
		if t != 0 {
			for k := 0; k < t; k++ {
				<-ffi.report
			}
		}
	}
}

func (scheduler *scheduler) setCoreByIndex(i int) {
	scheduler.cores[i].isfree = true
	scheduler.usedCores--
}

func (scheduler *scheduler) getCore() (int, int, error) {
	for i := range scheduler.cores {
		if scheduler.cores[i].isfree == true {
			scheduler.cores[i].isfree = false
			scheduler.usedCores++
			return scheduler.cores[i].id, i, nil
		}
	}
	return 0, 0, common.WrapWithNFError(nil, "Requested number of cores isn't enough.", common.NotEnoughCores)
}

func (ffi *instance) checkInputRingClonable(min uint32) bool {
	switch ffi.ff.Parameters.(type) {
	case *segmentParameters:
		for q := int32(0); q < ffi.inIndex[0]; q++ {
			if ffi.ff.Parameters.(*segmentParameters).in[ffi.inIndex[q+1]].GetRingCount() > min {
				return true
			}
		}
	case *copyParameters:
		for q := int32(0); q < ffi.inIndex[0]; q++ {
			if ffi.ff.Parameters.(*copyParameters).in[ffi.inIndex[q+1]].GetRingCount() > min {
				return true
			}
		}
	case *receiveParameters:
		for q := int32(0); q < ffi.inIndex[0]; q++ {
			if low.CheckRSSPacketCount(ffi.ff.Parameters.(*receiveParameters).port, int16(ffi.inIndex[q+1])) > int64(min) {
				return true
			}
		}
	}
	return false
}

func (ffi *instance) checkOutputRingClonable(max uint32) bool {
	switch ffi.ff.Parameters.(type) {
	case *generateParameters:
		if ffi.ff.Parameters.(*generateParameters).out[0].GetRingCount() <= max {
			return true
		}
	case *receiveParameters:
		for q := int32(0); q < ffi.inIndex[0]; q++ {
			if ffi.ff.Parameters.(*receiveParameters).out[ffi.inIndex[q+1]].GetRingCount() <= max {
				return true
			}
		}
	case *copyParameters:
		for q := int32(0); q < ffi.inIndex[0]; q++ {
			if ffi.ff.Parameters.(*copyParameters).out[ffi.inIndex[q+1]].GetRingCount() <= max ||
				ffi.ff.Parameters.(*copyParameters).outCopy[ffi.inIndex[q+1]].GetRingCount() <= max {
				return true
			}
		}
	case *segmentParameters:
		p := *(ffi.ff.Parameters.(*segmentParameters).out)
		for i := range p {
			for q := int32(0); q < ffi.inIndex[0]; q++ {
				if p[i][ffi.inIndex[q+1]].GetRingCount() <= max {
					return true
				}
			}
		}
	}
	return false
}

func constructZeroIndex(old []int32) []int32 {
	return make([]int32, len(old), len(old))
}

func constructDuplicatedIndex(old []int32, newIndex []int32) {
	oldLen := old[0]/2 + old[0]%2
	newLen := old[0] / 2
	old[0] = oldLen
	for q := int32(0); q < newLen; q++ {
		newIndex[q+1] = old[q+1+oldLen]
	}
	newIndex[0] = newLen
}

func constructNewIndex(inIndexNumber int32) []int32 {
	if inIndexNumber == 0 {
		return nil
	}
	newIndex := make([]int32, inIndexNumber+1, inIndexNumber+1)
	for q := int32(0); q < inIndexNumber; q++ {
		newIndex[q+1] = q
	}
	newIndex[0] = inIndexNumber
	return newIndex
}

// This function is used for measuring "wasted" time that framework
// spends on one "zero get from ring attempt". This function can be
// replaced by "inline" time measurements which will cost
// 3 time.Now = ~210nn per each burstSize (32) packets.
func (scheduler *scheduler) measure(N int32, clones int) uint64 {
	core, index, err := scheduler.getCore()
	if err != nil {
		return 0
	}
	par := new(segmentParameters)
	par.in = scheduler.measureRings
	out := make([]low.Rings, 0, 0)
	par.out = &out
	stype := uint8(0)
	par.stype = &stype
	inIndex := constructNewIndex(N)
	var stopper [2]chan int
	stopper[0] = make(chan int)
	stopper[1] = make(chan int)
	report := make(chan reportPair, 20)
	var reportedState reportPair
	var avg uint64
	t := schedTime
	pause := clones - 1
	if pause == 0 {
		schedTime = 5
	} else {
		schedTime = 15
	}
	for o := 0; o < 5; o++ {
		go func() {
			low.SetAffinity(core)
			segmentProcess(par, inIndex, stopper, report, nil)
		}()
		<-stopper[1]
		stopper[0] <- pause
		<-report
		for reportedState.ZeroAttempts[0] == 0 {
			reportedState = <-report
		}
		stopper[0] <- -1
		<-stopper[1]
		for len(report) > 0 {
			<-report
		}
		avg += uint64(schedTime) * 1000000 / reportedState.ZeroAttempts[0]
		reportedState.ZeroAttempts[0] = 0
	}
	scheduler.setCoreByIndex(index)
	schedTime = t
	close(stopper[0])
	close(stopper[1])
	close(report)
	return avg / 5
}
