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
	"github.com/intel-go/nff-go/low"
)

const generatePauseStep = 0.1

// These consts are used for freeing resources.
// They are NOT pass to
const process = 1
const stopRequest = 2
const wasStopped = 9

// TODO "5" and "39" constants derived empirically. Need to investigate more elegant thresholds.
const RSSCloneMin = 5
const RSSCloneMax = 39

// Tuple of current speed in packets and bytes
type reportPair struct {
	Packets uint64
	Bytes   uint64
}

// Clones of flow functions. They are determined
// by their core and their stopper channel
type clonePair struct {
	index   int
	channel [2]chan int
	flag    int32
}

// UserContext is used inside flow packet and is going for user via it
type UserContext interface {
	Copy() interface{}
	Delete()
}

// Function types which are used inside flow functions
type uncloneFlowFunction func(interface{}, [2]chan int)
type cloneFlowFunction func(interface{}, [2]chan int, chan reportPair, []UserContext)
type cFlowFunction func(interface{}, *int32, int)

type ffType int

const (
	segmentCopy ffType = iota
	fastGenerate
	receiveRSS     // receive from port
	sendReceiveKNI // send to port, send to KNI, receive from KNI
	generate
	readWrite
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
	// Number of clones of this function
	cloneNumber int
	// Clones of this function. They are determined
	// by their core and their stopper channel
	clone []*clonePair
	// Channel for reporting current speed.
	// It is one for all clones
	report chan reportPair
	// Current saved speed when making a clone.
	// It will be compared with immediate current speed to stop a clone.
	previousSpeed []reportPair
	// For debug purposes
	currentSpeed reportPair
	// Name of flow function
	name    string
	context *[]UserContext
	pause   int
	fType   ffType
}

// Adding every flow function to scheduler list
func (scheduler *scheduler) addFF(name string, ucfn uncloneFlowFunction, Cfn cFlowFunction, cfn cloneFlowFunction,
	par interface{}, context *[]UserContext, fType ffType) {
	ff := new(flowFunction)
	nameC := 1
	tName := name
	for i := range scheduler.ff {
		if scheduler.ff[i].name == tName {
			tName = name + strconv.Itoa(nameC)
			nameC++
		}
	}
	ff.name = tName
	ff.uncloneFunction = ucfn
	ff.cFunction = Cfn
	ff.cloneFunction = cfn
	ff.Parameters = par
	ff.report = make(chan reportPair, 50)
	ff.context = context
	ff.previousSpeed = make([]reportPair, len(scheduler.cores), len(scheduler.cores))
	ff.fType = fType
	scheduler.ff = append(scheduler.ff, ff)
}

type scheduler struct {
	ff                []*flowFunction
	cores             []core
	off               bool
	offRemove         bool
	stopDedicatedCore bool
	StopRing          *low.Ring
	usedCores         uint8
	checkTime         uint
	debugTime         uint
	Dropped           uint
	maxPacketsToClone uint32
	stopFlag          int32
	maxRecv           int
}

type core struct {
	id     int
	isfree bool
}

func newScheduler(cpus []int, schedulerOff bool, schedulerOffRemove bool,
	stopDedicatedCore bool, stopRing *low.Ring, checkTime uint, debugTime uint, maxPacketsToClone uint32, maxRecv int) *scheduler {
	coresNumber := len(cpus)
	// Init scheduler
	scheduler := new(scheduler)
	scheduler.cores = make([]core, coresNumber, coresNumber)
	for i, cpu := range cpus {
		scheduler.cores[i] = core{id: cpu, isfree: true}
	}
	scheduler.off = schedulerOff
	scheduler.offRemove = schedulerOff || schedulerOffRemove
	scheduler.StopRing = stopRing
	scheduler.stopDedicatedCore = stopDedicatedCore
	scheduler.checkTime = checkTime
	scheduler.debugTime = debugTime
	scheduler.maxPacketsToClone = maxPacketsToClone
	scheduler.maxRecv = maxRecv

	return scheduler
}

func (scheduler *scheduler) systemStart() (err error) {
	scheduler.stopFlag = process
	var core int
	if core, _, err = scheduler.getCore(); err != nil {
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
	go func() {
		low.Stop(scheduler.StopRing, &scheduler.stopFlag, core)
	}()
	for i := range scheduler.ff {
		if err = scheduler.startFF(scheduler.ff[i]); err != nil {
			return err
		}
	}
	// We need this to get a chance to all started goroutines to log their warnings.
	time.Sleep(time.Millisecond)
	return nil
}

func (scheduler *scheduler) startFF(ff *flowFunction) (err error) {
	core, index, err := scheduler.getCore()
	if err != nil {
		return err
	}
	common.LogDebug(common.Initialization, "Start new FlowFunction or clone for", ff.name, "at", core, "core")
	ff.clone = append(ff.clone, &clonePair{index, [2]chan int{nil, nil}, process})
	ff.cloneNumber++
	if ff.fType != receiveRSS && ff.fType != sendReceiveKNI {
		ff.clone[ff.cloneNumber-1].channel[0] = make(chan int)
		ff.clone[ff.cloneNumber-1].channel[1] = make(chan int)
	}
	go func() {
		if ff.fType != receiveRSS && ff.fType != sendReceiveKNI {
			if err := low.SetAffinity(core); err != nil {
				common.LogFatal(common.Initialization, "Failed to set affinity to", core, "core: ", err)
			}
			if ff.fType == segmentCopy || ff.fType == fastGenerate || ff.fType == generate {
				ff.cloneFunction(ff.Parameters, ff.clone[ff.cloneNumber-1].channel, ff.report, cloneContext(ff.context))
			} else {
				ff.uncloneFunction(ff.Parameters, ff.clone[ff.cloneNumber-1].channel)
			}
		} else {
			ff.cFunction(ff.Parameters, &ff.clone[ff.cloneNumber-1].flag, core)
		}
	}()
	return nil
}

func (scheduler *scheduler) stopFF(ff *flowFunction) {
	if ff.clone[ff.cloneNumber-1].channel[0] != nil {
		ff.clone[ff.cloneNumber-1].channel[0] <- -1
		<-ff.clone[ff.cloneNumber-1].channel[1]
		close(ff.clone[ff.cloneNumber-1].channel[0])
		close(ff.clone[ff.cloneNumber-1].channel[1])
	} else {
		atomic.StoreInt32(&ff.clone[ff.cloneNumber-1].flag, stopRequest)
		for atomic.LoadInt32(&ff.clone[ff.cloneNumber-1].flag) != wasStopped {
			runtime.Gosched()
		}
	}
	scheduler.setCoreByIndex(ff.clone[ff.cloneNumber-1].index)
	ff.clone = ff.clone[:len(ff.clone)-1]
	ff.cloneNumber--
}

func (scheduler *scheduler) systemStop() {
	atomic.StoreInt32(&scheduler.stopFlag, stopRequest)
	for atomic.LoadInt32(&scheduler.stopFlag) != wasStopped {
		// We need to wait because scheduler can sleep at this moment
		runtime.Gosched()
	}
	for i := range scheduler.ff {
		for scheduler.ff[i].cloneNumber != 0 {
			scheduler.stopFF(scheduler.ff[i])
		}
		if scheduler.ff[i].report != nil {
			close(scheduler.ff[i].report)
		}
	}
	scheduler.setCoreByIndex(0) // scheduler
	if scheduler.stopDedicatedCore {
		scheduler.setCoreByIndex(1) // stop
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
		select {
		case <-tick:
			checkRequired = true
		case <-debugTick:
			// Report current state of system
			common.LogDebug(common.Debug, "System is using", scheduler.usedCores, "cores now.", uint8(len(scheduler.cores))-scheduler.usedCores, "cores are left available.")
			low.Statistics(float32(scheduler.debugTime) / 1000)
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
			common.LogDebug(common.Debug, "---------------")
		default:
		}
		// Procced with each flow function
		for i := range scheduler.ff {
			ff := scheduler.ff[i]
			if ff.fType == segmentCopy || ff.fType == fastGenerate {
				ff.updateCurrentSpeed()
			}
			// Firstly we check removing clones. We can remove one clone if:
			// 1. flow function has clones or it is fastGenerate
			// 2. scheduler removing is switched on
			if (ff.cloneNumber > 1 || ff.fType == fastGenerate) && (scheduler.offRemove == false) {
				switch ff.fType {
				case segmentCopy:
					// 3. current speed of flow function is lower, than saved speed with less number of clones
					if ff.currentSpeed.Packets < ff.previousSpeed[ff.cloneNumber-1].Packets {
						// Save current speed as speed of flow function with this number of clones before removing
						ff.previousSpeed[ff.cloneNumber] = ff.currentSpeed
						scheduler.stopFF(ff)
						ff.updatePause(ff.cloneNumber)
						// After removing a clone we don't want to try to add clone immediately
						continue
					}
				case fastGenerate:
					targetSpeed := (ff.Parameters.(*generateParameters)).targetSpeed
					speedPKTS := float64(ff.currentSpeed.normalize(schedTime).Packets)
					// 3. Current speed is much bigger than target speed
					if speedPKTS > 1.1*targetSpeed {
						// 4. TODO strange heuristic, it is required to check this
						if ff.cloneNumber > 1 && targetSpeed/float64(ff.cloneNumber+1)*float64(ff.cloneNumber) > speedPKTS {
							scheduler.stopFF(ff)
							ff.updatePause(0)
							continue
						} else {
							if ff.pause == 0 {
								// This is proportion between required and current speeds.
								// 1000000000 is converting to nanoseconds
								ff.updatePause(int((speedPKTS - targetSpeed) / speedPKTS / targetSpeed * 1000000000))
							} else if float64(ff.pause)*generatePauseStep < 2 {
								// Multiplying can't be used here due to integer truncation
								ff.updatePause(ff.pause + 3)
							} else {
								ff.updatePause(int((1 + generatePauseStep) * float64(ff.pause)))
							}
						}
					}
				case receiveRSS:
					if low.CheckRSSPacketCount(ff.Parameters.(*receiveParameters).port) < RSSCloneMin {
						scheduler.stopFF(ff)
						low.DecreaseRSS((ff.Parameters.(*receiveParameters)).port)
						continue
					}
				case readWrite, generate, sendReceiveKNI:
				}
			}
			// Secondly we check adding clones. We can add one clone if:
			// 1. scheduler is switched on
			// 2. ouput ring is quite empty
			if scheduler.off == false && ff.checkOutputRingClonable(scheduler.maxPacketsToClone) {
				switch ff.fType {
				case segmentCopy:
					// 3. check function signals that we need to clone
					// 4. we don't know flow function speed with more clones, or we know it and it is bigger than current speed
					if ff.checkInputRingClonable(scheduler.maxPacketsToClone) &&
						(ff.previousSpeed[ff.cloneNumber+1].Packets == 0 || ff.previousSpeed[ff.cloneNumber+1].Packets > ff.currentSpeed.Packets) {
						// Save current speed as speed of flow function with this number of clones before adding
						ff.previousSpeed[ff.cloneNumber] = ff.currentSpeed
						if scheduler.startFF(ff) == nil {
							// Add a pause to all clones. This pause depends on the number of clones.
							ff.updatePause(ff.cloneNumber)
						} else {
							common.LogWarning(common.Debug, "Can't start new clone for", ff.name)
						}
						continue
					}
					// Scheduler can't add new clones if saved flow function speed with more
					// clones is slower than current. However this speed can be changed due to
					// external reasons. So flow function should check and update this speed
					// regular time.
					if checkRequired == true {
						// Regular flow function speed check after each checkTime milliseconds,
						// it is done by erasing previously measured speed data. After this scheduler can
						// add new clone. If performance decreases with added clone, it will be stopped
						// with setting speed data.
						ff.previousSpeed[ff.cloneNumber+1].Packets = 0
					}
				case fastGenerate:
					// 3. speed is not enough
					if float64(ff.currentSpeed.normalize(schedTime).Packets) < (ff.Parameters.(*generateParameters)).targetSpeed {
						if ff.pause != 0 {
							ff.updatePause(int((1 - generatePauseStep) * float64(ff.pause)))
						} else {
							// 3. there is no pause
							if scheduler.startFF(ff) == nil {
								ff.updatePause(0)
							} else {
								common.LogWarning(common.Debug, "Can't start new clone for", ff.name)
							}
							continue
						}
					}
				case receiveRSS:
					// 3. Number of packets in RSS is big enogh to cause overwrite (drop) problems
					if ff.checkInputRingClonable(RSSCloneMax) && ff.cloneNumber < scheduler.maxRecv {
						if low.IncreaseRSS((ff.Parameters.(*receiveParameters)).port) {
							if scheduler.startFF(ff) != nil {
								common.LogWarning(common.Debug, "Can't start new clone for", ff.name)
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

func (ff *flowFunction) updatePause(pause int) {
	ff.pause = pause
	for j := 0; j < ff.cloneNumber; j++ {
		ff.clone[j].channel[0] <- ff.pause
	}
}

func (ff *flowFunction) printDebug(schedTime uint) {
	switch ff.fType {
	case segmentCopy:
		out := ff.currentSpeed.normalize(schedTime)
		if reportMbits {
			common.LogDebug(common.Debug, "Current speed of", ff.name, "is", out.Packets, "PKT/S,", out.Bytes, "Mbits/s")
		} else {
			common.LogDebug(common.Debug, "Current speed of", ff.name, "is", out.Packets, "PKT/S")
		}
	case fastGenerate:
		targetSpeed := (ff.Parameters.(*generateParameters)).targetSpeed
		out := ff.currentSpeed.normalize(schedTime)
		if reportMbits {
			common.LogDebug(common.Debug, "Current speed of", ff.name, "is", out.Packets, "PKT/S,", out.Bytes, "Mbits/s, target speed is", int64(targetSpeed), "PKT/S")
		} else {
			common.LogDebug(common.Debug, "Current speed of", ff.name, "is", out.Packets, "PKT/S, target speed is", int64(targetSpeed), "PKT/S")
		}
	case readWrite, generate, sendReceiveKNI, receiveRSS:
	}
}

func (current reportPair) normalize(schedTime uint) reportPair {
	// We should multiply by 1000 because schedTime is in milliseconds
	// We multiply by 8 to translate bytes to bits
	// We add 24 because 4 is checksum + 20 is before/after packet gaps in 40GB ethernet
	// We divide by 1000 and 1000 because networking suppose that megabit has 1000 kilobits instead of 1024
	return reportPair{current.Packets * 1000 / uint64(schedTime), (current.Bytes + current.Packets*24) * 1000 / uint64(schedTime) * 8 / 1000 / 1000}
}

func (ff *flowFunction) updateCurrentSpeed() {
	// Gather and sum current speeds from all clones of current flow function
	// Flow function itself and all clones put their speeds in one channel
	ff.currentSpeed = reportPair{}
	t := len(ff.report) - ff.cloneNumber
	for k := 0; k < t; k++ {
		<-ff.report
	}
	for k := 0; k < ff.cloneNumber; k++ {
		temp := <-ff.report
		ff.currentSpeed.Packets += temp.Packets
		ff.currentSpeed.Bytes += temp.Bytes
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

func (ff *flowFunction) checkInputRingClonable(min uint32) bool {
	switch ff.Parameters.(type) {
	case *segmentParameters:
		if ff.Parameters.(*segmentParameters).in.GetRingCount() > min {
			return true
		}
	case *copyParameters:
		if ff.Parameters.(*copyParameters).in.GetRingCount() > min {
			return true
		}
	case *receiveParameters:
		if low.CheckRSSPacketCount(ff.Parameters.(*receiveParameters).port) > min {
			return true
		}
	}
	return false
}

func (ff *flowFunction) checkOutputRingClonable(max uint32) bool {
	switch ff.Parameters.(type) {
	case *receiveParameters:
		if ff.Parameters.(*receiveParameters).out.GetRingCount() <= max {
			return true
		}
	case *generateParameters:
		if ff.Parameters.(*generateParameters).out.GetRingCount() <= max {
			return true
		}
	case *copyParameters:
		if ff.Parameters.(*copyParameters).out.GetRingCount() <= max ||
			ff.Parameters.(*copyParameters).outCopy.GetRingCount() <= max {
			return true
		}
	case *segmentParameters:
		p := *(ff.Parameters.(*segmentParameters).out)
		for i := range p {
			if p[i].GetRingCount() <= max {
				return true
			}
		}
	}
	return false
}
