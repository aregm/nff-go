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
	"time"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/low"
)

// TODO: 1 is a delta of speeds. This delta should be
// verified or should be tunable from outside.
const speedDelta = 1
const generatePauseStep = 0.1

// Clones of flow functions. They are determined
// by their core and their stopper channel
type clonePair struct {
	index   int
	channel chan int
	flag    int
}

// UserContext is used inside flow packet and is going for user via it
type UserContext interface {
	Copy() interface{}
	Delete()
}

// Function types which are used inside flow functions
type uncloneFlowFunction func(interface{})
type cloneFlowFunction func(interface{}, chan int, chan uint64, UserContext)
type cFlowFunction func(interface{}, *int, int)

type ffType int

const (
	handleSplitSeparateCopy ffType = iota
	fastGenerate
	receiveRSS     // receive from port
	sendReceiveKNI // send to port, send to KNI, receive from KNI
	other
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
	// Pause channel of function itself (not clones)
	channel chan int
	// Number of clones of this function
	cloneNumber int
	// Clones of this function. They are determined
	// by their core and their stopper channel
	clone []*clonePair
	// Channel for reporting current speed.
	// It is one for all clones
	report chan uint64
	// Current saved speed when making a clone.
	// It will be compared with immediate current speed to stop a clone.
	previousSpeed []float64
	// For debug purposes
	currentSpeed float64
	// Name of flow function
	name    string
	context UserContext
	pause   int
	fType   ffType
}

// Adding every flow function to scheduler list
func (scheduler *scheduler) addFF(name string, ucfn uncloneFlowFunction, Cfn cFlowFunction, cfn cloneFlowFunction,
	par interface{}, report chan uint64, context UserContext, fType ffType) {
	ff := new(flowFunction)
	scheduler.ffCount++
	ff.name = name + " " + strconv.Itoa(scheduler.ffCount)
	ff.uncloneFunction = ucfn
	ff.cFunction = Cfn
	ff.cloneFunction = cfn
	ff.Parameters = par
	ff.report = report
	ff.context = context
	ff.previousSpeed = make([]float64, len(scheduler.cores), len(scheduler.cores))
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
	ffCount           int
	maxPacketsToClone uint32
}

type core struct {
	id     int
	isfree bool
}

func newScheduler(cpus []int, schedulerOff bool, schedulerOffRemove bool,
	stopDedicatedCore bool, stopRing *low.Ring, checkTime uint, debugTime uint, maxPacketsToClone uint32) *scheduler {
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

	return scheduler
}

func (scheduler *scheduler) systemStart() (err error) {
	var core int
	if core, err = scheduler.getCore(); err != nil {
		return err
	}
	common.LogDebug(common.Initialization, "Start SCHEDULER at", core, "core")
	if err = low.SetAffinity(core); err != nil {
		common.LogFatal(common.Initialization, "Failed to set affinity to", core, "core: ", err)
	}
	if scheduler.stopDedicatedCore {
		if core, err = scheduler.getCore(); err != nil {
			return err
		}
		common.LogDebug(common.Initialization, "Start STOP at", core, "core")
	} else {
		common.LogDebug(common.Initialization, "Start STOP at scheduler", core, "core")
	}
	go func() {
		low.Stop(scheduler.StopRing, core)
	}()
	for i := range scheduler.ff {
		if core, err := scheduler.getCore(); err != nil {
			return err
		} else if err = scheduler.startFF(scheduler.ff[i], core); err != nil {
			return err
		}
	}
	// We need this to get a chance to all started goroutines to log their warnings.
	time.Sleep(time.Millisecond)
	return nil
}

func (scheduler *scheduler) startFF(ff1 *flowFunction, core int) (err error) {
	ff := ff1
	common.LogDebug(common.Initialization, "Start FlowFunction", ff.name, "at", core, "core")
	stopFlag := int(1)
	go func() {
		if ff.fType != receiveRSS && ff.fType != sendReceiveKNI {
			if err := low.SetAffinity(core); err != nil {
				common.LogFatal(common.Initialization, "Failed to set affinity to", core, "core: ", err)
			}
			if ff.fType == handleSplitSeparateCopy || ff.fType == fastGenerate {
				ff.channel = make(chan int)
				if ff.context != nil {
					ff.cloneFunction(ff.Parameters, ff.channel, ff.report, (ff.context.Copy()).(UserContext))
				} else {
					ff.cloneFunction(ff.Parameters, ff.channel, ff.report, nil)
				}
			} else {
				ff.uncloneFunction(ff.Parameters)
			}
		} else {
			ff.cFunction(ff.Parameters, &stopFlag, core)
		}
	}()
	return nil
}

// Main loop after framework was started
func (scheduler *scheduler) schedule(schedTime uint) {
	tick := time.Tick(time.Duration(scheduler.checkTime) * time.Millisecond)
	debugTick := time.Tick(time.Duration(scheduler.debugTime) * time.Millisecond)
	checkRequired := false
	for {
		time.Sleep(time.Millisecond * time.Duration(schedTime))
		select {
		case <-tick:
			checkRequired = true
		case <-debugTick:
			// Report current state of system
			common.LogDebug(common.Debug, "---------------")
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
		default:
		}
		// Procced with each flow function
		for i := range scheduler.ff {
			recC := -1
			ff := scheduler.ff[i]
			if ff.fType == handleSplitSeparateCopy || ff.fType == fastGenerate {
				ff.updateCurrentSpeed()
			}
			// Firstly we check removing clones. We can remove one clone if:
			// 1. flow function has clones
			// 2. scheduler removing is switched on
			if (ff.cloneNumber != 0) && (scheduler.offRemove == false) {
				switch ff.fType {
				case handleSplitSeparateCopy:
					// 3. current speed of flow function is lower, than saved speed with less number of clones
					if ff.currentSpeed < speedDelta*ff.previousSpeed[ff.cloneNumber-1] {
						// Save current speed as speed of flow function with this number of clones before removing
						ff.previousSpeed[ff.cloneNumber] = ff.currentSpeed
						scheduler.removeClone(ff)
						ff.updatePause(ff.cloneNumber)
						// After removing a clone we don't want to try to add clone immediately
						continue
					}
				case fastGenerate:
					targetSpeed := (ff.Parameters.(*generateParameters)).targetSpeed
					speedPKTS := float64(convertPKTS(ff.currentSpeed, schedTime))
					// 3. Current speed is much bigger than target speed
					if speedPKTS > 1.1*targetSpeed {
						// 4. TODO strange heuristic, it is required to check this
						if targetSpeed/float64(ff.cloneNumber+1)*float64(ff.cloneNumber) > speedPKTS {
							scheduler.removeClone(ff)
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
					recC = low.CheckRSSPacketCount(ff.Parameters.(*receiveParameters).port)
					// TODO "5" and "39" constants below derived empirically. Need to investigate more elegant thresholds.
					if recC < 5 {
						scheduler.removeClone(ff)
						low.DecreaseRSS((ff.Parameters.(*receiveParameters)).port)
						continue
					}
				case other, sendReceiveKNI:
				}
			}
			// Secondly we check adding clones. We can add one clone if:
			// 1. scheduler is switched on
			if scheduler.off == false {
				switch ff.fType {
				case handleSplitSeparateCopy:
					// 2. check function signals that we need to clone
					// 3. we don't know flow function speed with more clones, or we know it and it is bigger than current speed
					if (ff.checkInputRing() > scheduler.maxPacketsToClone) &&
						(ff.previousSpeed[ff.cloneNumber+1] == 0 || ff.previousSpeed[ff.cloneNumber+1] > speedDelta*ff.currentSpeed) {
						// Save current speed as speed of flow function with this number of clones before adding
						ff.previousSpeed[ff.cloneNumber] = ff.currentSpeed
						if scheduler.startClone(ff) == true {
							// Add a pause to all clones. This pause depends on the number of clones.
							ff.updatePause(ff.cloneNumber)
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
						ff.previousSpeed[ff.cloneNumber+1] = 0
					}
				case fastGenerate:
					// 2. speed is not enough
					if float64(convertPKTS(ff.currentSpeed, schedTime)) < (ff.Parameters.(*generateParameters)).targetSpeed {
						if ff.pause != 0 {
							ff.updatePause(int((1 - generatePauseStep) * float64(ff.pause)))
						} else {
							// 3. there is no pause
							scheduler.startClone(ff)
							ff.updatePause(0)
							continue
						}
					}
				case receiveRSS:
					if recC == -1 {
						recC = low.CheckRSSPacketCount(ff.Parameters.(*receiveParameters).port)
					}
					if recC > 39 && ff.checkOutputRing() <= scheduler.maxPacketsToClone {
						if low.IncreaseRSS((ff.Parameters.(*receiveParameters)).port) {
							scheduler.startClone(ff)
						}
					}
				case other, sendReceiveKNI:
				}
			}
		}
		checkRequired = false
		runtime.Gosched()
	}
}

func (scheduler *scheduler) startClone(ff *flowFunction) bool {
	index := scheduler.getCoreIndex()
	if index == -1 {
		common.LogWarning(common.Debug, "Can't start new clone for", ff.name)
		return false
	}
	core := scheduler.cores[index].id
	cp := new(clonePair)
	cp.index = index
	if ff.fType == handleSplitSeparateCopy || ff.fType == fastGenerate {
		cp.channel = make(chan int)
	}
	cp.flag = 1
	ff.clone = append(ff.clone, cp)
	ff.cloneNumber++
	go func() {
		if ff.fType == handleSplitSeparateCopy || ff.fType == fastGenerate {
			err := low.SetAffinity(core)
			if err != nil {
				common.LogFatal(common.Debug, "Failed to set affinity to", core, "core: ", err)
			}
			if ff.context != nil {
				ff.cloneFunction(ff.Parameters, cp.channel, ff.report, (ff.context.Copy()).(UserContext))
			} else {
				ff.cloneFunction(ff.Parameters, cp.channel, ff.report, nil)
			}
		} else {
			ff.cFunction(ff.Parameters, &cp.flag, core)
		}
	}()
	return true
}

func (scheduler *scheduler) removeClone(ff *flowFunction) {
	if ff.fType == handleSplitSeparateCopy || ff.fType == fastGenerate {
		ff.clone[ff.cloneNumber-1].channel <- -1
	} else {
		ff.clone[ff.cloneNumber-1].flag = 0
	}
	scheduler.setCoreByIndex(ff.clone[ff.cloneNumber-1].index)
	ff.clone = ff.clone[:len(ff.clone)-1]
	ff.cloneNumber--
}

func (ff *flowFunction) updatePause(pause int) {
	ff.pause = pause
	ff.channel <- ff.pause
	for j := 0; j < ff.cloneNumber; j++ {
		ff.clone[j].channel <- ff.pause
	}
}

func (ff *flowFunction) printDebug(schedTime uint) {
	switch ff.fType {
	case handleSplitSeparateCopy:
		common.LogDebug(common.Debug, "Number of packets in queue", ff.name, ":", ff.checkInputRing())
		speedPKTS := convertPKTS(ff.currentSpeed, schedTime)
		common.LogDebug(common.Debug, "Current speed of", ff.name, "is", speedPKTS, "PKT/S")
	case fastGenerate:
		targetSpeed := (ff.Parameters.(*generateParameters)).targetSpeed
		speedPKTS := convertPKTS(ff.currentSpeed, schedTime)
		common.LogDebug(common.Debug, "Current speed of", ff.name, "is", speedPKTS, "PKT/S, target speed is", int64(targetSpeed), "PKT/S")
	case other, sendReceiveKNI, receiveRSS:
	}
}

func convertPKTS(currentSpeed float64, schedTime uint) uint64 {
	// We should multiply by 1000 because schedTime is in milliseconds
	return uint64(currentSpeed) * 1000 / uint64(schedTime)
	// We multiply by 84 because it is the minimal packet size (64) plus before/after packet gaps in 40GB ethernet
	// We multiply by 8 to translate bytes to bits
	// We divide by 1000 and 1000 because networking suppose that megabit has 1000 kilobits instead of 1024
	// TODO This Mbits measurement should be used only for 84 packet size for debug purposes
	// speedMbits := speedPKTS * 84 * 8 / 1000 / 1000
}

func (ff *flowFunction) updateCurrentSpeed() {
	// Gather and sum current speeds from all clones of current flow function
	// Flow function itself and all clones put their speeds in one channel
	currentSpeed := uint64(0)
	t := len(ff.report) - ff.cloneNumber - 1
	for k := 0; k < t; k++ {
		<-ff.report
	}
	for k := 0; k < ff.cloneNumber+1; k++ {
		currentSpeed += <-ff.report
	}
	ff.currentSpeed = float64(currentSpeed)
}

func (scheduler *scheduler) setCoreByIndex(i int) {
	scheduler.cores[i].isfree = true
	scheduler.usedCores--
}

func (scheduler *scheduler) getCoreIndex() int {
	for i := range scheduler.cores {
		if scheduler.cores[i].isfree == true {
			scheduler.cores[i].isfree = false
			scheduler.usedCores++
			return i
		}
	}
	return -1
}

func (scheduler *scheduler) getCore() (int, error) {
	index := scheduler.getCoreIndex()
	if index == -1 {
		return 0, common.WrapWithNFError(nil, "Requested number of cores isn't enough. System needs at least one core per each Set function (except Merger and Stopper) plus one additional core.", common.NotEnoughCores)
	}
	return scheduler.cores[index].id, nil
}

func (ff *flowFunction) checkInputRing() (n uint32) {
	switch ff.Parameters.(type) {
	case *handleParameters:
		n = ff.Parameters.(*handleParameters).in.GetRingCount()
	case *separateParameters:
		n = ff.Parameters.(*separateParameters).in.GetRingCount()
	case *splitParameters:
		n = ff.Parameters.(*splitParameters).in.GetRingCount()
	case *copyParameters:
		n = ff.Parameters.(*copyParameters).in.GetRingCount()
	}
	return n
}

func (ff *flowFunction) checkOutputRing() (n uint32) {
	switch ff.Parameters.(type) {
	case *receiveParameters:
		n = ff.Parameters.(*receiveParameters).out.GetRingCount()
	}
	return n
}
