// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scheduler

import (
	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/low"
	"runtime"
	"time"
)

// TODO: 1 is a delta of speeds. This delta should be
// verified or should be tunable from outside.
const speedDelta = 1

// Clones of flow functions. They are determined
// by their core and their stopper channel
type clonePair struct {
	core    int
	channel chan int
}

// UserContext is used inside flow packet and is going for user via it
type UserContext interface {
	Copy() interface{}
}

// Function types which are used inside flow functions
type uncloneFlowFunction func(interface{}, uint8)
type cloneFlowFunction func(interface{}, chan int, chan uint64, UserContext)
type conditionFlowFunction func(interface{}, uint64, bool) bool

// FlowFunction is a structure for all functions, is used inside flow package
type FlowFunction struct {
	// All parameters which gets these flow function
	Parameters interface{}
	// Main body of unclonable flow function
	uncloneFunction uncloneFlowFunction
	// Main body of clonable flow function
	cloneFunction cloneFlowFunction
	// Function true or false
	// and is used by scheduler
	checkPrintFunction conditionFlowFunction
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
	// Name of flow function
	name string
	// Identifier which could be used together with flow function name
	// to uniquely identify this flow function
	identifier int
	context    UserContext
}

// NewUnclonableFlowFunction is a function for adding unclonable flow functions. Is used inside flow package
func (scheduler *Scheduler) NewUnclonableFlowFunction(name string, id int, ucfn uncloneFlowFunction,
	par interface{}) *FlowFunction {
	ff := new(FlowFunction)
	ff.name = name
	ff.identifier = id
	ff.uncloneFunction = ucfn
	ff.Parameters = par
	return ff
}

// NewClonableFlowFunction is a function for adding clonable flow functions. Is used inside flow package
func (scheduler *Scheduler) NewClonableFlowFunction(name string, id int, cfn cloneFlowFunction,
	par interface{}, check conditionFlowFunction, report chan uint64, context UserContext) *FlowFunction {
	ff := new(FlowFunction)
	ff.name = name
	ff.identifier = id
	ff.cloneFunction = cfn
	ff.Parameters = par
	ff.checkPrintFunction = check
	ff.report = report
	ff.previousSpeed = make([]float64, len(scheduler.freeCores), len(scheduler.freeCores))
	ff.context = context
	return ff
}

// Scheduler is a main structure for scheduler. Is used inside flow package
type Scheduler struct {
	Clonable          []*FlowFunction
	UnClonable        []*FlowFunction
	freeCores         []bool
	off               bool
	offRemove         bool
	stopDedicatedCore bool
	StopRing          *low.Queue
	usedCores         uint8
	checkTime         uint
	debugTime         uint
	Dropped           uint
}

// NewScheduler is a function for creation new scheduler. Is used inside flow package
func NewScheduler(coresNumber uint, schedulerOff bool, schedulerOffRemove bool,
	stopDedicatedCore bool, stopRing *low.Queue, checkTime uint, debugTime uint) Scheduler {
	// Init scheduler
	scheduler := new(Scheduler)
	scheduler.freeCores = make([]bool, coresNumber, coresNumber)
	for i := uint(0); i < coresNumber; i++ {
		scheduler.freeCores[i] = true
	}
	scheduler.off = schedulerOff
	scheduler.offRemove = schedulerOff || schedulerOffRemove
	scheduler.StopRing = stopRing
	scheduler.usedCores = 0
	scheduler.stopDedicatedCore = stopDedicatedCore
	scheduler.checkTime = checkTime
	scheduler.debugTime = debugTime
	scheduler.Dropped = 0

	return *scheduler
}

// SystemStart starts whole system. Is used inside flow package
func (scheduler *Scheduler) SystemStart() {
	core := scheduler.getCore(true)
	common.LogDebug(common.Initialization, "Start SCHEDULER at", core, "core")
	low.SetAffinity(uint8(core))
	if scheduler.stopDedicatedCore {
		core = scheduler.getCore(true)
		common.LogDebug(common.Initialization, "Start STOP at", core, "core")
	} else {
		common.LogDebug(common.Initialization, "Start STOP at scheduler", core, "core")
	}
	go func() {
		low.SetAffinity(uint8(core))
		low.Stop(scheduler.StopRing)
	}()
	for i := range scheduler.UnClonable {
		ff := scheduler.UnClonable[i]
		core := scheduler.getCore(true)
		common.LogDebug(common.Initialization, "Start unclonable FlowFunction", ff.name, ff.identifier, "at", core, "core")
		go func() {
			ff.uncloneFunction(ff.Parameters, uint8(core))
		}()
	}
	for i := range scheduler.Clonable {
		ff := scheduler.Clonable[i]
		core := scheduler.getCore(true)
		common.LogDebug(common.Initialization, "Start clonable FlowFunction", ff.name, ff.identifier, "at", core, "core")
		go func() {
			low.SetAffinity(uint8(core))
			ff.cloneNumber = 0
			if ff.context != nil {
				ff.cloneFunction(ff.Parameters, nil, ff.report, (ff.context.Copy()).(UserContext))
			} else {
				ff.cloneFunction(ff.Parameters, nil, ff.report, nil)
			}
		}()
	}
	// We need this to get a chance to all started goroutines to log their warnings.
	time.Sleep(time.Millisecond)
}

// Schedule - main execution. Is used inside flow package
func (scheduler *Scheduler) Schedule(schedTime uint) {
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
			common.LogDebug(common.Debug, "System is using", scheduler.usedCores, "cores now.", uint8(len(scheduler.freeCores))-scheduler.usedCores, "cores are left available.")
			low.Statistics(float32(scheduler.debugTime) / 1000)
			for i := range scheduler.Clonable {
				scheduler.Clonable[i].checkPrintFunction(scheduler.Clonable[i].Parameters, 0, true)
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
		// Procced with each clonable flow function
		for i := range scheduler.Clonable {
			ff := scheduler.Clonable[i]

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
			// We should multiply by 1000 because schedTime is in milliseconds
			speedPKTS := currentSpeed * 1000 / uint64(schedTime)
			// We multiply by 84 because it is the minimal packet size (64) plus before/after packet gaps in 40GB ethernet
			// We multiply by 8 to translate bytes to bits
			// We divide by 1000 and 1000 because networking suppose that megabit has 1000 kilobits instead of 1024
			// TODO This Mbits measurement should be used only for 84 packet size for debug purposes
//			speedMbits := speedPKTS * 84 * 8 / 1000 / 1000
			common.LogDebug(common.Debug, "Current speed of", ff.name, ff.identifier, "is", speedPKTS, "PKT/S")

			// After we gather current speed we can add or remove clones.

			// Firstly we check removing clones. We can remove one clone if:
			// 1. flow function has clones
			// 2. scheduler removing is switched on
			// 3. current speed of flow function is lower, than saved speed with less number of clones
			if (ff.cloneNumber != 0) && (scheduler.offRemove == false) && (float64(currentSpeed) < speedDelta*ff.previousSpeed[ff.cloneNumber-1]) {
				// Save current speed as speed of flow function with this number of clones before removing
				ff.previousSpeed[ff.cloneNumber] = float64(currentSpeed)
				ff.clone[ff.cloneNumber-1].channel <- -1
				scheduler.setCore(ff.clone[ff.cloneNumber-1].core)
				ff.clone = ff.clone[:len(ff.clone)-1]
				ff.cloneNumber--
				for j := 0; j < ff.cloneNumber; j++ {
					ff.clone[j].channel <- ff.cloneNumber
				}
				// After removing a clone we don't want to try to add clone immediately
				continue
			}

			// Secondly we check adding clones. We can add one clone if:
			// 1. check function signals that we need to clone
			// 2. scheduler is switched on
			// 3. we don't know flow function speed with more clones, or we know it and it is bigger than current speed
			if (ff.checkPrintFunction(ff.Parameters, speedPKTS, false) == true) && (scheduler.off == false) &&
				(ff.previousSpeed[ff.cloneNumber+1] == 0 || ff.previousSpeed[ff.cloneNumber+1] > speedDelta*float64(currentSpeed)) {
				// Save current speed as speed of flow function with this number of clones before adding
				ff.previousSpeed[ff.cloneNumber] = float64(currentSpeed)
				go func() {
					core := scheduler.getCore(false)
					if core != -1 {
						low.SetAffinity(uint8(core))
						quit := make(chan int)
						cp := new(clonePair)
						cp.channel = quit
						cp.core = core
						ff.clone = append(ff.clone, cp)
						ff.cloneNumber++
						for j := 0; j < ff.cloneNumber-1; j++ {
							// Here we want to add a pause to all clones. This pause depends on the number of clones.
							// As we can't use a channel from its goroutine we iterates to cloneNumber-1. We are OK
							// if the last clone will have zero pause as well as original (not cloned) function.
							ff.clone[j].channel <- ff.cloneNumber
						}
						if ff.context != nil {
							ff.cloneFunction(ff.Parameters, quit, ff.report, (ff.context.Copy()).(UserContext))
						} else {
							ff.cloneFunction(ff.Parameters, quit, ff.report, nil)
						}
					} else {
						common.LogWarning(common.Debug, "Can't start new clone for", ff.name, ff.identifier)
					}
				}()
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
		}
		checkRequired = false
		runtime.Gosched()
	}
}

func (scheduler *Scheduler) setCore(i int) {
	scheduler.freeCores[i] = true
	scheduler.usedCores--
}

func (scheduler *Scheduler) getCore(startStage bool) int {
	for i := range scheduler.freeCores {
		if scheduler.freeCores[i] == true {
			scheduler.freeCores[i] = false
			scheduler.usedCores++
			return i
		}
	}
	if startStage == true {
		common.LogError(common.Initialization, "Requested number of cores isn't enough. System needs at least one core per each Set function (except Merger and Stopper) plus one additional core.")
	}
	return -1
}
