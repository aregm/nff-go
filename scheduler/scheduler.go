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

// TODO: now it is number of milliseconds after what we
// check our system and add / delete clones. However it isn't
// stable. We should calculate something more general than time
// because our goroutine can not be stopped by timer when we
// expect this.
var ScaleTime uint

// TODO: 0.98 is a delta of speeds. This delta should be
// verified or should be tunable from outside.
const speedDelta = 0.98

// Clones of flow functions. They are determined
// by their core and their stopper channel
type clonePair struct {
	core    int
	channel chan int
}

// Function types which are used inside flow functions
type uncloneFlowFunction func(interface{}, uint8)
type cloneFlowFunction func(interface{}, chan int, chan uint64)
type conditionFlowFunction func(interface{}, uint64) bool

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
	previousSpeed float64
	// Name of flow function
	name string
	// Identifier which could be used together with flow function name
	// to uniquely identify this flow function
	identifier int
}

func NewUnclonableFlowFunction(name string, id int, ucfn uncloneFlowFunction, par interface{}) *FlowFunction {
	ff := new(FlowFunction)
	ff.name = name
	ff.identifier = id
	ff.uncloneFunction = ucfn
	ff.Parameters = par
	return ff
}

func NewClonableFlowFunction(name string, id int, cfn cloneFlowFunction, par interface{}, check conditionFlowFunction, report chan uint64) *FlowFunction {
	ff := new(FlowFunction)
	ff.name = name
	ff.identifier = id
	ff.cloneFunction = cfn
	ff.Parameters = par
	ff.checkPrintFunction = check
	ff.report = report
	return ff
}

type Scheduler struct {
	Clonable   []*FlowFunction
	UnClonable []*FlowFunction
	freeCores  []bool
	off        bool
	offRemove  bool
	StopRing   *low.Queue
	usedCores  uint8
}

func NewScheduler(coresNumber uint, schedulerOff bool, schedulerOffRemove bool, stopRing *low.Queue) Scheduler {
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

	return *scheduler
}

func (scheduler *Scheduler) SystemStart() {
	core := scheduler.getCore(true)
	common.LogDebug(common.Initialization, "Start SCHEDULER at", core, "core")
	low.SetAffinity(uint8(core))
	core = scheduler.getCore(true)
	common.LogDebug(common.Initialization, "Start STOP at", core, "core")
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
			ff.cloneFunction(ff.Parameters, nil, ff.report)
		}()
	}
	// We need this to get a chance to all started goroutines to log their warnings.
	time.Sleep(time.Millisecond)
}

func (scheduler *Scheduler) Schedule(schedTime uint) {
	for {
		time.Sleep(time.Millisecond * time.Duration(schedTime))
		common.LogDebug(common.Debug, "System is using", scheduler.usedCores, "cores now.", uint8(len(scheduler.freeCores))-scheduler.usedCores, "cores are left available.")
		for i := range scheduler.Clonable {
			ff := scheduler.Clonable[i]
			currentSpeed := <-ff.report
			for k := 0; k < ff.cloneNumber; k++ {
				currentSpeed += <-ff.report
			}
			// We should multiply by 1000 because schedTime is in milliseconds
			speedPKTS := currentSpeed * 1000 / uint64(schedTime)
			// We multiply by 84 because it is the minimal packet size (64) plus before/after packet gaps in 40GB ethernet
			// We multiply by 8 to translate bytes to bits
			// We divide by 1000 and 1000 because networking suppose that megabit has 1000 kilobits instead of 1024
			// TODO This Mbits measurement should be used only for 84 packet size for debug purposes
			speedMbits := speedPKTS * 84 * 8 / 1000 / 1000
			common.LogDebug(common.Debug, "Current speed of", ff.name, ff.identifier, "is", speedMbits, "Mbits/S,", speedPKTS, "PKT/S")
			if (ff.checkPrintFunction(ff.Parameters, speedPKTS) == true) && (scheduler.off == false) {
				ff.previousSpeed = float64(currentSpeed)
				go func() {
					core := scheduler.getCore(false)
					if core != -1 {
						common.LogDebug(common.Debug, "Start new clone for", ff.name, ff.identifier, "at", core, "core")
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
						ff.cloneFunction(ff.Parameters, quit, ff.report)
					} else {
						common.LogWarning(common.Debug, "Can't start new clone for", ff.name, ff.identifier)
					}
				}()
			}
			if (scheduler.offRemove == false) && (float64(currentSpeed) < speedDelta*ff.previousSpeed) {
				if ff.cloneNumber != 0 {
					common.LogDebug(common.Debug, "Stop a clone of", ff.name, ff.identifier, "at", ff.clone[ff.cloneNumber-1].core, "core")
					ff.clone[ff.cloneNumber-1].channel <- -1
					scheduler.setCore(ff.clone[ff.cloneNumber-1].core)
					ff.clone = ff.clone[:len(ff.clone)-1]
					ff.cloneNumber--
					for j := 0; j < ff.cloneNumber; j++ {
						ff.clone[j].channel <- ff.cloneNumber
					}
				}
			}
		}
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
		common.LogError(common.Initialization, "Requested number of cores isn't enough. System needs at least one core per each Set function (except Merger and Stop) plus two additional cores.")
	}
	return -1
}
