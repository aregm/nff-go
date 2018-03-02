// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scheduler

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
}

// UserContext is used inside flow packet and is going for user via it
type UserContext interface {
	Copy() interface{}
	Delete()
}

// Function types which are used inside flow functions
type uncloneFlowFunction func(interface{}, int)
type cloneFlowFunction func(interface{}, chan int, chan uint64, UserContext)
type conditionFlowFunction func(interface{}, bool) int

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
	name        string
	context     UserContext
	targetSpeed float64
	pause       int
}

// NewFF is a function for adding every flow function. Then these function will be concatenated with
// appropriate lists, for example Clonable or Unclonable
func (scheduler *Scheduler) NewFF(name string, ucfn uncloneFlowFunction, cfn cloneFlowFunction,
	par interface{}, check conditionFlowFunction, targetSpeed float64, report chan uint64, context UserContext) *FlowFunction {
	ff := new(FlowFunction)
	scheduler.ffCount++
	ff.name = name + " " + strconv.Itoa(scheduler.ffCount)
	ff.uncloneFunction = ucfn
	ff.cloneFunction = cfn
	ff.Parameters = par
	ff.checkPrintFunction = check
	ff.report = report
	ff.context = context
	ff.targetSpeed = targetSpeed
	return ff
}

// Scheduler is a main structure for scheduler. Is used inside flow package
type Scheduler struct {
	Clonable          []*FlowFunction
	UnClonable        []*FlowFunction
	Generate          []*FlowFunction
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
}

type core struct {
	id     int
	isfree bool
}

// NewScheduler is a function for creation new scheduler. Is used inside flow package
func NewScheduler(cpus []int, schedulerOff bool, schedulerOffRemove bool,
	stopDedicatedCore bool, stopRing *low.Ring, checkTime uint, debugTime uint) Scheduler {
	coresNumber := len(cpus)
	// Init scheduler
	scheduler := new(Scheduler)
	scheduler.cores = make([]core, coresNumber, coresNumber)
	for i, cpu := range cpus {
		scheduler.cores[i] = core{id: cpu, isfree: true}
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
func (scheduler *Scheduler) SystemStart() (err error) {
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
	for i := range scheduler.UnClonable {
		if core, err = scheduler.getCore(); err != nil {
			return err
		}
		ff := scheduler.UnClonable[i]
		common.LogDebug(common.Initialization, "Start unclonable FlowFunction", ff.name, "at", core, "core")
		go func() {
			ff.uncloneFunction(ff.Parameters, core)
		}()
	}
	for i := range scheduler.Clonable {
		if err = scheduler.startClonable(scheduler.Clonable[i]); err != nil {
			return err
		}
	}
	for i := range scheduler.Generate {
		if err = scheduler.startClonable(scheduler.Generate[i]); err != nil {
			return err
		}
	}
	// We need this to get a chance to all started goroutines to log their warnings.
	time.Sleep(time.Millisecond)
	return nil
}

func (scheduler *Scheduler) startClonable(ff *FlowFunction) (err error) {
	var core int
	if core, err = scheduler.getCore(); err != nil {
		return err
	}
	common.LogDebug(common.Initialization, "Start clonable FlowFunction", ff.name, "at", core, "core")
	go func() {
		if err := low.SetAffinity(core); err != nil {
			common.LogFatal(common.Initialization, "Failed to set affinity to", core, "core: ", err)
		}
		ff.channel = make(chan int)
		if ff.context != nil {
			ff.cloneFunction(ff.Parameters, ff.channel, ff.report, (ff.context.Copy()).(UserContext))
		} else {
			ff.cloneFunction(ff.Parameters, ff.channel, ff.report, nil)
		}
	}()
	return nil
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
			common.LogDebug(common.Debug, "System is using", scheduler.usedCores, "cores now.", uint8(len(scheduler.cores))-scheduler.usedCores, "cores are left available.")
			low.Statistics(float32(scheduler.debugTime) / 1000)
			for i := range scheduler.Clonable {
				scheduler.Clonable[i].printDebug(schedTime)
			}
			for i := range scheduler.Generate {
				scheduler.Generate[i].printDebug(schedTime)
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
			ff.updateCurrentSpeed()

			// Firstly we check removing clones. We can remove one clone if:
			// 1. flow function has clones
			// 2. scheduler removing is switched on
			// 3. current speed of flow function is lower, than saved speed with less number of clones
			if (ff.cloneNumber != 0) && (scheduler.offRemove == false) && (ff.currentSpeed < speedDelta*ff.previousSpeed[ff.cloneNumber-1]) {
				// Save current speed as speed of flow function with this number of clones before removing
				ff.previousSpeed[ff.cloneNumber] = ff.currentSpeed
				scheduler.removeClone(ff)
				ff.updatePause(ff.cloneNumber)
				// After removing a clone we don't want to try to add clone immediately
				continue
			}

			// Secondly we check adding clones. We can add one clone if:
			// 1. check function signals that we need to clone
			// 2. scheduler is switched on
			// 3. we don't know flow function speed with more clones, or we know it and it is bigger than current speed
			if (ff.checkPrintFunction(ff.Parameters, false) == 1) && (scheduler.off == false) &&
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
		}

		// Procced with each generate flow function
		for i := range scheduler.Generate {
			ff := scheduler.Generate[i]
			ff.updateCurrentSpeed()

			speedPKTS := float64(convertPKTS(ff.currentSpeed, schedTime))
			if speedPKTS > 1.1*ff.targetSpeed {
				if ff.targetSpeed/float64(ff.cloneNumber+1)*float64(ff.cloneNumber) > speedPKTS {
					if scheduler.offRemove == false {
						scheduler.removeClone(ff)
						ff.updatePause(0)
						continue
					}
				} else {
					if ff.pause == 0 {
						// This is proportion between required and current speeds.
						// 1000000000 is converting to nanoseconds
						ff.updatePause(int((speedPKTS - ff.targetSpeed) / speedPKTS / ff.targetSpeed * 1000000000))
					} else if float64(ff.pause)*generatePauseStep < 2 {
						// Multiplying can't be used here due to integer truncation
						ff.updatePause(ff.pause + 3)
					} else {
						ff.updatePause(int((1 + generatePauseStep) * float64(ff.pause)))
					}
				}
			} else if speedPKTS < ff.targetSpeed {
				if ff.pause != 0 {
					ff.updatePause(int((1 - generatePauseStep) * float64(ff.pause)))
				} else if scheduler.off == false {
					scheduler.startClone(ff)
					ff.updatePause(0)
					continue
				}
			}
		}
		checkRequired = false
		runtime.Gosched()
	}
}

func (scheduler *Scheduler) startClone(ff *FlowFunction) bool {
	index := scheduler.getCoreIndex()
	if index == -1 {
		common.LogWarning(common.Debug, "Can't start new clone for", ff.name)
		return false
	}
	core := scheduler.cores[index].id
	cp := new(clonePair)
	cp.channel = make(chan int)
	cp.index = index
	ff.clone = append(ff.clone, cp)
	ff.cloneNumber++
	go func() {
		err := low.SetAffinity(core)
		if err != nil {
			common.LogFatal(common.Debug, "Failed to set affinity to", core, "core: ", err)
		}
		if ff.context != nil {
			ff.cloneFunction(ff.Parameters, cp.channel, ff.report, (ff.context.Copy()).(UserContext))
		} else {
			ff.cloneFunction(ff.Parameters, cp.channel, ff.report, nil)
		}
	}()
	return true
}

func (scheduler *Scheduler) removeClone(ff *FlowFunction) {
	ff.clone[ff.cloneNumber-1].channel <- -1
	scheduler.setCoreByIndex(ff.clone[ff.cloneNumber-1].index)
	ff.clone = ff.clone[:len(ff.clone)-1]
	ff.cloneNumber--
}

func (ff *FlowFunction) updatePause(pause int) {
	ff.pause = pause
	ff.channel <- ff.pause
	for j := 0; j < ff.cloneNumber; j++ {
		ff.clone[j].channel <- ff.pause
	}
}

func (ff *FlowFunction) printDebug(schedTime uint) {
	if ff.checkPrintFunction != nil {
		ff.checkPrintFunction(ff.Parameters, true)
	}
	speedPKTS := convertPKTS(ff.currentSpeed, schedTime)
	// We multiply by 84 because it is the minimal packet size (64) plus before/after packet gaps in 40GB ethernet
	// We multiply by 8 to translate bytes to bits
	// We divide by 1000 and 1000 because networking suppose that megabit has 1000 kilobits instead of 1024
	// TODO This Mbits measurement should be used only for 84 packet size for debug purposes
	// speedMbits := speedPKTS * 84 * 8 / 1000 / 1000
	if ff.targetSpeed == 0 {
		common.LogDebug(common.Debug, "Current speed of", ff.name, "is", speedPKTS, "PKT/S")
	} else {
		common.LogDebug(common.Debug, "Current speed of", ff.name, "is", speedPKTS, "PKT/S, target speed is", int64(ff.targetSpeed), "PKT/S")
	}
}

func convertPKTS(currentSpeed float64, schedTime uint) uint64 {
	// We should multiply by 1000 because schedTime is in milliseconds
	return uint64(currentSpeed) * 1000 / uint64(schedTime)
}

func (ff *FlowFunction) updateCurrentSpeed() {
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

func (scheduler *Scheduler) setCoreByIndex(i int) {
	scheduler.cores[i].isfree = true
	scheduler.usedCores--
}

func (scheduler *Scheduler) getCoreIndex() int {
	for i := range scheduler.cores {
		if scheduler.cores[i].isfree == true {
			scheduler.cores[i].isfree = false
			scheduler.usedCores++
			return i
		}
	}
	return -1
}

func (scheduler *Scheduler) getCore() (int, error) {
	index := scheduler.getCoreIndex()
	if index == -1 {
		return 0, common.WrapWithNFError(nil, "Requested number of cores isn't enough. System needs at least one core per each Set function (except Merger and Stopper) plus one additional core.", common.NotEnoughCores)
	}
	return scheduler.cores[index].id, nil
}
