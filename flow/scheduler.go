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

type instance struct {
	inIndex []int32
	// Clones of this instance
	clone []*clonePair
	// Channel for reporting current speed.
	report       chan reportPair
	currentSpeed reportPair
	// Current saved speed when making a clone.
	// It will be compared with immediate current speed to stop a clone.
	previousSpeed []reportPair
	// Number of clones of this instance
	cloneNumber int
	pause       int
	ff          *flowFunction
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
	par interface{}, context *[]UserContext, fType ffType, inIndexNumber int32) string {
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
	scheduler.ff = append(scheduler.ff, ff)
	return tName
}

type scheduler struct {
	ff                []*flowFunction
	cores             []core
	off               bool
	offRemove         bool
	anyway            bool
	stopDedicatedCore bool
	StopRing          low.Rings
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

func newScheduler(cpus []int, schedulerOff bool, schedulerOffRemove bool, stopDedicatedCore bool,
	stopRing low.Rings, checkTime uint, debugTime uint, maxPacketsToClone uint32, maxRecv int, anyway bool) *scheduler {
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
	scheduler.anyway = anyway

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
		if err = scheduler.ff[i].startNewInstance(constructNewIndex(scheduler.ff[i].inIndexNumber), scheduler); err != nil {
			return err
		}
	}
	// We need this to get a chance to all started goroutines to log their warnings.
	time.Sleep(time.Millisecond)
	return nil
}

func (ff *flowFunction) startNewInstance(inIndex []int32, scheduler *scheduler) (err error) {
	ffi := new(instance)
	common.LogDebug(common.Initialization, "Start new instance for", ff.name)
	ffi.inIndex = inIndex
	ffi.report = make(chan reportPair, 50)
	ffi.previousSpeed = make([]reportPair, len(scheduler.cores), len(scheduler.cores))
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
	core, index, err := scheduler.getCore()
	if err != nil {
		common.LogWarning(common.Debug, "Can't start new clone for", ff.name, "instance", n)
		return err
	}
	common.LogDebug(common.Initialization, "Start new clone for", ff.name, "instance", n, "at", core, "core")
	ffi.clone = append(ffi.clone, &clonePair{index, [2]chan int{nil, nil}, process})
	ffi.cloneNumber++
	if ff.fType != receiveRSS && ff.fType != sendReceiveKNI {
		ffi.clone[ffi.cloneNumber-1].channel[0] = make(chan int)
		ffi.clone[ffi.cloneNumber-1].channel[1] = make(chan int)
	}
	go func() {
		if ff.fType != receiveRSS && ff.fType != sendReceiveKNI {
			if err := low.SetAffinity(core); err != nil {
				common.LogFatal(common.Initialization, "Failed to set affinity to", core, "core: ", err)
			}
			if ff.fType == segmentCopy || ff.fType == fastGenerate || ff.fType == generate {
				ff.cloneFunction(ff.Parameters, ffi.inIndex, ffi.clone[ffi.cloneNumber-1].channel, ffi.report, cloneContext(ff.context))
			} else {
				ff.uncloneFunction(ff.Parameters, ffi.inIndex, ffi.clone[ffi.cloneNumber-1].channel)
			}
		} else {
			ff.cFunction(ff.Parameters, ffi.inIndex, &ffi.clone[ffi.cloneNumber-1].flag, core)
		}
	}()
	return nil
}

func (ff *flowFunction) stopClone(ffi *instance, scheduler *scheduler) {
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
	scheduler.setCoreByIndex(ffi.clone[ffi.cloneNumber-1].index)
	ffi.clone = ffi.clone[:len(ffi.clone)-1]
	ffi.cloneNumber--
}

func (ff *flowFunction) stopInstance(from int, to int, scheduler *scheduler) {
	common.LogDebug(common.Initialization, "Stop instance for", ff.name)
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
			if scheduler.offRemove == false {
				switch ff.fType {
				case segmentCopy: // Both instances and clones
					for q := 0; q < ff.instanceNumber; q++ {
						ffi := ff.instance[q]
						if ffi.cloneNumber > 1 {
							// 3. current speed of flow function is lower, than saved speed with less number of clones
							if ffi.currentSpeed.Packets < ffi.previousSpeed[ffi.cloneNumber-1].Packets {
								// Save current speed as speed of flow function with this number of clones before removing
								ffi.previousSpeed[ffi.cloneNumber] = ffi.currentSpeed
								ff.stopClone(ffi, scheduler)
								ffi.updatePause(ffi.cloneNumber)
							}
						}
					}
					if ff.instanceNumber > 1 {
						min0 := 0
						min1 := 1
						if ff.instance[0].currentSpeed.Packets > ff.instance[1].currentSpeed.Packets {
							min0 = 1
							min1 = 0
						}
						for q := 2; q < ff.instanceNumber; q++ {
							if ff.instance[q].currentSpeed.Packets < ff.instance[min0].currentSpeed.Packets {
								min1 = min0
								min0 = q
								continue
							}
							if ff.instance[q].currentSpeed.Packets < ff.instance[min1].currentSpeed.Packets {
								min1 = q
							}
						}
						if ff.instance[min0].currentSpeed.Packets+ff.instance[min1].currentSpeed.Packets < ff.oneCoreSpeed.Packets {
							ff.stopInstance(min0, min1, scheduler)
						}
					}
				case fastGenerate: // Only clones, no instances
					targetSpeed := (ff.Parameters.(*generateParameters)).targetSpeed
					speedPKTS := float64(ff.instance[0].currentSpeed.normalize(schedTime).Packets)
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
								if low.CheckRSSPacketCount(ff.Parameters.(*receiveParameters).port, int16(ff.instance[q].inIndex[q1])) > RSSCloneMin {
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
						if ffi.checkInputRingClonable(scheduler.maxPacketsToClone) {
							if ffi.inIndex[0] > 1 {
								ff.oneCoreSpeed = ffi.currentSpeed
								if ff.startNewInstance(constructZeroIndex(ffi.inIndex), scheduler) == nil {
									ff.instance[ff.instanceNumber-1].inIndex = constructDuplicatedIndex(ffi.inIndex)
									a = false
								}
							}
						}
					}
					if a == true {
						for q := 0; q < l; q++ {
							ffi := ff.instance[q]
							if ffi.checkInputRingClonable(scheduler.maxPacketsToClone) {
								if ffi.inIndex[0] == 1 && scheduler.anyway && ffi.checkOutputRingClonable(scheduler.maxPacketsToClone) &&
									(ffi.previousSpeed[ffi.cloneNumber+1].Packets == 0 ||
										ffi.previousSpeed[ffi.cloneNumber+1].Packets > ffi.currentSpeed.Packets) {
									// Save current speed as speed of flow function with this number of clones before adding
									ffi.previousSpeed[ffi.cloneNumber] = ffi.currentSpeed
									if ffi.startNewClone(scheduler, q) == nil {
										// Add a pause to all clones. This pause depends on the number of clones.
										ffi.updatePause(ffi.cloneNumber)
									}
									continue
								}
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
								ffi.previousSpeed[ffi.cloneNumber+1].Packets = 0
							}
						}
					}
				case fastGenerate: // Only clones, no instances
					// 3. speed is not enough
					if float64(ff.instance[0].currentSpeed.normalize(schedTime).Packets) < (ff.Parameters.(*generateParameters)).targetSpeed {
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
									ff.instance[ff.instanceNumber-1].inIndex = constructDuplicatedIndex(ff.instance[q].inIndex)
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
			out := ff.instance[q].currentSpeed.normalize(schedTime)
			if reportMbits {
				common.LogDebug(common.Debug, "Current speed of", q, "instance of", ff.name, "is", out.Packets, "PKT/S,", out.Bytes, "Mbits/s")
			} else {
				common.LogDebug(common.Debug, "Current speed of", q, "instance of", ff.name, "is", out.Packets, "PKT/S, cloneNumber:", ff.instance[q].cloneNumber)
			}
		}
	case fastGenerate:
		targetSpeed := (ff.Parameters.(*generateParameters)).targetSpeed
		out := ff.instance[0].currentSpeed.normalize(schedTime)
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
	for q := 0; q < ff.instanceNumber; q++ {
		ffi := ff.instance[q]
		ffi.currentSpeed = reportPair{}
		t := len(ffi.report) - ffi.cloneNumber
		for k := 0; k < t; k++ {
			<-ffi.report
		}
		for k := 0; k < ffi.cloneNumber; k++ {
			temp := <-ffi.report
			ffi.currentSpeed.Packets += temp.Packets
			ffi.currentSpeed.Bytes += temp.Bytes
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
			if low.CheckRSSPacketCount(ffi.ff.Parameters.(*receiveParameters).port, int16(ffi.inIndex[q+1])) > min {
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

func constructDuplicatedIndex(old []int32) []int32 {
	newIndex := make([]int32, len(old), len(old))
	oldLen := old[0]/2 + old[0]%2
	newLen := old[0] / 2
	for q := int32(0); q < newLen; q++ {
		newIndex[q+1] = old[q+1+oldLen]
	}
	newIndex[0] = newLen
	old[0] = oldLen
	return newIndex
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
