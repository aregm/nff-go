// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package is used for combining common functions from other packages
// which aren't connected with C language part
package common

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
)

type LogType uint8

const (
	No             LogType = 1 << iota // No output even after fatal errors
	Initialization                     // Output during system initialization
	Debug                              // Output during execution one time per time period (scheduler ticks)
	Verbose                            // Output during execution as soon as something happens. Can influence performance
)

var currentLogType LogType = No | Initialization | Debug

func LogError(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		log.Fatal("ERROR: ", t)
	}
	os.Exit(1)
}

func LogWarning(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		log.Print("WARNING: ", t)
	}
}

func LogDebug(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		log.Print("DEBUG: ", t)
	}
}

func LogTitle(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		log.Print(v...)
	}
}

func SetLogType(logType LogType) {
	log.SetFlags(0)
	currentLogType = logType
}

func GetDPDKLogLevel() string {
	switch currentLogType {
	case No:
		return "0"
	case No | Initialization:
		return "7"
	case No | Initialization | Debug:
		return "8"
	case No | Initialization | Debug | Verbose:
		return "8"
	default:
		return "8"
	}
}

// System config representatioin.
type options struct {
	CPUCoresNumber struct {
		Value  uint `json:"value"`
		Locked bool `json:"locked"`
	} `json:"cores"`
	SchedulerOff struct {
		Value  bool `json:"value"`
		Locked bool `json:"locked"`
	} `json:"no-scheduler"`
	SchedulerOffRemove struct {
		Value  bool `json:"value"`
		Locked bool `json:"locked"`
	} `json:"no-remove-clones"`
	StopDedicatedCore struct {
		Value  bool `json:"value"`
		Locked bool `json:"locked"`
	} `json:"stop-at-dedicated-core"`
	MempoolSize struct {
		Value  uint `json:"value"`
		Locked bool `json:"locked"`
	} `json:"mempool-size"`
	MbufCacheSize struct {
		Value  uint `json:"value"`
		Locked bool `json:"locked"`
	} `json:"mempool-cache"`
	SizeMultiplier struct {
		Value  uint `json:"value"`
		Locked bool `json:"locked"`
	} `json:"ring-size"`
	SchedTime struct {
		Value  uint `json:"value"`
		Locked bool `json:"locked"`
	} `json:"scale-time"`
	BurstSize struct {
		Value  uint `json:"value"`
		Locked bool `json:"locked"`
	} `json:"burst-size"`
}

var OptsSettings options

func DeclareFlags(optsJson []byte) {
	// This is YANFF flags default values. By default all values
	// are not locked and can be changes by user.
	OptsSettings.CPUCoresNumber.Value = 8
	OptsSettings.SchedulerOff.Value = false
	OptsSettings.SchedulerOffRemove.Value = false
	OptsSettings.StopDedicatedCore.Value = false
	OptsSettings.MempoolSize.Value = 8191
	OptsSettings.MbufCacheSize.Value = 250
	OptsSettings.BurstSize.Value = 32
	OptsSettings.SizeMultiplier.Value = 256
	OptsSettings.SchedTime.Value = 1500

	err := json.Unmarshal(optsJson, &OptsSettings)
	if err != nil {
		LogError(Debug, "JSON error during config line parsing: ", err)
	}

	// Create YANFF flags, if value is not locked by user.
	if !OptsSettings.CPUCoresNumber.Locked {
		flag.UintVar(&OptsSettings.CPUCoresNumber.Value, "cores", OptsSettings.CPUCoresNumber.Value, "Number of CPU cores used by system")
	}
	if !OptsSettings.SchedulerOff.Locked {
		flag.BoolVar(&OptsSettings.SchedulerOff.Value, "no-scheduler", OptsSettings.SchedulerOff.Value, "Use this for switching scheduler off")
	}
	if !OptsSettings.SchedulerOffRemove.Locked {
		flag.BoolVar(&OptsSettings.SchedulerOffRemove.Value, "no-remove-clones", OptsSettings.SchedulerOffRemove.Value, "Use this for switching off removing clones in scheduler")
	}
	if !OptsSettings.StopDedicatedCore.Locked {
		flag.BoolVar(&OptsSettings.StopDedicatedCore.Value, "stop-at-dedicated-core", OptsSettings.StopDedicatedCore.Value, "Use this for setting scheduler and stop functionality to different cores")
	}
	if !OptsSettings.MempoolSize.Locked {
		flag.UintVar(&OptsSettings.MempoolSize.Value, "mempool-size", OptsSettings.MempoolSize.Value, "Advanced option: number of mbufs in mempool per port")
	}
	if !OptsSettings.MbufCacheSize.Locked {
		flag.UintVar(&OptsSettings.MbufCacheSize.Value, "mempool-cache", OptsSettings.MbufCacheSize.Value, "Advanced option: Size of local per-core cache in mempool (in mbufs)")
	}
	if !OptsSettings.SizeMultiplier.Locked {
		flag.UintVar(&OptsSettings.SizeMultiplier.Value, "ring-size", OptsSettings.SizeMultiplier.Value, "Advanced option: number of 'burst_size' groups in all rings. This should be power of 2")
	}
	if !OptsSettings.SchedTime.Locked {
		flag.UintVar(&OptsSettings.SchedTime.Value, "scale-time", OptsSettings.SchedTime.Value, "Time between scheduler actions in miliseconds")
	}
	if !OptsSettings.BurstSize.Locked {
		flag.UintVar(&OptsSettings.BurstSize.Value, "burst-size", OptsSettings.BurstSize.Value, "Advanced option: number of mbufs per one enqueue / dequeue from ring")
	}
}

func LogOptions(opts options) {
	LogDebug(Debug, "------------***-------- YANFF settings --------***------------")
	LogDebug(Debug, "CPUCoresNumber=", opts.CPUCoresNumber)
	LogDebug(Debug, "schedulerOff=", opts.SchedulerOff)
	LogDebug(Debug, "schedulerOffRemove=", opts.SchedulerOffRemove)
	LogDebug(Debug, "stopDedicatedCore=", opts.StopDedicatedCore)
	LogDebug(Debug, "mbufNumber=", opts.MempoolSize)
	LogDebug(Debug, "mbufCacheSize=", opts.MbufCacheSize)
	LogDebug(Debug, "sizeMultiplier=", opts.SizeMultiplier)
	LogDebug(Debug, "schedTime=", opts.SchedTime)
	LogDebug(Debug, "burstSize=", opts.BurstSize)
}
