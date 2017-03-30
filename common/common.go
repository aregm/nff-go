// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package is used for combining common functions from other packages
// which aren't connected with C language part
package common

import (
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
