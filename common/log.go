// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package common

import (
	"fmt"
	"log"
	"os"
)

// LogType - type of logging, used in flow package
type LogType uint8

const (
	// No - no output even after fatal errors
	No LogType = 1 << iota
	// Initialization - output during system initialization
	Initialization = 2
	// Debug - output during execution one time per time period (scheduler ticks)
	Debug = 4
	// Verbose - output during execution as soon as something happens. Can influence performance
	Verbose = 8
)

var currentLogType = No | Initialization | Debug

// LogFatal internal, used in all packages
func LogFatal(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		log.Fatal("ERROR: ", t)
	}
	os.Exit(1)
}

// LogFatalf is a wrapper at LogFatal which makes formatting before logger.
func LogFatalf(logType LogType, format string, v ...interface{}) {
	LogFatal(logType, fmt.Sprintf(format, v...))
}

// LogError internal, used in all packages
func LogError(logType LogType, v ...interface{}) string {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		log.Print("ERROR: ", t)
		return t
	}
	return ""
}

// LogWarning internal, used in all packages
func LogWarning(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		log.Print("WARNING: ", t)
	}
}

// LogDebug internal, used in all packages
func LogDebug(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		log.Print("DEBUG: ", t)
	}
}

// LogInfo internal, used in all packages
func LogInfo(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		log.Print("INFO: ", t)
	}
}

// LogDrop internal, used in all packages
func LogDrop(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		log.Print("DROP: ", t)
	}
}

// LogTitle internal, used in all packages
func LogTitle(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		log.Print(v...)
	}
}

// SetLogType internal, used in flow package
func SetLogType(logType LogType) {
	log.SetFlags(0)
	currentLogType = logType
}

// GetDPDKLogLevel internal, used in flow package
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
