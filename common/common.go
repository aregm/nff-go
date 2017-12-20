// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package common is used for combining common functions from other packages
// which aren't connected with C language part
package common

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
)

// Length of addresses.
const (
	EtherAddrLen = 6
	IPv4AddrLen  = 4
	IPv6AddrLen  = 16
)

// Supported EtherType for L2
const (
	IPV4Number = 0x0800
	ARPNumber  = 0x0806
	VLANNumber = 0x8100
	IPV6Number = 0x86dd
)

// Supported L4 types
const (
	ICMPNumber   = 0x01
	IPNumber     = 0x04
	TCPNumber    = 0x06
	UDPNumber    = 0x11
	NoNextHeader = 0x3B
)

// Supported ICMP Types
const (
	ICMPTypeEchoRequest  uint8 = 8
	ICMPTypeEchoResponse uint8 = 0
)

// These constants keep length of supported headers in bytes.
//
// IPv6Len - minimum length of IPv6 header in bytes. It can be higher and it
// is not determined inside packet. Only default minimum size is used.
//
// IPv4MinLen and TCPMinLen are used only in packet generation functions.
//
// In parsing we take actual length of TCP header from DataOff field and length of
// IPv4 take from Ihl field.
const (
	EtherLen   = 14
	VLANLen    = 4
	IPv4MinLen = 20
	IPv6Len    = 40
	ICMPLen    = 8
	TCPMinLen  = 20
	UDPLen     = 8
	ARPLen     = 28
)

// LogType - type of logging, used in flow package
type LogType uint8

const (
	// No - no output even after fatal errors
	No LogType = 1 << iota
	// Initialization - output during system initialization
	Initialization
	// Debug - output during execution one time per time period (scheduler ticks)
	Debug
	// Verbose - output during execution as soon as something happens. Can influence performance
	Verbose
)

// TCPFlags contains set TCP flags.
type TCPFlags uint8

// Constants for valuues of TCP flags.
const (
	TCPFlagFin = 0x01
	TCPFlagSyn = 0x02
	TCPFlagRst = 0x04
	TCPFlagPsh = 0x08
	TCPFlagAck = 0x10
	TCPFlagUrg = 0x20
	TCPFlagEce = 0x40
	TCPFlagCwr = 0x80
)

var currentLogType = No | Initialization | Debug

// LogError internal, used in all packages
func LogError(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		log.Fatal("ERROR: ", t)
	}
	os.Exit(1)
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

// GetDefaultCPUs returns default core list {0, 1, ..., GOMAXPROCS-1}
func GetDefaultCPUs(cpuNumber uint) []uint {
	cpus := make([]uint, cpuNumber, cpuNumber)
	for i := uint(0); i < cpuNumber; i++ {
		cpus[i] = i
	}
	return cpus
}

var (
	// ErrMaxCPUExceed is error in case requested CPU exceeds maximum cores number on machine
	ErrMaxCPUExceed    = errors.New("Requested cpu exceeds maximum cores number on machine")
	ErrInvalidCPURange = errors.New("CPU range is invalid, min should not exceed max")
)

// ParseCPUs parses cpu list string into array of cpu numbers
// and truncate the list according to given coresNumber (GOMAXPROCS)
func ParseCPUs(s string, coresNumber uint) ([]uint, error) {
	var startRange, k int
	nums := make([]uint, 0, 256)
	if s == "" {
		return nums, nil
	}
	startRange = -1
	var err error
	for i, j := 0, 0; i <= len(s); i++ {
		if i != len(s) && s[i] == '-' {
			startRange, err = strconv.Atoi(s[j:i])
			if err != nil {
				return nums, err
			}
			j = i + 1
		}

		if i == len(s) || s[i] == ',' {
			r, err := strconv.Atoi(s[j:i])
			if err != nil {
				return nums, err
			}
			if startRange != -1 {
				if startRange > r {
					return nums, ErrInvalidCPURange
				}
				for k = startRange; k <= r; k++ {
					nums = append(nums, uint(k))
				}
				startRange = -1
			} else {
				nums = append(nums, uint(r))
			}
			if i == len(s) {
				break
			}
			j = i + 1
		}
	}

	nums = removeDuplicates(nums)

	numCPU := uint(runtime.NumCPU())
	for _, cpu := range nums {
		if cpu >= numCPU {
			return []uint{}, ErrMaxCPUExceed
		}
	}
	if len(nums) > int(coresNumber) {
		return nums[:coresNumber], nil
	}

	return nums, nil
}

func removeDuplicates(array []uint) []uint {
	result := []uint{}
	seen := map[uint]bool{}
	for _, val := range array {
		if _, ok := seen[val]; !ok {
			result = append(result, val)
			seen[val] = true
		}
	}
	return result
}
