// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package common is used for combining common functions from other packages
// which aren't connected with C language part
package common

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strconv"

	"github.com/pkg/errors"
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

// ErrorCode type for codes of errors
type ErrorCode int

// constants with error codes
const (
	_ ErrorCode = iota
	Fail
	ParseCPUListErr
	ReqTooManyPorts
	BadArgument
	UseNilFlowErr
	UseClosedFlowErr
	OpenedFlowAtTheEnd
	PortHasNoQueues
	NotAllQueuesUsed
	FailToInitPort
	ParseRuleJSONErr
	FileErr
	ParseRuleErr
	IncorrectArgInRules
	IncorrectRule
	AllocMbufErr
	PktMbufHeadRoomTooSmall
	NotEnoughCores
	CreatePortErr
	MaxCPUExceedErr
	PcapReadFail
	PcapWriteFail
	InvalidCPURangeErr
)

// NFError is error type returned by yanff functions
type NFError struct {
	Code     ErrorCode
	Message  string
	CauseErr error
}

type causer interface {
	Cause() error
}

// Error method to implement error interface
func (err NFError) Error() string {
	return fmt.Sprintf("%s (%d)", err.Message, err.Code)
}

// GetNFErrorCode returns value of cCode field if err is
// NFError or pointer to it and -1 otherwise.
func GetNFErrorCode(err error) ErrorCode {
	if nferr := GetNFError(err); nferr != nil {
		return nferr.Code
	}
	return -1
}

func checkAndGetNFErrPointer(err error) *NFError {
	if err != nil {
		if nferr, ok := err.(NFError); ok {
			return &nferr
		} else if nferr, ok := err.(*NFError); ok {
			return nferr
		}
	}
	return nil
}

// GetNFError if error is NFerror or pointer to int
// returns pointer to NFError, otherwise returns nil.
func GetNFError(err error) (nferr *NFError) {
	nferr = checkAndGetNFErrPointer(err)
	if nferr == nil {
		if cause, ok := err.(causer); ok {
			nferr = checkAndGetNFErrPointer(cause.Cause())
		}
	}
	return nferr
}

// Cause returns the underlying cause of error, if
// possible. If not, returns err itself.
func (err *NFError) Cause() error {
	if err == nil {
		return nil
	}
	if err.CauseErr != nil {
		if cause, ok := err.CauseErr.(causer); ok {
			return cause.Cause()
		}
		return err.CauseErr
	}
	return err
}

// Format makes formatted printing of errors,
// the following verbs are supported:
// %s, %v print the error. If the error has a
// Cause it will be printed recursively
// %+v - extended format. Each Frame of the error's
// StackTrace will be printed in detail if possible.
func (err *NFError) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('+') {
			if cause := err.Cause(); cause != err && cause != nil {
				fmt.Fprintf(s, "%+v\n", err.Cause())
				io.WriteString(s, err.Message)
				return
			}
		}
		fallthrough
	case 's', 'q':
		io.WriteString(s, err.Error())
	}
}

// WrapWithNFError returns an error annotating err with a stack trace
// at the point WrapWithNFError is called, and the next our NFError.
// If err is nil, Wrap returns nil.
func WrapWithNFError(err error, message string, code ErrorCode) error {
	err = &NFError{
		CauseErr: err,
		Message:  message,
		Code:     code,
	}
	return errors.WithStack(err)
}

var currentLogType = No | Initialization | Debug

// LogFatal internal, used in all packages
func LogFatal(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		log.Fatal("ERROR: ", t)
	}
	os.Exit(1)
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
				return nums, WrapWithNFError(err, "parsing of CPU list failed", ParseCPUListErr)
			}
			j = i + 1
		}

		if i == len(s) || s[i] == ',' {
			r, err := strconv.Atoi(s[j:i])
			if err != nil {
				return nums, WrapWithNFError(err, "parsing of CPU list failed", ParseCPUListErr)
			}
			if startRange != -1 {
				if startRange > r {
					return nums, WrapWithNFError(nil, "CPU range is invalid, min should not exceed max", InvalidCPURangeErr)
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
			return []uint{}, WrapWithNFError(nil, "requested cpu exceeds maximum cores number on machine", MaxCPUExceedErr)
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
