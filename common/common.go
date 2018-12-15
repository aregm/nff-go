// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package common is used for combining common functions from other packages
// which aren't connected with C language part
package common

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"strconv"

	"github.com/pkg/errors"
)

// Max array length for type conversions
const MaxLength = math.MaxInt32

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
	MPLSNumber = 0x8847
	IPV6Number = 0x86dd

	SwapIPV4Number = 0x0008
	SwapARPNumber  = 0x0608
	SwapVLANNumber = 0x0081
	SwapMPLSNumber = 0x4788
	SwapIPV6Number = 0xdd86
)

// Supported L4 types
const (
	ICMPNumber   = 0x01
	IPNumber     = 0x04
	TCPNumber    = 0x06
	UDPNumber    = 0x11
	ICMPv6Number = 0x3a
	NoNextHeader = 0x3b
)

// Supported ICMP Types
const (
	ICMPTypeEchoRequest         uint8 = 8
	ICMPTypeEchoResponse        uint8 = 0
	ICMPv6TypeEchoRequest       uint8 = 128
	ICMPv6TypeEchoResponse      uint8 = 129
	ICMPv6NeighborSolicitation  uint8 = 135
	ICMPv6NeighborAdvertisement uint8 = 136
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
	MPLSLen    = 4
	IPv4MinLen = 20
	IPv6Len    = 40
	ICMPLen    = 8
	TCPMinLen  = 20
	UDPLen     = 8
	ARPLen     = 28
	GTPMinLen  = 8
)

const (
	TCPMinDataOffset = 0x50 // minimal tcp data offset
	IPv4VersionIhl   = 0x45 // IPv4, IHL = 5 (min header len)
	IPv6VtcFlow      = 0x60 // IPv6 version
)

type IPv4Address uint32

// BytesToIPv4 converts four element address to IPv4Address representation
func BytesToIPv4(a byte, b byte, c byte, d byte) IPv4Address {
	return IPv4Address(d)<<24 | IPv4Address(c)<<16 | IPv4Address(b)<<8 | IPv4Address(a)
}

// ArrayToIPv4 converts four element array to IPv4Address representation
func ArrayToIPv4(a [IPv4AddrLen]byte) IPv4Address {
	return IPv4Address(a[3])<<24 | IPv4Address(a[2])<<16 | IPv4Address(a[1])<<8 | IPv4Address(a[0])
}

// SliceToIPv4 converts four element slice to IPv4Address representation
func SliceToIPv4(s []byte) IPv4Address {
	return IPv4Address(s[3])<<24 | IPv4Address(s[2])<<16 | IPv4Address(s[1])<<8 | IPv4Address(s[0])
}

// IPv4ToBytes converts four element address to IPv4Address representation
func IPv4ToBytes(v IPv4Address) [IPv4AddrLen]byte {
	return [IPv4AddrLen]uint8{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

func (addr IPv4Address) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24))
}

// UnmarshalJSON parses IPv4 address.
func (out *IPv4Address) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	if ip := net.ParseIP(s); ip != nil {
		ipv4 := ip.To4()
		if ipv4 == nil {
			return fmt.Errorf("Bad IPv4 address %s", s)
		}
		*out = BytesToIPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3])
		return nil
	}
	return fmt.Errorf("Failed to parse address %s", s)
}

type IPv6Address [IPv6AddrLen]uint8

func (addr IPv6Address) String() string {
	return fmt.Sprintf("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]",
		addr[0], addr[1], addr[2], addr[3],
		addr[4], addr[5], addr[6], addr[7],
		addr[8], addr[9], addr[10], addr[11],
		addr[12], addr[13], addr[14], addr[15])
}

// UnmarshalJSON parses IPv6 address.
func (out *IPv6Address) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	if ip := net.ParseIP(s); ip != nil {
		ipv6 := ip.To16()
		if ipv6 == nil {
			return fmt.Errorf("Bad IPv6 address %s", s)
		}
		copy((*out)[:], ipv6)
		return nil
	}
	return fmt.Errorf("Failed to parse address %s", s)
}

type MACAddress [EtherAddrLen]uint8

// MACToString return MAC address like string
func (mac MACAddress) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

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
	SetAffinityErr
	MultipleReceivePort
	MultipleKNIPort
	WrongPort
	FailToInitDPDK
	FailToCreateKNI
	FailToReleaseKNI
	BadSocket
)

// NFError is error type returned by nff-go functions
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

// GetDefaultCPUs returns default core list {0, 1, ..., NumCPU}
func GetDefaultCPUs(cpuNumber int) []int {
	cpus := make([]int, cpuNumber, cpuNumber)
	for i := 0; i < cpuNumber; i++ {
		cpus[i] = i
	}
	return cpus
}

// HandleCPUs parses cpu list string into array of valid core numbers.
// Removes duplicates
func HandleCPUList(s string, maxcpu int) ([]int, error) {
	nums, err := parseCPUs(s)
	nums = removeDuplicates(nums)
	nums = dropInvalidCPUs(nums, maxcpu)
	return nums, err
}

// parseCPUs parses cpu list string into array of cpu numbers
func parseCPUs(s string) ([]int, error) {
	var startRange, k int
	nums := make([]int, 0, 256)
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
					nums = append(nums, k)
				}
				startRange = -1
			} else {
				nums = append(nums, r)
			}
			if i == len(s) {
				break
			}
			j = i + 1
		}
	}
	return nums, nil
}

func removeDuplicates(array []int) []int {
	result := []int{}
	seen := map[int]bool{}
	for _, val := range array {
		if _, ok := seen[val]; !ok {
			result = append(result, val)
			seen[val] = true
		}
	}
	return result
}

// dropInvalidCPUs validates cpu list. Takes array of cpu ids and checks it is < maxcpu on machine,
// invalid are excluded. Returns list of valid cpu ids.
func dropInvalidCPUs(nums []int, maxcpu int) []int {
	i := 0
	for _, x := range nums {
		if x < maxcpu {
			nums[i] = x
			i++
		} else {
			LogWarning(Initialization, "Requested cpu", x, "exceeds maximum cores number on machine, skip it")
		}
	}
	return nums[:i]
}
