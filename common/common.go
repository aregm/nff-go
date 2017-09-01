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

// Length of addresses.
const (
	EtherAddrLen = 6
	IPv6AddrLen  = 16
)

// Supported EtherType for L2
const (
	IPV4Number = 0x0800
	IPV6Number = 0x86dd
)

// Supported L4 types
const (
	ICMPNumber = 0x01
	IPNumber   = 0x04
	TCPNumber  = 0x06
	UDPNumber  = 0x11
)

// Supported ICMP Types
const (
	ICMP_TYPE_ECHO_REQUEST  uint8 = 8
	ICMP_TYPE_ECHO_RESPONSE uint8 = 0
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
	IPv4MinLen = 20
	IPv6Len    = 40
	ICMPLen    = 8
	TCPMinLen  = 20
	UDPLen     = 8
)

type LogType uint8

const (
	No             LogType = 1 << iota // No output even after fatal errors
	Initialization                     // Output during system initialization
	Debug                              // Output during execution one time per time period (scheduler ticks)
	Verbose                            // Output during execution as soon as something happens. Can influence performance
)

type TCPFlags uint8

const (
	TCP_FLAG_FIN = 0x01
	TCP_FLAG_SYN = 0x02
	TCP_FLAG_RST = 0x04
	TCP_FLAG_PSH = 0x08
	TCP_FLAG_ACK = 0x10
	TCP_FLAG_URG = 0x20
	TCP_FLAG_ECE = 0x40
	TCP_FLAG_CWR = 0x80
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

func LogDrop(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		log.Print("DROP: ", t)
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
