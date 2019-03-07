// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package common

import (
	"fmt"
	"io"

	"github.com/pkg/errors"
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
