// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"testing"
)

// TODO unfortunately this test can't be executed as go test right now due to https://github.com/intel-go/nff-go/issues/301
// If you want to test it via go test you should firstly comment FreeMempools function at flow/flow.go
// You will have multiple mempools however test will pass.
func TestInit(t *testing.T) {
	if err := initDPDK(); err != nil {
		t.Logf("fail: %+v\n", err)
		t.Fail()
	}
}

func TestGenerate(t *testing.T) {
	launch(t, generate)
}

func TestFastGenerate(t *testing.T) {
	launch(t, fastGenerate)
}

func TestVectorFastGenerate(t *testing.T) {
	launch(t, vectorFastGenerate)
}

func TestReceiveFile(t *testing.T) {
	launch(t, receiveFile)
}

func TestSendFile(t *testing.T) {
	launch(t, sendFile)
}

func TestSendKNI(t *testing.T) {
	launch(t, sendKni)
}

func TestReceiveKNI(t *testing.T) {
	launch(t, receiveKni)
}

func launch(t *testing.T, testType uint) {
	if err := executeTest("", "", gotest, testType); err != nil {
		t.Logf("fail: %+v\n", err)
		t.Fail()
	}
}
