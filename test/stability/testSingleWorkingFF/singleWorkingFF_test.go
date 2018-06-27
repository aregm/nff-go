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

func TestSeparate(t *testing.T) {
	launch(t, separate)
}

func TestSplit(t *testing.T) {
	launch(t, split)
}

func TestPartition(t *testing.T) {
	launch(t, partition)
}

func TestCopy(t *testing.T) {
	launch(t, pcopy)
}

func TestHandle(t *testing.T) {
	launch(t, handle)
}

func TestHandleDrop(t *testing.T) {
	launch(t, dhandle)
}

func TestVectorSeparate(t *testing.T) {
	launch(t, vseparate)
}

func TestVectorSplit(t *testing.T) {
	launch(t, vsplit)
}

func TestVectorPartition(t *testing.T) {
	launch(t, vpartition)
}

func TestVectorHandle(t *testing.T) {
	launch(t, vhandle)
}

func TestVectorHandleDrop(t *testing.T) {
	launch(t, vdhandle)
}

func launch(t *testing.T, testType uint) {
	if err := executeTest("", "", gotest, testType); err != nil {
		t.Logf("fail: %+v\n", err)
		t.Fail()
	}
}
