// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"testing"
)

func TestInit(t *testing.T) {
	if err := initDPDK(); err != nil {
                t.Logf("fail: %+v\n", err)
                t.Fail()
        }
}

func TestSeparate(t *testing.T) {
	if err := executeTest("", "", gotest, separate); err != nil {
		t.Logf("fail: %+v\n", err)
		t.Fail()
	}
}

func TestSplit(t *testing.T) {
	if err := executeTest("", "", gotest, split); err != nil {
		t.Logf("fail: %+v\n", err)
		t.Fail()
	}
}

func TestPartition(t *testing.T) {
	if err := executeTest("", "", gotest, partition); err != nil {
		t.Logf("fail: %+v\n", err)
		t.Fail()
	}
}

func TestCopy(t *testing.T) {
	if err := executeTest("", "", gotest, pcopy); err != nil {
		t.Logf("fail: %+v\n", err)
		t.Fail()
	}
}

func TestHandle(t *testing.T) {
	if err := executeTest("", "", gotest, handle); err != nil {
		t.Logf("fail: %+v\n", err)
		t.Fail()
	}
}

func TestHandleDrop(t *testing.T) {
	if err := executeTest("", "", gotest, dhandle); err != nil {
		t.Logf("fail: %+v\n", err)
		t.Fail()
	}
}
