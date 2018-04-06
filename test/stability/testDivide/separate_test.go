// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"testing"
)

func TestSeparate(t *testing.T) {
	if err := executeTest("", "", 0, separate); err != nil {
		t.Logf("fail: %+v\n", err)
		t.Fail()
	}
}
