// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"
	"testing"
)

func init() {
	if err := initDPDK(); err != nil {
		log.Fatalf("fail to initialize with error: %+v\n", err)
	}
}

// TODO unfortunately this test can't be executed as go test right now due to https://github.com/intel-go/nff-go/issues/301
// If you want to test it via go test you should firstly comment FreeMempools function at flow/flow.go
// You will have multiple mempools however test will pass.
func TestMerge(t *testing.T) {
	scenarios := []pipelineScenario{getGet, segmGet, multipleSegm, singleSegm, getCopy, copyCopy, segmCopy}
	addSegmVariants := []bool{true, false}
	for _, scenario := range scenarios {
		for _, addSegm := range addSegmVariants {
			t.Logf("scenario: %d, add segment after merge: %t", scenario, addSegm)
			err := executeTest("", "", gotest, scenario, addSegm)
			resetState()
			if err != nil {
				t.Logf("fail: %v\n", err)
				t.Fail()
			}
		}
	}
}
