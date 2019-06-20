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

// If it will fail due to strange mempool behaviour feel free to reopen https://github.com/intel-go/nff-go/issues/301
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
