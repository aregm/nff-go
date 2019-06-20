// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"
	"testing"
)

func init() {
	if err := initTest(); err != nil {
		log.Fatalf("fail to initialize with error: %+v\n", err)
	}
}

// If it will fail due to strange mempool behaviour feel free to reopen https://github.com/intel-go/nff-go/issues/301
func TestChecksum(t *testing.T) {
	variants := []struct{ useUDP, useTCP, useICMP bool }{
		{false, false, false},
		{true, false, false},
		{false, true, false},
		{false, false, true},
		{true, true, false}}
	for _, useIPv4 := range []bool{true, false} {
		for _, useIPv6 := range []bool{true, false} {
			for _, useVLAN := range []bool{true, false} {
				for _, v := range variants {
					err := executeTest(gotest, useIPv4, useIPv6, v.useUDP, v.useTCP, v.useICMP, useVLAN)
					resetState()
					if err != nil {
						t.Logf("useIPv4=%t, useIPv6=%t, useUDP=%t, useTCP=%t, useICMP=%t, useVLAN=%t configuration failed with: %+v\n", useIPv4, useIPv6, v.useUDP, v.useTCP, v.useICMP, useVLAN, err)
						t.Fail()
					}
				}
			}
		}
	}
}
