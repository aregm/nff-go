// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "nfv/test"

import (
	"os"
	"time"
)

func main() {
	test.SetLogLevel(test.LOG_DEBUG)
	// Read config
	configFile := "config.json"
	if len(os.Args) > 1 {
		index := 1

		if os.Args[1] == "-nodelete" {
			test.DeleteContainersOnExit = false
			index++
		}

		if len(os.Args) > index {
			configFile = os.Args[index]
		}
	}
	config, err := test.ReadConfig(configFile)
	if err != nil {
		test.LogPanic(err)
	}
	test.LogDebug(config)

	timestr := time.Now().Format(time.RFC3339)
	err = os.Mkdir(timestr, os.ModeDir|os.ModePerm)
	if err != nil {
		test.LogPanic(err)
	}

	config.RunAllTests(timestr)
}
