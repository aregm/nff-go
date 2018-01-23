// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "github.com/intel-go/yanff/test"

import (
	"os"
	"time"
)

func main() {
	test.SetLogLevel(test.LogDebugLvl)
	// Read config
	configFile := "config.json"
	var directory string
	if len(os.Args) > 1 {
		index := 1

		if os.Args[1] == "-nodelete" {
			test.DeleteContainersOnExit = false
			index++
		}

		if len(os.Args) > 2 {
			if os.Args[1] == "-directory" {
				directory = os.Args[2]
				index += 2
			}
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
	if directory == "" {
		directory = timestr
	}
	err = os.Mkdir(directory, os.ModeDir|os.ModePerm)
	if err != nil {
		test.LogPanic(err)
	}

	config.RunAllTests(directory)
}
