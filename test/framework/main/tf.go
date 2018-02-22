// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "github.com/intel-go/nff-go/test/framework"

import (
	"flag"
	"os"
	"time"
)

var hl test.HostsList

func main() {
	test.SetLogLevel(test.LogDebugLvl)
	var configFile string
	var directory string

	flag.Var(&hl, "hosts", "Comma-separated list of `host:port,host:port...host:port` pairs to override settings in config file, e.g. \"-hosts host1:2375,host2:2376\".")
	flag.StringVar(&configFile, "config", "config.json", "Name of config file to use")
	flag.StringVar(&directory, "directory", "", "Use `directory` to output log files instead of timestamp")
	flag.BoolVar(&test.NoDeleteContainersOnExit, "nodelete", false, "Do not remove containers after tests finish")
	flag.Parse()

	// Read config
	config, err := test.ReadConfig(configFile, hl)
	if err != nil {
		test.LogPanic(err)
	}
	test.LogDebug(config)

	if directory == "" {
		directory = time.Now().Format(time.RFC3339)
	}
	err = os.Mkdir(directory, os.ModeDir|os.ModePerm)
	if err != nil {
		test.LogPanic(err)
	}

	// Start test execution
	status := config.RunAllTests(directory)
	os.Exit(status)
}
