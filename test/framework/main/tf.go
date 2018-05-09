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
var vl test.VariablesList = test.VariablesList{}
var tl test.TestsList

func main() {
	test.SetLogLevel(test.LogDebugLvl)
	var configFile string
	var directory string

	flag.Var(&hl, "hosts", "Comma-separated list of `host:port,host:port...host:port` pairs to override settings in config file, e.g. \"-hosts host1:2375,host2:2376\".")
	flag.Var(&vl, "var", "Variables listed in form NAME=VALUE. Variables are replaced in tests command lines in form NAME substring is replaced with VALUE. If whole paramenters becomes an empty string it is deleted entirely from command line. Multiple -var flags are allowed. Command line replacement order is not defined.")
	flag.Var(&tl, "test", "Testcase regexp to execute. Test is executed if regexp matches test name substring. Multiple -test flags are allowed. If no -test flag is specified, all testcases in config file are executed.")
	flag.StringVar(&configFile, "config", "config.json", "Name of config file to use")
	flag.StringVar(&directory, "directory", "", "Use `directory` to output log files instead of timestamp")
	flag.BoolVar(&test.NoDeleteContainersOnExit, "nodelete", false, "Do not remove containers after tests finish")
	flag.Parse()

	// Read config
	config, err := test.ReadConfig(configFile, hl, vl)
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
	status := config.RunAllTests(directory, tl)
	os.Exit(status)
}
