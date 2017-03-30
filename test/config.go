// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Settings controlling benchmark parameters, usually for tests with
// type TEST_TYPE_BENCHMARK.
type BenchmarkConfig struct {
	// Array of strings to pass to pktgen Lua scripting interface upon
	// startup. All commands are executed once after getting port
	// number information from pktgen.
	StartCommands []string `json:"pktgen-startup-commands"`
	// Start gathering statistics after this number of
	// nanoseconds. Zero by default, so gather all statisctics.
	MeasureAfter time.Duration `json:"measure-after"`
	// Gather statistics for this number of nanoseconds. When zero,
	// don't stop gathering statistics. Zero by default.
	MeasureFor time.Duration `json:"measure-for"`
}

// Settings controlling test distributed application parameters.
type AppConfig struct {
	// Specifies host name where docker daemon is running. Port number
	// is specified in DockerConfig structure and is the same for all
	// hosts.
	HostName string `json:"host-name"`
	// Specifies docker image to run for this test application.
	ImageName string `json:"image-name"`
	// Specifies application type. Valid values are "TESTAPP_GO" and "TESTAPP_PKTGEN"
	Type AppType `json:"app-type"`
	// Specifies an array of application command line arguments. First
	// argument is application executable.
	CommandLine []string `json:"exec-cmd"`
}

func (app *AppConfig) String() string {
	return fmt.Sprintf("%s:%s", app.HostName, app.ImageName)
}

// Settings for one test case.
type TestConfig struct {
	// Test case name identifier. It is better to be unique.
	Name string `json:"name"`
	// Test time out. For benchmark tests this is the duration for
	// which test applications are running. For scenario tests this is
	// the duration after which test is considered hanging and
	// failed. For both test types applications are forcedly stopped
	// after this time.
	TestTime time.Duration `json:"test-time"`
	// Type of the test. Valid values are "TEST_TYPE_BENCHMARK" and
	// "TEST_TYPE_SCENARIO".
	Type TestType `json:"test-type"`
	// Array of settings specific for each test application.
	Apps []AppConfig `json:"test-apps"`
	// Benchmark controlling settings. May be omitted for scenario
	// tests.
	BenchConf BenchmarkConfig `json:"benchmarking-settings"`
}

func (test *TestConfig) String() string {
	return fmt.Sprintf("%s:%s", test.Name, test.Type.String())
}

// Settings controlling communication with docker daemons.
type DockerConfig struct {
	// Timeout for one http communication request. This setting is
	// controlling all framework-application communications. If no
	// answer is received after this time, test is considered failed.
	RequestTimeout time.Duration `json:"request-timeout"`
	// Version of docker remote client protocol. Should not be greater
	// than docker daemon which runs on network hosts.
	DockerVersion string `json:"docker-client-version"`
	// Whether to use Privileged container setting. Should be "true"
	// if DPDK is used on any of network hosts.
	Privileged bool `json:"privileged"`
	// Specifies volumes to map from outside system into docker
	// container. If wrong filesystems are specified in this array,
	// DPDK doesn't work.
	Volumes []string `json:"map-volumes"`
	// Network socket port to be used to communicate with docker
	// daemon. Usually 2375.
	DockerPort int `json:"docker-port"`
	// Network socket port to be used to communicate with pktgen
	// program. Usually 22022.
	PktgenPort int `json:"pktgen-port"`
}

// Settings which describe whole test suite.
type TestsuiteConfig struct {
	// Settings which control docker daemon functionality.
	Config DockerConfig `json:"docker-config"`
	// Array of test cases.
	Tests []TestConfig `json:"tests"`
}

// readConfig function reads and parses config file
func ReadConfig(fileName string) (*TestsuiteConfig, error) {
	var config TestsuiteConfig

	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(file)

	err = decoder.Decode(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
