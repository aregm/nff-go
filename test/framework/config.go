// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// BenchmarkConfig struct has settings controlling benchmark
// parameters, usually for tests with type TestTypeBenchmark.
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

// AppConfig struct has settings controlling test
// distributed application parameters.
type AppConfig struct {
	// Specifies docker image to run for this test application.
	ImageName string `json:"image-name"`
	// Specifies application type. Valid values are "TestAppGo" and "TestAppPktgen"
	Type AppType `json:"app-type"`
	// Specifies an array of application command line arguments. First
	// argument is application executable.
	CommandLine []string `json:"exec-cmd"`
	// Host:port pair after initial config processing. This is the
	// effectively used address of docker server.
	hp hostPort
}

func (app *AppConfig) String() string {
	return fmt.Sprintf("%s:%d:%s", app.hp.host, app.hp.port, app.ImageName)
}

// TestConfig struct has settings for one test case.
type TestConfig struct {
	// Test case name identifier. It is better to be unique.
	Name string `json:"name"`
	// Test time out. For benchmark tests this is the duration for
	// which test applications are running. For scenario tests this is
	// the duration after which test is considered hanging and
	// failed. For both test types applications are forcedly stopped
	// after this time.
	TestTime time.Duration `json:"test-time"`
	// Type of the test. Valid values are "TestTypeBenchmark" and
	// "TestTypeScenario".
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

// DockerConfig struct has settings controlling
// communication with docker daemons.
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
	// Network socket port to be used to communicate with pktgen
	// program. Usually 22022.
	PktgenPort int `json:"pktgen-port"`
}

// TestsuiteConfig struct has settings which describe
// whole test suite.
type TestsuiteConfig struct {
	// Settings which control docker daemon functionality.
	Config DockerConfig `json:"docker-config"`
	// A set of variables for tests command lines
	Variables map[string]string
	// Array of test cases.
	Tests []TestConfig `json:"tests"`
}

// ReadConfig function reads and parses config file.
func ReadConfig(fileName string, hl HostsList, vl VariablesList) (*TestsuiteConfig, error) {
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

	// Correct hostnames in test application configurations
	for iii := range config.Tests {
		for jjj := range config.Tests[iii].Apps {
			if jjj < len(hl) {
				config.Tests[iii].Apps[jjj].hp = hl[jjj]
			} else {
				LogPanic("Host number ", jjj, " not defined on command line for test \"",
					config.Tests[iii].Name,
					"\"\nIt is necessary to specify hosts for all test applications in -hosts switch.\n")
			}
		}
	}

	// Merge variables from command line into default variable values
	// from JSON configuration
	for kkk, vvv := range vl {
		config.Variables[kkk] = vvv
	}

	// Replace variables in test command lines
	for ttt := range config.Tests {
		for aaa := range config.Tests[ttt].Apps {
			app := &config.Tests[ttt].Apps[aaa]
			cmd := app.CommandLine

			for kkk, vvv := range config.Variables {
				for ccc := 0; ccc < len(cmd); {
					newparam := strings.Replace(cmd[ccc], kkk, vvv, -1)
					if newparam == "" {
						cmd = append(cmd[:ccc], cmd[ccc+1:]...)
					} else {
						cmd[ccc] = newparam
						ccc++
					}
				}
			}
			app.CommandLine = cmd
		}
	}

	return &config, nil
}

type hostPort struct {
	host string
	port int
}

// HostsList is a slice of host:port pairs that are used to replace
// values read from JSON config file.
type HostsList []hostPort

func (hl *HostsList) String() string {
	return fmt.Sprint(*hl)
}

func (hl *HostsList) Set(value string) error {
	list := strings.Split(value, ",")
	if len(list) == 0 {
		return errors.New("Bad format of hosts list")
	}
	for _, e := range list {
		host, portStr, err := net.SplitHostPort(e)
		if err != nil {
			return err
		}
		port, err := strconv.ParseInt(portStr, 10, 32)
		if err != nil {
			return err
		}

		*hl = append(*hl, hostPort{
			host: host,
			port: int(port),
		})
	}
	return nil
}

// Variable is a string in a form of NAME=VALUE pair which is replaced
// inside of tests command lines.
type VariablesList map[string]string

func (vl *VariablesList) String() string {
	return fmt.Sprint(*vl)
}

func (vl *VariablesList) Set(value string) error {
	parts := strings.SplitAfterN(value, "=", 2)
	if len(parts) != 2 {
		return errors.New("Bad variable format: " + value)
	}

	(*vl)[strings.TrimRight(parts[0], "=")] = parts[1]
	return nil
}

type TestsList []*regexp.Regexp

func (tl *TestsList) String() string {
	return fmt.Sprint(*tl)
}

func (tl *TestsList) Set(value string) error {
	r, err := regexp.Compile(value)
	if err != nil {
		return err
	}
	*tl = append(*tl, r)
	return nil
}
