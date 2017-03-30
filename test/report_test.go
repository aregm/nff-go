// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test_test

import (
	"nfv/test"

	"os"
	"strconv"
	"testing"
	"time"
)

const (
	NUM_TESTS        = 10
	NUM_APPS         = 2
	NUM_PORTS        = 4
	NUM_MEASUREMENTS = 30

	PKTS  = 40000000
	MBITS = 28000
)

func makeLogDir(t *testing.T) string {
	timestr := "TEST-" + time.Now().Format(time.RFC3339Nano)
	err := os.Mkdir(timestr, os.ModeDir|os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}
	return timestr
}

func makeDockerConfig() test.DockerConfig {
	return test.DockerConfig{
		RequestTimeout: time.Duration(10 * time.Second),
		DockerVersion:  "1.24",
		Privileged:     true,
		Volumes: []string{
			"/sys/bus/pci/drivers:/sys/bus/pci/drivers",
			"/sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages",
			"/sys/devices/system/node:/sys/devices/system/node",
			"/dev:/dev",
		},
		DockerPort: 2375,
		PktgenPort: 22022,
	}
}

func testScenarios(t *testing.T, logdir string, tests []test.TestcaseReportInfo) {
	report := test.StartReport(logdir)
	if report == nil {
		t.Fatal("Could not initialize report")
	}

	for iii := range tests {
		select {
		case report.Pipe <- tests[iii]:
			t.Log("Reported test", iii)
		case err := <-report.Done:
			t.Fatal(err)
		}
	}

	report.FinishReport()
}

func testManyApps(t *testing.T, testtype test.TestType) {
	logdir := makeLogDir(t)
	dc := makeDockerConfig()
	tests := make([]test.TestcaseReportInfo, NUM_TESTS)

	for jjj := range tests {
		appConfig := make([]test.AppConfig, NUM_APPS)

		for iii := range appConfig {
			appConfig[iii] = test.AppConfig{
				HostName:  "hostname",
				ImageName: "nfvtests",
			}
			if iii == 0 && testtype == test.TEST_TYPE_BENCHMARK {
				appConfig[iii].Type = test.TESTAPP_PKTGEN
			} else {
				appConfig[iii].Type = test.TESTAPP_GO
			}
		}

		ttt := test.TestConfig{
			Name:     "test-" + strconv.Itoa(jjj),
			TestTime: time.Duration(30 * time.Second),
			Type:     testtype,
			Apps:     appConfig,
		}

		apps := make([]test.RunningApp, NUM_APPS)

		for iii := range apps {
			logpath := logdir + string(os.PathSeparator) + ttt.Name + "-" + strconv.Itoa(iii) + ".log"
			file, err := os.Create(logpath)
			defer file.Close()

			if err != nil {
				t.Fatal("Error running test application", &apps[iii], ":", err)
			}

			logger := test.NewLogger(file)
			apps[iii].InitTest(logger, iii, &ttt.Apps[iii], &dc, &ttt)
			if err != nil {
				t.Fatal("Error running test application", &apps[iii], ":", err)
			}

			apps[iii].Status = test.TEST_REPORTED_PASSED
			if appConfig[iii].Type == test.TESTAPP_PKTGEN {
				apps[iii].Benchmarks = make([][]test.Measurement, NUM_MEASUREMENTS)
				for jjj := range apps[iii].Benchmarks {
					bencdata := make([]test.Measurement, NUM_PORTS)
					for iii := range bencdata {
						bencdata[iii].Pkts_TX = PKTS + 2
						bencdata[iii].Pkts_RX = PKTS + 1
						bencdata[iii].Mbits_TX = MBITS + 2
						bencdata[iii].Mbits_RX = MBITS + 1
					}
					apps[iii].Benchmarks[jjj] = bencdata
				}
			} else if testtype == test.TEST_TYPE_BENCHMARK {
				apps[iii].CoresStats = make([]test.CoresInfo, NUM_MEASUREMENTS)

				for jjj := range apps[iii].CoresStats {
					apps[iii].CoresStats[jjj].CoresUsed = 10
					apps[iii].CoresStats[jjj].CoresFree = 6
				}
			}
		}

		tests[jjj].Status = test.TEST_REPORTED_PASSED
		tests[jjj].Apps = apps

		if testtype == test.TEST_TYPE_BENCHMARK {
			bencdata := make([]test.Measurement, NUM_PORTS)
			for iii := range bencdata {
				bencdata[iii].Pkts_TX = PKTS + 2
				bencdata[iii].Pkts_RX = PKTS + 1
				bencdata[iii].Mbits_TX = MBITS + 2
				bencdata[iii].Mbits_RX = MBITS + 1
			}
			tests[jjj].Benchdata = bencdata

			tests[jjj].CoresStats.CoresUsed = 10
			tests[jjj].CoresStats.CoresFree = 6
			tests[jjj].CoreLastValue = 5
			tests[jjj].CoreDecreased = true
		}
	}

	testScenarios(t, logdir, tests)
}

func TestBenchmarkManyApps(t *testing.T) {
	testManyApps(t, test.TEST_TYPE_BENCHMARK)
}

func TestScenarioManyApps(t *testing.T) {
	testManyApps(t, test.TEST_TYPE_SCENARIO)
}
