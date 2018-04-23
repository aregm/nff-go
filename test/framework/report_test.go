// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"os"
	"strconv"
	"strings"
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
	timestr := "TEST-" + t.Name() + "-" +
		strings.Replace(time.Now().Format(time.RFC3339Nano), ":", "\ua789", -1)
	err := os.Mkdir(timestr, os.ModeDir|os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}
	return timestr
}

func makeDockerConfig() DockerConfig {
	return DockerConfig{
		RequestTimeout: time.Duration(10 * time.Second),
		DockerVersion:  "1.24",
		Privileged:     true,
		Volumes: []string{
			"/sys/bus/pci/drivers:/sys/bus/pci/drivers",
			"/sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages",
			"/sys/devices/system/node:/sys/devices/system/node",
			"/dev:/dev",
		},
		PktgenPort: 22022,
	}
}

func testScenarios(t *testing.T, logdir string, tests []TestcaseReportInfo) {
	report := StartReport(logdir)
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

func testManyApps(t *testing.T, testtype TestType) {
	logdir := makeLogDir(t)
	dc := makeDockerConfig()
	tests := make([]TestcaseReportInfo, NUM_TESTS)

	for jjj := range tests {
		appConfig := make([]AppConfig, NUM_APPS)

		for iii := range appConfig {
			appConfig[iii] = AppConfig{
				hp: hostPort{
					host: "hostname",
					port: 1234,
				},
				ImageName:   "nff-go-tests",
				CommandLine: []string{"testapp", strconv.Itoa(iii)},
			}
			if iii == 0 && testtype == TestTypeBenchmark {
				appConfig[iii].Type = TestAppPktgen
			} else if iii == 0 && testtype == TestTypeApacheBenchmark {
				appConfig[iii].Type = TestAppApacheBenchmark
			} else if iii == 0 && testtype == TestTypeLatency {
				appConfig[iii].Type = TestAppLatency
			} else {
				appConfig[iii].Type = TestAppGo
			}
		}

		ttt := TestConfig{
			Name:     "test-" + strconv.Itoa(jjj),
			TestTime: time.Duration(30 * time.Second),
			Type:     testtype,
			Apps:     appConfig,
		}

		apps := make([]RunningApp, NUM_APPS)

		for iii := range apps {
			logpath := logdir + string(os.PathSeparator) + ttt.Name + "-" + strconv.Itoa(iii) + ".log"
			file, err := os.Create(logpath)
			defer file.Close()

			if err != nil {
				t.Fatal("Error running test application", &apps[iii], ":", err)
			}

			logger := NewLogger(file)
			apps[iii].InitTest(logger, iii, &ttt.Apps[iii], &dc, &ttt)
			if err != nil {
				t.Fatal("Error running test application", &apps[iii], ":", err)
			}

			apps[iii].Status = TestReportedPassed
			if appConfig[iii].Type == TestAppPktgen {
				apps[iii].PktgenBenchdata = make([][]PktgenMeasurement, NUM_MEASUREMENTS)
				for jjj := range apps[iii].PktgenBenchdata {
					bencdata := make([]PktgenMeasurement, NUM_PORTS)
					for iii := range bencdata {
						bencdata[iii].PktsTX = PKTS + 2
						bencdata[iii].PktsRX = PKTS + 1
						bencdata[iii].MbitsTX = MBITS + 2
						bencdata[iii].MbitsRX = MBITS + 1
					}
					apps[iii].PktgenBenchdata[jjj] = bencdata
				}
			} else if appConfig[iii].Type == TestAppApacheBenchmark {
				apps[iii].abs = &ApacheBenchmarkStats{
					Stats: [4]float32{111.111, 222.222, 333.333, 444.444},
				}
			} else if appConfig[iii].Type == TestAppLatency {
				apps[iii].lats = &LatencyStats{
					Stats: [5]float32{111.111, 1000000, 222.222, 333.333, 444.444},
				}
			} else { // appConfig[iii].Type == TestAppGo
				apps[iii].CoresStats = make([]CoresInfo, NUM_MEASUREMENTS)

				for jjj := range apps[iii].CoresStats {
					apps[iii].CoresStats[jjj].CoresUsed = 10
					apps[iii].CoresStats[jjj].CoresFree = 6
				}
			}
		}

		tests[jjj].Status = TestReportedPassed
		tests[jjj].Apps = apps

		if testtype == TestTypeBenchmark {
			bencdata := make([]PktgenMeasurement, NUM_PORTS)
			for iii := range bencdata {
				bencdata[iii].PktsTX = PKTS + 2
				bencdata[iii].PktsRX = PKTS + 1
				bencdata[iii].MbitsTX = MBITS + 2
				bencdata[iii].MbitsRX = MBITS + 1
			}
			tests[jjj].PktgenBenchdata = bencdata

			tests[jjj].CoresStats = &ReportCoresInfo{
				CoresInfo: CoresInfo{
					CoresUsed: 10,
					CoresFree: 6,
				},
				CoreLastValue: 5,
				CoreDecreased: true,
			}
		} else if testtype == TestTypeApacheBenchmark {
			for iii := range apps {
				if apps[iii].config.Type == TestAppApacheBenchmark {
					tests[jjj].ABStats = apps[iii].abs
					break
				}
			}
		} else if testtype == TestTypeLatency {
			for iii := range apps {
				if apps[iii].config.Type == TestAppLatency {
					tests[jjj].LatStats = apps[iii].lats
					break
				}
			}
		}
	}

	testScenarios(t, logdir, tests)
}

func TestBenchmarkManyApps(t *testing.T) {
	testManyApps(t, TestTypeBenchmark)
}

func TestScenarioManyApps(t *testing.T) {
	testManyApps(t, TestTypeScenario)
}

func TestApacheBenchmarkManyApps(t *testing.T) {
	testManyApps(t, TestTypeApacheBenchmark)
}

func TestLatencyManyApps(t *testing.T) {
	testManyApps(t, TestTypeLatency)
}
