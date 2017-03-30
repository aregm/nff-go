// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"os"
	"strconv"
	"time"
)

func (config *TestsuiteConfig) executeOneTest(index int, logdir string, reportPipe chan TestcaseReportInfo) {
	test := config.Tests[index]

	if test.TestTime < config.Config.RequestTimeout {
		LogError("Test", test.Name, "duration", test.TestTime, "should be greater than docker http request timeout",
			config.Config.RequestTimeout)
		return
	}

	LogInfo("/--- Running test", test.Name, "---")

	apps := make([]RunningApp, len(test.Apps))

	badStart := false
	for iii := range apps {
		logpath := logdir + string(os.PathSeparator) + test.Name + "-" + strconv.Itoa(iii) + ".log"
		file, err := os.Create(logpath)
		defer file.Close()

		if err != nil {
			LogError("Error running test application", &apps[iii], ":", err)
			badStart = true
			break
		}

		logger := NewLogger(file)
		apps[iii].InitTest(logger, iii, &test.Apps[iii], &config.Config, &test)
		err = apps[iii].startTest()
		if err != nil {
			LogError("Error running test application", &apps[iii], ":", err)
			badStart = true
			break
		}
	}

	pktgenAppIndex := -1
	coresAppIndex := -1
	if badStart {
		killAllRunningAndRemoveData(apps)
	} else {
		report := make(chan TestReport)
		cancel := make(chan struct{})

		// Run all test app containers
		for iii := range apps {
			go apps[iii].testRoutine(report, cancel)
			if apps[iii].config.Type == TESTAPP_PKTGEN {
				go apps[iii].testPktgenRoutine(report, cancel)
				pktgenAppIndex = iii
			} else {
				coresAppIndex = iii
			}
		}

		ticker := time.Tick(test.TestTime)

		// Main loop waiting for goroutines to report test status or time out
	endtest:
		for {
			select {
			case r := <-report:
				apps[r.AppIndex].Logger.LogInfo(r.AppIndex, "\"", r.msg, "\"")
				if r.AppStatus == TEST_REPORTED_FAILED || r.AppStatus == TEST_REPORTED_PASSED {
					apps[r.AppIndex].Logger.LogDebug("Finished with code", r.AppStatus)

					killAllRunningAndRemoveData(apps)
					apps[r.AppIndex].Status = r.AppStatus
					if r.AppStatus == TEST_REPORTED_PASSED {
						setAppStatusOnPassed(apps)
					}
					break endtest
				}
			case <-ticker:
				LogDebug("Test", test, "timeout reached", test.TestTime)
				// Send all apps signal to stop
				close(cancel)
				killAllRunningAndRemoveData(apps)
				setAppStatusOnTimeout(test.Type, apps)
				break endtest
			}
		}
	}

	testStatus := TEST_REPORTED_PASSED
	// Try to figure out test status
	for iii := range apps {
		if apps[iii].Status != TEST_REPORTED_PASSED {
			testStatus = apps[iii].Status
			break
		}
	}

	LogInfo("\\--- Finished test", test.Name, "--- status:", testStatus)

	var b []Measurement
	if test.Type == TEST_TYPE_BENCHMARK && pktgenAppIndex >= 0 && apps[pktgenAppIndex].Benchmarks != nil {
		ports := len(apps[pktgenAppIndex].Benchmarks[0])
		b = make([]Measurement, ports)
		for _, m := range apps[pktgenAppIndex].Benchmarks {
			for p := 0; p < ports; p++ {
				b[p].Pkts_TX += m[p].Pkts_TX
				b[p].Mbits_TX += m[p].Mbits_TX
				b[p].Pkts_RX += m[p].Pkts_RX
				b[p].Mbits_RX += m[p].Mbits_RX
			}
		}

		number := int64(len(apps[pktgenAppIndex].Benchmarks))
		for p := 0; p < ports; p++ {
			b[p].Pkts_TX /= number
			b[p].Mbits_TX /= number
			b[p].Pkts_RX /= number
			b[p].Mbits_RX /= number
		}
	}

	var c CoresInfo
	var clv int = 0
	var cd bool = false
	if test.Type == TEST_TYPE_BENCHMARK && coresAppIndex >= 0 && apps[coresAppIndex].CoresStats != nil {
		for _, cs := range apps[coresAppIndex].CoresStats {
			c.CoresUsed += cs.CoresUsed
			c.CoresFree += cs.CoresFree

			if !cd && cs.CoresUsed < clv {
				cd = true
			}
			clv = cs.CoresUsed
		}

		number := len(apps[coresAppIndex].CoresStats)
		c.CoresUsed /= number
		c.CoresFree /= number
	}

	reportPipe <- TestcaseReportInfo{
		Status:        testStatus,
		Benchdata:     b,
		CoresStats:    c,
		CoreLastValue: clv,
		CoreDecreased: cd,
		Apps:          apps,
	}
}

func (config *TestsuiteConfig) RunAllTests(logdir string) {
	report := StartReport(logdir)
	if report == nil {
		return
	}

	for iii := range config.Tests {
		config.executeOneTest(iii, logdir, report.Pipe)
	}

	report.FinishReport()
}

func setAppStatusOnTimeout(testType TestType, apps []RunningApp) {
	// If it was a scenario, and some apps didn't finish, they are
	// considered as timed out, for benchmars it is normal
	var setStatus TestStatus
	if testType == TEST_TYPE_BENCHMARK {
		setStatus = TEST_REPORTED_PASSED
	} else {
		setStatus = TEST_TIMED_OUT
	}
	for iii := range apps {
		if apps[iii].Status == TEST_RUNNING {
			apps[iii].Status = setStatus
		}
	}
}

func setAppStatusOnPassed(apps []RunningApp) {
	// If it was a scenario, and some apps didn't finish, they are
	// considered as timed out, for benchmars it is normal
	var setStatus TestStatus
	setStatus = TEST_REPORTED_PASSED

	for iii := range apps {
		if apps[iii].Status == TEST_RUNNING {
			apps[iii].Status = setStatus
		}
	}
}
