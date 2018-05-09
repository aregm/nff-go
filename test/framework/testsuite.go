// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"os"
	"os/signal"
	"strconv"
	"time"
)

func (config *TestsuiteConfig) executeOneTest(test *TestConfig, logdir string,
	interrupt chan os.Signal) *TestcaseReportInfo {
	if test.TestTime < config.Config.RequestTimeout {
		LogError("Test", test.Name, "duration", test.TestTime, "should be greater than docker http request timeout",
			config.Config.RequestTimeout)
		return &TestcaseReportInfo{
			Status: TestInvalid,
		}
	}

	LogInfo("/--- Running test", test.Name, "---")
	LogInfo("Apps: ", test.Apps)

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
		apps[iii].InitTest(logger, iii, &test.Apps[iii], &config.Config, test)
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
			if apps[iii].config.Type == TestAppPktgen {
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
				apps[r.AppIndex].Logger.LogInfo(r.AppIndex, r.msg)
				if r.AppStatus == TestReportedFailed || r.AppStatus == TestReportedPassed {
					apps[r.AppIndex].Logger.LogDebug("Finished with code", r.AppStatus)

					killAllRunningAndRemoveData(apps)
					apps[r.AppIndex].Status = r.AppStatus
					if r.AppStatus == TestReportedPassed {
						setRunningAppsStatusTo(TestReportedPassed, apps)
					}
					break endtest
				}
			case sig := <-interrupt:
				// Interrupt signal from keyboard
				LogDebug("Received signal", sig)
				LogDebug("Test", test, "is interrupted", test.TestTime)
				close(cancel)
				killAllRunningAndRemoveData(apps)
				setRunningAppsStatusTo(TestInterrupted, apps)
				break endtest
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

	testStatus := TestReportedPassed
	// Try to figure out test status
	for iii := range apps {
		if apps[iii].Status != TestReportedPassed {
			testStatus = apps[iii].Status
			break
		}
	}

	LogInfo("\\--- Finished test", test.Name, "--- status:", testStatus)

	var b []Measurement
	if test.Type == TestTypeBenchmark && pktgenAppIndex >= 0 && apps[pktgenAppIndex].Benchmarks != nil {
		ports := len(apps[pktgenAppIndex].Benchmarks[0])
		b = make([]Measurement, ports)
		for _, m := range apps[pktgenAppIndex].Benchmarks {
			for p := 0; p < ports; p++ {
				b[p].PktsTX += m[p].PktsTX
				b[p].MbitsTX += m[p].MbitsTX
				b[p].PktsRX += m[p].PktsRX
				b[p].MbitsRX += m[p].MbitsRX
			}
		}

		number := int64(len(apps[pktgenAppIndex].Benchmarks))
		for p := 0; p < ports; p++ {
			b[p].PktsTX /= number
			b[p].MbitsTX /= number
			b[p].PktsRX /= number
			b[p].MbitsRX /= number
		}
	}

	var c CoresInfo
	var clv int
	var cd = false
	if test.Type == TestTypeBenchmark && coresAppIndex >= 0 && apps[coresAppIndex].CoresStats != nil {
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

	return &TestcaseReportInfo{
		Status:        testStatus,
		Benchdata:     b,
		CoresStats:    c,
		CoreLastValue: clv,
		CoreDecreased: cd,
		Apps:          apps,
	}
}

func isTestInList(test *TestConfig, tl TestsList) bool {
	if len(tl) == 0 {
		return true
	}

	for iii := range tl {
		if tl[iii].MatchString(test.Name) {
			return true
		}
	}
	return false
}

// RunAllTests launches all tests.
func (config *TestsuiteConfig) RunAllTests(logdir string, tl TestsList) int {
	report := StartReport(logdir)
	if report == nil {
		return 255
	}

	// Set up reaction to SIGINT (Ctrl-C)
	sichan := make(chan os.Signal, 1)
	signal.Notify(sichan, os.Interrupt)

	var totalTests, passedTests, failedTests []string
	for iii := range config.Tests {
		test := &config.Tests[iii]

		if isTestInList(test, tl) {
			tr := config.executeOneTest(test, logdir, sichan)
			report.Pipe <- *tr

			totalTests = append(totalTests, test.Name)
			if tr.Status == TestReportedPassed {
				passedTests = append(passedTests, test.Name)
			} else {
				failedTests = append(failedTests, test.Name)
			}

			if tr.Status == TestInterrupted {
				break
			}
		}
	}

	report.FinishReport()

	LogInfo("EXECUTED TEST NAMES:", totalTests)
	LogInfo("PASSED TEST NAMES:", passedTests)
	LogInfo("FAILED TEST NAMES:", failedTests)
	LogInfo("TESTS EXECUTED:", len(totalTests))
	LogInfo("PASSED:", len(passedTests))
	LogInfo("FAILED:", len(failedTests))

	if len(failedTests) > 0 {
		return 100 + len(failedTests)
	} else {
		return 0
	}
}

func setAppStatusOnTimeout(testType TestType, apps []RunningApp) {
	// If it was a scenario, and some apps didn't finish, they are
	// considered as timed out, for benchmarks it is normal
	var setStatus TestStatus
	if testType == TestTypeBenchmark {
		setStatus = TestReportedPassed
	} else {
		setStatus = TestTimedOut
	}

	setRunningAppsStatusTo(setStatus, apps)
}

func setRunningAppsStatusTo(setStatus TestStatus, apps []RunningApp) {
	// If it was a scenario, and some apps didn't finish, they are
	// considered as timed out. In some cases it means that test
	// passed, in some cases it means an error.
	for iii := range apps {
		if apps[iii].Status == TestRunning {
			apps[iii].Status = setStatus
		}
	}
}
