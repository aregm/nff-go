// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"encoding/json"
	"fmt"
)

//go:generate stringer -type=AppType,TestType,TestStatus types.go

// TestStatus is a status of the test.
type TestStatus int

// Constants for different test statuses.
const (
	TestCreated TestStatus = iota
	TestInitialized
	TestInvalid
	TestRunning
	TestReportedPassed
	TestReportedFailed
	TestTimedOut
	TestInterrupted
)

// UnmarshalJSON unmarshals data and checks app type validity.
func (at *TestStatus) UnmarshalJSON(data []byte) error {
	// Extract the string from data.
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("TestStatus should be a string, got %s", data)
	}

	// Use map to get int keys for string values
	got, ok := map[string]TestStatus{
		"TestCreated":        TestCreated,
		"TestInitialized":    TestInitialized,
		"TestInvalid":        TestInvalid,
		"TestRunning":        TestRunning,
		"TestReportedPassed": TestReportedPassed,
		"TestReportedFailed": TestReportedFailed,
		"TestTimedOut":       TestTimedOut,
		"TestInterrupted":    TestInterrupted,
	}[s]
	if !ok {
		return fmt.Errorf("invalid TestStatus %q", s)
	}
	*at = got
	return nil
}

// AppType is a type of application.
type AppType int

// Constants for different application types.
const (
	TestAppGo AppType = iota
	TestAppPerf
	TestAppPktgen
	TestAppApacheBenchmark
	TestAppLatency
	TestAppWrkBenchmark
)

// UnmarshalJSON unmarshals data and checks app type validity.
func (at *AppType) UnmarshalJSON(data []byte) error {
	// Extract the string from data.
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("app-type should be a string, got %s", data)
	}

	// Use map to get int keys for string values
	got, ok := map[string]AppType{
		"TestAppGo":              TestAppGo,
		"TestAppPerf":            TestAppPerf,
		"TestAppPktgen":          TestAppPktgen,
		"TestAppApacheBenchmark": TestAppApacheBenchmark,
		"TestAppLatency":         TestAppLatency,
		"TestAppWrkBenchmark":    TestAppWrkBenchmark,
	}[s]
	if !ok {
		return fmt.Errorf("invalid AppType %q", s)
	}
	*at = got
	return nil
}

// TestType is a type of the test.
type TestType int

// Constants for different test types.
const (
	TestTypeBenchmark TestType = iota
	TestTypeScenario
	TestTypeApacheBenchmark
	TestTypeLatency
	TestTypeWrkBenchmark
)

// UnmarshalJSON unmarshals data and checks test type validity.
func (at *TestType) UnmarshalJSON(data []byte) error {
	// Extract the string from data.
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("app-type should be a string, got %s", data)
	}

	// Use map to get int keys for string values
	got, ok := map[string]TestType{
		"TestTypeBenchmark":       TestTypeBenchmark,
		"TestTypeScenario":        TestTypeScenario,
		"TestTypeApacheBenchmark": TestTypeApacheBenchmark,
		"TestTypeLatency":         TestTypeLatency,
		"TestTypeWrkBenchmark":    TestTypeWrkBenchmark,
	}[s]
	if !ok {
		return fmt.Errorf("invalid TestType %q", s)
	}
	*at = got
	return nil
}

// PktgenMeasurement has measured by pktgen benchmark values.
type PktgenMeasurement struct {
	PktsTX, MbitsTX, PktsRX, MbitsRX int64
}

// CoresInfo has info about used and free cores.
type CoresInfo struct {
	CoresUsed, CoresFree int
}

// ReportCoresInfo has info about cores for final report
type ReportCoresInfo struct {
	CoresInfo
	CoreLastValue int
	CoreDecreased bool
}

// Indexes in array of Apache Benchmark stats ApacheBenchmarkStats
const (
	AbRequestsPerSecond = iota
	AbTimePerRequest
	AbTimePerRequestConcurrent
	AbTransferRate
)

// ApacheBenchmarkStats has info about running Apache Benchmark web
// client.
type ApacheBenchmarkStats struct {
	Stats [4]float64
}

// Indexes in array of latency stats LatencyStats
const (
	ReceivedSentRatio = iota
	Speed
	MedianLatency
	AverageLatency
	Stddev
)

// LatencyStats has info about finished latency perf test
type LatencyStats struct {
	Stats [5]float64
}

// Indexes in array of Wireshark Benchmark stats WrkBenchmarkStats
const (
	WrkRequestsPerSecond = iota
	WrkTransferRate
)

type WrkBenchmarkStats struct {
	Stats [2]float64
}

// TestReport has info about test status and application.
type TestReport struct {
	AppIndex  int
	AppStatus TestStatus
	msg       string
}
