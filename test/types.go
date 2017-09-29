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
)

// AppType is a type of application.
type AppType int

// Constants for different application types.
const (
	TestAppGo AppType = iota
	TestAppPktgen
)

// UnmarshalJSON unmarshals data and checks app type validity.
func (at *AppType) UnmarshalJSON(data []byte) error {
	// Extract the string from data.
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("app-type should be a string, got %s", data)
	}

	// Use map to get int keys for string values
	got, ok := map[string]AppType{"TestAppGo": TestAppGo, "TestAppPktgen": TestAppPktgen}[s]
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
)

// UnmarshalJSON unmarshals data and checks test type validity.
func (at *TestType) UnmarshalJSON(data []byte) error {
	// Extract the string from data.
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("app-type should be a string, got %s", data)
	}

	// Use map to get int keys for string values
	got, ok := map[string]TestType{"TestTypeBenchmark": TestTypeBenchmark, "TestTypeScenario": TestTypeScenario}[s]
	if !ok {
		return fmt.Errorf("invalid TestType %q", s)
	}
	*at = got
	return nil
}
