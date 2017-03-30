// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"encoding/json"
	"fmt"
)

//go:generate stringer -type=AppType,TestType,TestStatus types.go
type TestStatus int

const (
	TEST_CREATED TestStatus = iota
	TEST_INITIALIZED
	TEST_INVALID
	TEST_RUNNING
	TEST_REPORTED_PASSED
	TEST_REPORTED_FAILED
	TEST_TIMED_OUT
)

type AppType int

const (
	TESTAPP_GO AppType = iota
	TESTAPP_PKTGEN
)

func (at *AppType) UnmarshalJSON(data []byte) error {
	// Extract the string from data.
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("app-type should be a string, got %s", data)
	}

	// Use map to get int keys for string values
	got, ok := map[string]AppType{"TESTAPP_GO": TESTAPP_GO, "TESTAPP_PKTGEN": TESTAPP_PKTGEN}[s]
	if !ok {
		return fmt.Errorf("invalid AppType %q", s)
	}
	*at = got
	return nil
}

type TestType int

const (
	TEST_TYPE_BENCHMARK TestType = iota
	TEST_TYPE_SCENARIO
)

func (at *TestType) UnmarshalJSON(data []byte) error {
	// Extract the string from data.
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("app-type should be a string, got %s", data)
	}

	// Use map to get int keys for string values
	got, ok := map[string]TestType{"TEST_TYPE_BENCHMARK": TEST_TYPE_BENCHMARK, "TEST_TYPE_SCENARIO": TEST_TYPE_SCENARIO}[s]
	if !ok {
		return fmt.Errorf("invalid TestType %q", s)
	}
	*at = got
	return nil
}
