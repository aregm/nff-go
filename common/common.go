// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package common is used for combining common functions from other packages
// which aren't connected with C language part
package common

import (
	"strconv"
)

// GetDefaultCPUs returns default core list {0, 1, ..., NumCPU}
func GetDefaultCPUs(cpuNumber int) []int {
	cpus := make([]int, cpuNumber, cpuNumber)
	for i := 0; i < cpuNumber; i++ {
		cpus[i] = i
	}
	return cpus
}

// HandleCPUs parses cpu list string into array of valid core numbers.
// Removes duplicates
func HandleCPUList(s string, maxcpu int) ([]int, error) {
	nums, err := parseCPUs(s)
	nums = removeDuplicates(nums)
	nums = dropInvalidCPUs(nums, maxcpu)
	return nums, err
}

// parseCPUs parses cpu list string into array of cpu numbers
func parseCPUs(s string) ([]int, error) {
	var startRange, k int
	nums := make([]int, 0, 256)
	if s == "" {
		return nums, nil
	}
	startRange = -1
	var err error
	for i, j := 0, 0; i <= len(s); i++ {
		if i != len(s) && s[i] == '-' {
			startRange, err = strconv.Atoi(s[j:i])
			if err != nil {
				return nums, WrapWithNFError(err, "parsing of CPU list failed", ParseCPUListErr)
			}
			j = i + 1
		}

		if i == len(s) || s[i] == ',' {
			r, err := strconv.Atoi(s[j:i])
			if err != nil {
				return nums, WrapWithNFError(err, "parsing of CPU list failed", ParseCPUListErr)
			}
			if startRange != -1 {
				if startRange > r {
					return nums, WrapWithNFError(nil, "CPU range is invalid, min should not exceed max", InvalidCPURangeErr)
				}
				for k = startRange; k <= r; k++ {
					nums = append(nums, k)
				}
				startRange = -1
			} else {
				nums = append(nums, r)
			}
			if i == len(s) {
				break
			}
			j = i + 1
		}
	}
	return nums, nil
}

func removeDuplicates(array []int) []int {
	result := []int{}
	seen := map[int]bool{}
	for _, val := range array {
		if _, ok := seen[val]; !ok {
			result = append(result, val)
			seen[val] = true
		}
	}
	return result
}

// dropInvalidCPUs validates cpu list. Takes array of cpu ids and checks it is < maxcpu on machine,
// invalid are excluded. Returns list of valid cpu ids.
func dropInvalidCPUs(nums []int, maxcpu int) []int {
	i := 0
	for _, x := range nums {
		if x < maxcpu {
			nums[i] = x
			i++
		} else {
			LogWarning(Initialization, "Requested cpu", x, "exceeds maximum cores number on machine, skip it")
		}
	}
	return nums[:i]
}

// RXTXStats describes statistics for sender or receiver flow function
// node.
type RXTXStats struct {
	PacketsProcessed, PacketsDropped, BytesProcessed uint64
}
