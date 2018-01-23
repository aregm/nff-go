// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package main

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("should have one argument for a directory with test results")
		os.Exit(1)
	}
	currentFile := os.Args[1] + "/index.html"

	i := 0
	s := 0
	global_off := 1.0
	global_on := 1.0
	global_cores := 1.0
	geomean := 0.0

	file, err := os.Open(currentFile)
	if err != nil {
		fmt.Println("Can't open", currentFile)
		os.Exit(1)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	for i < len(lines) {
		if strings.Contains(lines[i], "TEST_TYPE_BENCHMARK") && !strings.Contains(lines[i], "log") { // "TestTypeBenchmark"
			name := strings.Split(lines[i][8:len(lines[i])-20], "_off_") // -21 / -18 -17 ?
			if len(name[1]) == 2 {
				name[1] = "  " + name[1]
			} else if len(name[1]) == 3 {
				name[1] = " " + name[1]
			}

			normal_cores := 6
			if name[0] == "ipsec" {
				normal_cores = 4
			} else if name[0] == "nat_fixed_ports" || name[0] == "nat_nonfixed_ports" {
				// Ask Maria!!!
			}

			j := i + 1
			for strings.Contains(lines[j], "Average") == false {
				j++
			}
			t := strings.Split(lines[j], "</td><td class=\"rborder\">")[2]
			off_MGB, _ := strconv.Atoi(t[:len(t)-5]) // -6 ?
			t = strings.Split(lines[j+1], "</td>")[0]
			off_cores, _ := strconv.Atoi(t[40:])
			off_cores = off_cores - normal_cores

			k := j + 1
			for strings.Contains(lines[k], "Average") == false {
				k++
			}
			t = strings.Split(lines[k], "</td><td class=\"rborder\">")[2]
			on_MGB, _ := strconv.Atoi(t[:len(t)-5]) // -6 ?
			t = strings.Split(lines[k+1], "</td>")[0]
			on_cores, _ := strconv.Atoi(t[40:])
			on_cores = on_cores - normal_cores

			t = strings.Split(lines[k+1], "</td><td class=\"rborder\">")[1]
			decreased := (t)[:len(t)-6]

			percent := int(float64(on_MGB) / float64(on_cores) / float64(off_MGB) * float64(off_cores) * 100)
			if (s < 9 && s%3 == 0) || (s >= 9 && (s-9)%4 == 0) {
				fmt.Println("--------", name[0], name[1], "off:", off_MGB, "on:", on_MGB, on_cores, "cores,", percent, "%", decreased, "--------")
			} else {
				fmt.Println("        ", name[0], name[1], "off:", off_MGB, "on:", on_MGB, on_cores, "cores,", percent, "%", decreased)
			}
			global_off = global_off * float64(off_MGB)
			global_on = global_on * float64(on_MGB)
			global_cores = global_cores * float64(on_cores)
			geomean++
			i = k + 1
			s = s + 1
		} else {
			i++
		}
	}
	fmt.Println("Overall geomean off:", math.Pow(global_off, 1.0/geomean), "on:", math.Pow(global_on, 1.0/geomean), "cores:", math.Pow(global_cores, 1.0/geomean))
}
