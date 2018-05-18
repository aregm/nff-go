// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "github.com/intel-go/nff-go/test/framework"

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
)

type inputReportsArray []*test.TestsuiteReport

func (na *inputReportsArray) String() string {
	return fmt.Sprint(*na)
}

func (ira *inputReportsArray) Set(value string) error {
	file, err := os.Open(value)
	if err != nil {
		return err
	}
	defer file.Close()

	report := test.TestsuiteReport{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&report)
	if err != nil {
		return err
	}
	*ira = append(*ira, &report)
	return nil
}

type reportProcessorResult interface {
	// compare returns true if this report is better than another report
	compare(another reportProcessorResult) bool
	String() string
}

type reportProcessor interface {
	process(*test.TestsuiteReport, bool) reportProcessorResult
}

type comparisonMode struct {
	reportProcessor
}

func (cm *comparisonMode) String() string {
	if _, ok := cm.reportProcessor.(geomeanProcessor); ok {
		return "perf_geomean_received"
	}

	return "bad value"
}

func (cm *comparisonMode) Set(value string) error {
	got, ok := map[string]reportProcessor{
		"perf_geomean_received": geomeanProcessor{},
	}[value]

	if !ok {
		return fmt.Errorf("invalid comparison mode %q", value)
	}
	*cm = comparisonMode{
		reportProcessor: got,
	}
	return nil
}

func main() {
	reports := inputReportsArray{}
	processMode := comparisonMode{
		reportProcessor: geomeanProcessor{},
	}
	flag.Usage = func() {
		fmt.Printf(`Usage: report_compare [-v] [-m mode] -i base_report [-i new_report1] ... [-i new_reportN]

Program processes report using chosen processing mode and outputs calculated result for every report.
If more than one report is given on the command line, first report is considered base report. In this case
other reports are compared with base report and program returns error if any of new reports is worse than
base report.

`)
		flag.PrintDefaults()
	}

	flag.Var(&reports, "i", "Specifies input JSON report file. Should be specified at least twice.")
	flag.Var(&processMode, "m", "Specifies comparison mode. Allowed modes are \"perf_geomean\" which calculates geomean for all tests found in report. Default is \"perf_geomean_received\".")
	verbose := flag.Bool("v", false, "Verbose mode")
	flag.Parse()

	if len(reports) < 1 {
		fmt.Printf("You should specify at least one report to process.\n")
		os.Exit(1)
	}

	values := make([]reportProcessorResult, len(reports))
	for iii := range reports {
		values[iii] = processMode.process(reports[iii], *verbose)
		fmt.Printf("Test report from %s: %s\n", reports[iii].Timestamp, values[iii].String())
	}

	fmt.Printf("\n")
	exitCode := 0
	for iii := 1; iii < len(reports); iii++ {
		if values[0].compare(values[iii]) {
			fmt.Printf("New report %s is worse than base report %s\n",
				reports[iii].Timestamp, reports[0].Timestamp)
			exitCode = 1
		}
	}
	os.Exit(exitCode)
}

type geomeanProcessorResult struct {
	reportProcessorResult
	geomeanPkts, geomeanMbits, geomeanCores float64
}

// compare by average packets received to ensure transitivity
func (gp geomeanProcessorResult) compare(another reportProcessorResult) bool {
	a := another.(*geomeanProcessorResult)

	return gp.geomeanPkts > a.geomeanPkts
}

func (gpr geomeanProcessorResult) String() string {
	return fmt.Sprintf("packets: %f, megabits: %f, cores: %f",
		gpr.geomeanPkts, gpr.geomeanMbits, gpr.geomeanCores)
}

type geomeanProcessor struct {
}

func (gp geomeanProcessor) process(tr *test.TestsuiteReport, verbose bool) reportProcessorResult {
	if verbose {
		fmt.Printf("Parsing report %s\n", tr.Timestamp)
	}
	geomeanPkts := 1.0
	geomeanMbits := 1.0
	geomeanCores := 1.0
	for iii := range tr.Tests {
		ttt := tr.Tests[iii]
		pgbd := ttt.PktgenBenchdata
		pkts := int64(0)
		mbits := int64(0)
		for port := range pgbd {
			pkts += pgbd[port].PktsRX
			mbits += pgbd[port].MbitsRX
		}
		if verbose {
			fmt.Printf("Test %s: pkts: %d, mbits: %d, cores: %d\n", ttt.TestName, pkts, mbits, ttt.CoresStats.CoresUsed)
		}
		geomeanPkts *= float64(pkts)
		geomeanMbits *= float64(mbits)
		geomeanCores *= float64(ttt.CoresStats.CoresUsed)
	}

	return &geomeanProcessorResult{
		geomeanPkts:  math.Pow(geomeanPkts, 1.0/float64(len(tr.Tests))),
		geomeanMbits: math.Pow(geomeanMbits, 1.0/float64(len(tr.Tests))),
		geomeanCores: math.Pow(geomeanCores, 1.0/float64(len(tr.Tests))),
	}
}
