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

func (ira *inputReportsArray) String() string {
	return fmt.Sprint(*ira)
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
	compare(another reportProcessorResult) (bool, error)
	String() string
}

type reportProcessor interface {
	process(*test.TestsuiteReport, bool) reportProcessorResult
}

type comparisonMode struct {
	reportProcessor
}

func (cm *comparisonMode) String() string {
	if _, ok := cm.reportProcessor.(geomeanProcessorPkts); ok {
		return "geomean_recv_pkts"
	} else if _, ok := cm.reportProcessor.(geomeanProcessorMbits); ok {
		return "geomean_recv_mbits"
	} else if _, ok := cm.reportProcessor.(sbsProcessorPkts); ok {
		return "sbs_recv_pkts"
	} else if _, ok := cm.reportProcessor.(sbsProcessorMbits); ok {
		return "sbs_recv_mbits"
	}

	return "bad value"
}

func (cm *comparisonMode) Set(value string) error {
	got, ok := map[string]reportProcessor{
		"geomean_recv_pkts":  geomeanProcessorPkts{},
		"geomean_recv_mbits": geomeanProcessorMbits{},
		"sbs_recv_pkts":      sbsProcessorPkts{},
		"sbs_recv_mbits":     sbsProcessorMbits{},
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
		reportProcessor: geomeanProcessorMbits{},
	}
	flag.Usage = func() {
		fmt.Printf(`Usage: report_compare [-v] [-m mode] -i base_report [-i new_report1] ... [-i new_reportN]

Program processes report using chosen processing mode and outputs
calculated result for every report.  If more than one report is given
on the command line, first report is considered base report. In this
case other reports are compared with base report and program returns
error if any of new reports is worse than base report.

`)
		flag.PrintDefaults()
	}

	flag.Var(&reports, "i", "Specifies input JSON report file. Should be specified at least twice.")
	flag.Var(&processMode, "m", `Specifies comparison mode. Allowed modes are
        geomean_recv_pkts - calculates geomean for all tests found in report
                and compares reports by received packets geomean.
                Reports may have different tests.
        geomean_recv_mbits - calculates geomean for all tests found in report
                and compares reports by received packets geomean.
                Reports may have different tests.
        sbs_recv_pkts - compares test reports side by side by received packets.
                Reports have to have the same tests.
        sbs_recv_mbits - compares test reports side by side by received traffic
                speed. Reports have to have the same tests.
       `)
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
		result, err := values[0].compare(values[iii])
		if err != nil {
			fmt.Print(err)
			exitCode = 1
			break
		} else if result {
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

func (gpr geomeanProcessorResult) String() string {
	return fmt.Sprintf("packets: %f, megabits: %f, cores: %f",
		gpr.geomeanPkts, gpr.geomeanMbits, gpr.geomeanCores)
}

type geomeanProcessorResultPkts struct {
	geomeanProcessorResult
}

type geomeanProcessorResultMbits struct {
	geomeanProcessorResult
}

// compare by average packets received to ensure transitivity
func (gp geomeanProcessorResultPkts) compare(another reportProcessorResult) (bool, error) {
	a := another.(geomeanProcessorResultPkts)

	return gp.geomeanPkts > a.geomeanPkts, nil
}

// compare by average packets received to ensure transitivity
func (gp geomeanProcessorResultMbits) compare(another reportProcessorResult) (bool, error) {
	a := another.(geomeanProcessorResultMbits)

	return gp.geomeanMbits > a.geomeanMbits, nil
}

type geomeanProcessor struct {
	reportProcessor
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

	return geomeanProcessorResult{
		geomeanPkts:  math.Pow(geomeanPkts, 1.0/float64(len(tr.Tests))),
		geomeanMbits: math.Pow(geomeanMbits, 1.0/float64(len(tr.Tests))),
		geomeanCores: math.Pow(geomeanCores, 1.0/float64(len(tr.Tests))),
	}
}

type geomeanProcessorPkts struct {
	geomeanProcessor
}

type geomeanProcessorMbits struct {
	geomeanProcessor
}

func (gp geomeanProcessorPkts) process(tr *test.TestsuiteReport, verbose bool) reportProcessorResult {
	return geomeanProcessorResultPkts{
		geomeanProcessorResult: gp.geomeanProcessor.process(tr, verbose).(geomeanProcessorResult),
	}
}

func (gp geomeanProcessorMbits) process(tr *test.TestsuiteReport, verbose bool) reportProcessorResult {
	return geomeanProcessorResultMbits{
		geomeanProcessorResult: gp.geomeanProcessor.process(tr, verbose).(geomeanProcessorResult),
	}
}

type testResult struct {
	name        string
	pkts, mbits int64
	cores       int
}

func (tr *testResult) String() string {
	return fmt.Sprintf("%s: packets %d, megabits: %d, cores: %d",
		tr.name, tr.pkts, tr.mbits, tr.cores)
}

type sbsProcessorResult struct {
	reportProcessorResult
	suiteName string
	results   []testResult
}

const indentString = "    "
const indentLen = len(indentString)
const pktsHeader = "   pkts/s   "
const mbitsHeader = "   Mbit/s   "
const coresHeader = " cores"
const percents = "  pkts/s    Mbit/s    cores"

func (spr sbsProcessorResult) compare(another reportProcessorResult) (bool, error) {
	a := another.(sbsProcessorResult)

	if len(spr.results) != len(a.results) {
		return false, fmt.Errorf("Reports %s and %s have different number of tests.", spr.suiteName, a.suiteName)
	}

	col1Len := 0
	for iii := range spr.results {
		if spr.results[iii].name != a.results[iii].name {
			return false, fmt.Errorf("Reports %s has test named %s while report %s has test named %s. Cannot compare them.",
				spr.suiteName, spr.results[iii].name, a.suiteName, a.results[iii].name)
		}
		if col1Len < len(spr.results[iii].name) {
			col1Len = len(spr.results[iii].name)
		}
	}

	sep2Len := 1
	col2Len := len(pktsHeader) + len(mbitsHeader) + len(coresHeader) + sep2Len
	if len(spr.suiteName) > col2Len {
		sep2Len += len(spr.suiteName) - col2Len
		col2Len = len(spr.suiteName)
	}

	sep3Len := 1
	col3Len := len(pktsHeader) + len(mbitsHeader) + len(coresHeader) + sep3Len
	if len(a.suiteName) > col2Len {
		sep3Len += len(a.suiteName) - col3Len
		col3Len = len(a.suiteName)
	}

	// Print header with report names
	fmt.Printf("%*s | %*s | %*s\n",
		col1Len, "",
		col2Len, spr.suiteName,
		col3Len, a.suiteName)
	// Print header with units
	fmt.Printf("%*s | %s%*s%s%s | %s%*s%s%s | %s\n",
		col1Len, "",
		pktsHeader, sep2Len, "", mbitsHeader, coresHeader,
		pktsHeader, sep3Len, "", mbitsHeader, coresHeader,
		percents)
	// Print individual tests
	for iii := range spr.results {
		fmt.Printf("%*s | %*d%*s%*d %*d | %*d%*s%*d %*d | %+7.2f%%  %+7.2f%% %+7.2f%%\n",
			col1Len, spr.results[iii].name,
			len(pktsHeader), spr.results[iii].pkts, sep2Len, "", len(mbitsHeader), spr.results[iii].mbits, len(coresHeader)-1, spr.results[iii].cores,
			len(pktsHeader), a.results[iii].pkts, sep3Len, "", len(mbitsHeader), a.results[iii].mbits, len(coresHeader)-1, a.results[iii].cores,
			(float64(a.results[iii].pkts)-float64(spr.results[iii].pkts))/float64(spr.results[iii].pkts)*100.0,
			(float64(a.results[iii].mbits)-float64(spr.results[iii].mbits))/float64(spr.results[iii].mbits)*100.0,
			(float64(a.results[iii].cores)-float64(spr.results[iii].cores))/float64(spr.results[iii].cores)*100.0)
	}
	return false, nil
}

func (spr sbsProcessorResult) String() string {
	out := "\n"
	for iii := range spr.results {
		out = indentString + spr.results[iii].String() + "\n"
	}
	return out
}

type sbsProcessorResultPkts struct {
	sbsProcessorResult
}

type sbsProcessorResultMbits struct {
	sbsProcessorResult
}

// Return true if at least one test result is better than another result
func (spr sbsProcessorResultPkts) compare(another reportProcessorResult) (bool, error) {
	a := another.(sbsProcessorResultPkts)

	_, err := spr.sbsProcessorResult.compare(a.sbsProcessorResult)
	if err != nil {
		return false, err
	}
	for iii := range spr.results {
		if spr.results[iii].pkts > a.results[iii].pkts {
			return true, nil
		}
	}
	return false, nil
}

// Return true if at least one test result is better than another result
func (spr sbsProcessorResultMbits) compare(another reportProcessorResult) (bool, error) {
	a := another.(sbsProcessorResultMbits)

	_, err := spr.sbsProcessorResult.compare(a.sbsProcessorResult)
	if err != nil {
		return false, err
	}
	for iii := range spr.results {
		if spr.results[iii].mbits > a.results[iii].mbits {
			return true, nil
		}
	}
	return false, nil
}

type sbsProcessor struct {
	reportProcessor
}

func (sp *sbsProcessor) process(tr *test.TestsuiteReport, verbose bool) reportProcessorResult {
	out := make([]testResult, len(tr.Tests))

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
		out[iii] = testResult{
			name:  ttt.TestName,
			pkts:  pkts,
			mbits: mbits,
			cores: ttt.CoresStats.CoresUsed,
		}
	}

	return sbsProcessorResult{
		suiteName: tr.Timestamp,
		results:   out,
	}
}

type sbsProcessorPkts struct {
	sbsProcessor
}

type sbsProcessorMbits struct {
	sbsProcessor
}

func (sp sbsProcessorPkts) process(tr *test.TestsuiteReport, verbose bool) reportProcessorResult {
	return sbsProcessorResultPkts{
		sbsProcessorResult: sp.sbsProcessor.process(tr, verbose).(sbsProcessorResult),
	}
}

func (sp sbsProcessorMbits) process(tr *test.TestsuiteReport, verbose bool) reportProcessorResult {
	return sbsProcessorResultMbits{
		sbsProcessorResult: sp.sbsProcessor.process(tr, verbose).(sbsProcessorResult),
	}
}
