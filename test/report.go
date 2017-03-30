// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"fmt"
	"html/template"
	"os"
	"strconv"
	"time"
)

type TestcaseReportInfo struct {
	Status        TestStatus
	Benchdata     []Measurement
	CoresStats    CoresInfo
	CoreLastValue int
	CoreDecreased bool
	Apps          []RunningApp
}

type Report struct {
	output *os.File
	t      *template.Template
	Done   chan error
	Pipe   chan TestcaseReportInfo
}

const (
	reportHeader = `{{define "header"}}<!DOCTYPE html><html>
    <head>
        <meta charset="UTF-8">
        <style>
            table {
                border: 3pt solid black;
                border-collapse: collapse;
                text-align: left;
            }
            table.bench {
                border: 3pt solid black;
                border-collapse: collapse;
                text-align: right;
            }
            th {
                text-align:center;
            }
            th.thinrborder {
                border-right: 1pt solid grey;
                border-bottom: 1pt solid grey;
            }
            th.rbborder {
                border-right: 3pt solid black;
                border-bottom: 1pt solid grey;
            }
            tr.test {
                border-top: 3pt solid black;
            }
            td.rborder {
                border-right: 3pt solid black;
            }
            td.thinrborder {
                border-right: 1pt solid grey;
            }
        </style>
        <script>
            function toggleVisibility(buttonID, idArray) {
                for(i = 0; i < idArray.length; i++) {
                    element = document.getElementById(idArray[i])
                    if (element.style.display=='none') {
                        element.style.display='table-row'
                    }
                    else {
                        element.style.display='none'
                    }
                }
                button = document.getElementById(buttonID);
                if (button.value == "Show details") {
                    button.value = "Hide details";
                } else {
                    button.value = "Show details";
                }
            }
        </script>
        <title>Test report from {{.}}</title>
    </head>
    <body>
        <h1>Test report from {{.}}</h1>
    <table style="width:100%">{{end}}`

	statusTemplate = `{{define "statusLine"}}<font color="{{if eq . %d}}green{{else}}red{{end}}">{{.}}</font>{{end}}`

	reportTemplate = `{{range $testindex, $testelement := .}}<tr class="test">
    <td>
        {{with $buttonid := genbuttonid $testindex}}<input onclick="toggleVisibility('{{$buttonid}}', [{{range $appindex, $appelement := $testelement.Apps}}'{{genappid $testindex $appindex}}', {{end}}])" type="button" value="Show details" id="{{$buttonid}}"></input>{{end}}
        {{testid .}}
    </td><td>
        {{block "statusLine" .Status}}{{end}}{{if .Benchdata}}{{with .Benchdata}}
        <table class="bench">
            <tr>
                <th class="rbborder">Port</th>
                {{range $index, $element := .}}<th colspan="4" class="rbborder">{{$index}}</th>{{end}}
                <th colspan = "4" class="rbborder">Cores</th>
            </tr><tr>
                <th class="rbborder"></th>
                {{range .}}<th class="thinrborder">Pkts TX</th><th class="thinrborder">Mbit TX</th><th class="thinrborder">Pkts RX</th><th class="rbborder">Mbit RX</th>{{end}}
                <th class="thinrborder">Used</th><th class="thinrborder">Free</th><th class="thinrborder">Last</th><th class="rbborder">Decreased</th>
            </tr><tr>
                <td class="rborder">Average</td>{{range .}}<td>{{.Pkts_TX}}</td><td>{{.Mbits_TX}}</td><td>{{.Pkts_RX}}</td><td class="rborder">{{.Mbits_RX}}</td>{{end}}{{end}}{{/* end with .Benchdata */}}
                <td class="thinrborder">{{.CoresStats.CoresUsed}}</td><td class="thinrborder">{{.CoresStats.CoresFree}}</td><td class="thinrborder">{{.CoreLastValue}}</td><td class="rborder">{{if .CoreDecreased}}YES{{else}}NO{{end}}</td>
            </tr>
        </table>{{end}}{{/* end if .Benchdata */}}
    </td>
</tr>{{range $appindex, $appelement := .Apps}}<tr style='display:none' id='{{genappid $testindex $appindex}}'>
    <td>
        <a {{getloggerfile .}}>{{.String}}</a>
    </td>
    <td>
        {{block "statusLine" .Status}}{{end}}{{with .Benchmarks}}<table class="bench">{{range $index, $element := .}}{{if eq $index 0}}<tr>
                <th class="rbborder">Port</th>
                {{range $port, $e := $element}}<th colspan="4" class="rbborder">{{$port}}</th>{{end}}
            </tr><tr>
                <th class="rbborder"></th>
                {{range $element}}<th class="thinrborder">Pkts TX</th><th class="thinrborder">Mbit TX</th><th class="thinrborder">Pkts RX</th><th class="rbborder">Mbit RX</th>{{end}}
            </tr>{{end}}{{/* end of table header */}}<tr>
                <td class="rborder">{{$index}}</td>{{range $element}}<td class="thinrborder">{{.Pkts_TX}}</td><td class="thinrborder">{{.Mbits_TX}}</td><td class="thinrborder">{{.Pkts_RX}}</td><td class="rborder">{{.Mbits_RX}}</td>{{end}}
            </tr>
        {{end}}</table>{{end}}{{/* end with .Benchmarks */}}{{with .CoresStats}}<table class="bench">
            <tr>
                <th class="rbborder"></th>
                <th colspan="2" class="rbborder">Cores</th>
            </tr>
            <tr>
                <th class="rbborder">Measurement</th>
                <th class="thinrborder">Used</th><th class="thinrborder">Free</th>
            </tr>{{range $index, $element := .}}<tr>
                <td class="rborder">{{$index}}</td>
                <td class="thinrborder">{{.CoresUsed}}</td><td class="thinrborder">{{.CoresFree}}</td>
            </tr>{{end}}
        </table>{{end}}{{/* end with .Benchmarks */}}
    </td>
</tr>{{end}}{{end}}`

	reportFooter = `{{define "footer"}}</table></body></html>{{end}}`
)

var (
	funcs = template.FuncMap{
		"testid":      func(tr TestcaseReportInfo) string { return tr.Apps[0].test.String() },
		"genbuttonid": func(index int) string { return "test-" + strconv.Itoa(index) },
		"genappid": func(testindex, appindex int) string {
			return "app-" + strconv.Itoa(testindex) + "-" + strconv.Itoa(appindex)
		},
		"getloggerfile": func(app RunningApp) template.HTMLAttr {
			if app.Logger != nil {
				return template.HTMLAttr("href=\"" + app.Logger.String() + "\"")
			} else {
				return ""
			}
		},
	}
)

func StartReport(logdir string) *Report {
	var r Report
	var err error

	// Parse report templates
	r.t = template.New("report")
	r.t, err = r.t.Parse(reportHeader)
	if err != nil {
		LogError("Report header template parse error:", err)
		return nil
	}
	r.t, err = r.t.Parse(fmt.Sprintf(statusTemplate, TEST_REPORTED_PASSED))
	if err != nil {
		LogError("Report status template parse error:", err)
		return nil
	}
	r.t, err = r.t.Funcs(funcs).Parse(reportTemplate)
	if err != nil {
		LogError("Report body template parse error:", err)
		return nil
	}
	r.t, err = r.t.Parse(reportFooter)
	if err != nil {
		LogError("Report footer template parse error:", err)
		return nil
	}

	// Open report file
	name := logdir + string(os.PathSeparator) + "index.html"
	r.output, err = os.Create(name)
	if err != nil {
		LogError("Failed to create report file", name, err)
		return nil
	}

	timestr := time.Now().Format(time.RFC3339)
	err = r.t.ExecuteTemplate(r.output, "header", timestr)
	if err != nil {
		LogError("Failed to write to report file", name, err)
		r.output.Close()
		return nil
	}

	// Create a pipe for communication with report writing go-routine
	r.Pipe = make(chan TestcaseReportInfo)
	r.Done = make(chan error, 1)

	// Start report writing go-routine
	go writeReport(&r)

	return &r
}

func writeReport(r *Report) {
	err := r.t.ExecuteTemplate(r.output, "report", r.Pipe)
	if err != nil {
		r.Done <- err
	}

	close(r.Done)
}

func (r *Report) FinishReport() {
	close(r.Pipe)

	select {
	case err := <-r.Done:
		LogErrorsIfNotNil(err)
	}

	err := r.t.ExecuteTemplate(r.output, "footer", nil)
	LogErrorsIfNotNil(err)

	r.output.Close()
}
