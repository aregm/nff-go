// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package flow

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/internal/low"
)

const (
	rootText = `<!DOCTYPE html><html><body>
/<a href="/rxtx">rxtx</a> for protocol statistics gathered on all send and
receive or /rxtx/name for individual sender/receiver port.<br>
/<a href="/json/rxtx">json/rxtx</a> for JSON data structure enumerating all
ports that have statistics or /json/rxtx/name for JSON data structure with statistics
of indivitual individual sender/receiver port.
</body></html>`

	statsSummaryTemplateText = `<!DOCTYPE html>
<html><body>Select a node to see its counters
<table>{{$name := .StatsName}}
{{range $key, $value := .Values}}<tr><td><a href="/{{$name}}/{{$key}}">{{$key}}</a></td></tr>{{end}}{{/* end range .Values */}}
</table></body></html>`

	statsTemplateText = `<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
        <script type="text/javascript">
        google.charts.load('current', {'packages':['line']});
        google.charts.setOnLoadCallback(drawChart);

        var seconds;
        var interval;
        var seconds_counter = 0;
        var timeframe_input, interval_input;
        var pktsProcessedTotal, pktsDroppedTotal, bytesProcessedTotal;
        var pktsProcessedDelta, pktsDroppedDelta, bytesProcessedDelta;
        var prevPacketsProcessed = 0, prevPacketsDropped = 0, prevBytesProcessed = 0;
        var prevDataAvailable = false;
        var pkts_chart, bytes_chart;
        var delta_button, total_button;
        var pkts_object, bytes_object;
        var pkts_data, bytes_data;
        var pkts_options = {
            title:'Packets per refresh interval',
            legend:{position:'bottom'},
            chartArea:{width:'90%', height:'65%'},
            axes: {
                y: {
                    0: {
                        side: 'right',
                        label: 'Packets',
                        range: {min: 0}
                    }
                },
                x: {
                    0: {label: 'Seconds'}
                }
            }
        };
        var bytes_options = {
            title:'Bytes per refresh interval',
            legend:{position:'bottom'},
            chartArea:{width:'90%', height:'65%'},
            axes: {
                y: {
                    0: {
                        side: 'right',
                        label: 'Bytes',
                        range: {min: 0}
                    }
                },
                x: {
                    0: {label: 'Seconds'}
                }
            }
        };
        var intervalTimer;

        window.onload = init;

        function init()
        {
            pktsProcessedTotal = document.getElementById("pktsProcessedTotal");
            bytesProcessedTotal = document.getElementById("bytesProcessedTotal");
            pktsProcessedDelta = document.getElementById("pktsProcessedDelta");
            bytesProcessedDelta = document.getElementById("bytesProcessedDelta");
            pktsDroppedTotal = document.getElementById("pktsDroppedTotal");
            pktsDroppedDelta = document.getElementById("pktsDroppedDelta");

            pkts_chart = document.getElementById("pkts_chart");
            bytes_chart = document.getElementById("bytes_chart");

            timeframe_input = document.getElementById("timeframe_input");
            seconds = parseInt(timeframe_input.value, 10);

            interval_input = document.getElementById("interval_input");
            interval = parseInt(interval_input.value, 10);

            delta_button = document.getElementById("delta_button");
            total_button = document.getElementById("total_button");

            new_data();
            intervalTimer = setInterval(refreshdata, interval);
        }

        function new_data()
        {
            pkts_data = new google.visualization.DataTable();
            pkts_data.addColumn('string', 'Seconds');

            bytes_data = new google.visualization.DataTable();
            bytes_data.addColumn('string', 'Seconds');

            if (delta_button.checked) {
                pkts_data.addColumn('number', 'Delta packets processed');
                pkts_data.addColumn('number', 'Delta packets dropped');
                bytes_data.addColumn('number', 'Delta bytes processed');
            } else {
                pkts_data.addColumn('number', 'Total packets processed');
                pkts_data.addColumn('number', 'Total packets dropped');
                bytes_data.addColumn('number', 'Total bytes processed');
            }

            pkts_data.addRows(seconds * 1000.0 / interval);
            bytes_data.addRows(seconds * 1000.0 / interval);
        }

        function reset_data()
        {
            if (timeframe_input.validity.valid) {
                seconds = parseInt(timeframe_input.value, 10);
            } else {
                timeframe_input.value = seconds;
            }
            if (interval_input.validity.valid) {
                interval = parseInt(interval_input.value, 10);
            } else {
                interval_input.value = interval;
            }
            new_data();
            seconds_counter = 0;
            prevDataAvailable = false;
            clearInterval(intervalTimer);
            intervalTimer = setInterval(refreshdata, interval);
        }

        function refreshdata()
        {
            var xmlhttp = new XMLHttpRequest();
            xmlhttp.onreadystatechange = function() {
                if (this.readyState == 4)
                {
                    var dataObj;
                    if (this.status == 200)
                    {
                        dataObj = JSON.parse(this.responseText);
                    }
                    update_data(dataObj);
                }
            };
            xmlhttp.open("GET", "/json/{{.StatsName}}/{{.NodeName}}", true);
            xmlhttp.send();

            seconds_counter += interval / 1000.0;
        }

        function update_data(dataObj)
        {
            if (dataObj == null)
            {
                pktsProcessedTotal.innerHTML = "no data";
                bytesProcessedTotal.innerHTML = "no data";
                pktsProcessedDelta.innerHTML = "no data";
                bytesProcessedDelta.innerHTML = "no data";
                pktsDroppedTotal.innerHTML = "no data";
                pktsDroppedDelta.innerHTML = "no data";
                pkts_data.addRow(["" + seconds_counter, undefined, undefined]);
                bytes_data.addRow(["" + seconds_counter, undefined]);

                prevDataAvailable = false;
            }
            else
            {
                pktsProcessedTotal.innerHTML = dataObj.PacketsProcessed;
                bytesProcessedTotal.innerHTML = dataObj.BytesProcessed;
                prevPacketsProcessed = dataObj.PacketsProcessed - prevPacketsProcessed;
                prevBytesProcessed = dataObj.BytesProcessed - prevBytesProcessed;
                pktsDroppedTotal.innerHTML = dataObj.PacketsDropped;
                prevPacketsDropped = dataObj.PacketsDropped - prevPacketsDropped;

                if (prevDataAvailable) {
                    pktsProcessedDelta.innerHTML = prevPacketsProcessed;
                    pktsDroppedDelta.innerHTML = prevPacketsDropped;
                    bytesProcessedDelta.innerHTML = prevBytesProcessed;
                } else {
                    pktsProcessedDelta.innerHTML = "no data";
                    pktsDroppedDelta.innerHTML = "no data";
                    bytesProcessedDelta.innerHTML = "no data";
                }

                if (delta_button.checked) {
                    if (prevDataAvailable) {
                        pkts_data.addRow(["" + (seconds_counter).toFixed(1), prevPacketsProcessed, prevPacketsDropped]);
                        bytes_data.addRow(["" + (seconds_counter).toFixed(1), prevBytesProcessed]);
                    } else {
                        pkts_data.addRow(["" + (seconds_counter).toFixed(1), undefined, undefined]);
                        bytes_data.addRow(["" + (seconds_counter).toFixed(1), undefined]);
                    }
                } else {
                    pkts_data.addRow(["" + (seconds_counter).toFixed(1), dataObj.PacketsProcessed, dataObj.PacketsDropped]);
                    bytes_data.addRow(["" + (seconds_counter).toFixed(1), dataObj.BytesProcessed]);
                }

                prevDataAvailable = true;
                prevPacketsProcessed = dataObj.PacketsProcessed;
                prevPacketsDropped = dataObj.PacketsDropped;
                prevBytesProcessed = dataObj.BytesProcessed;
            }

            pkts_data.removeRow(0);
            pkts_object.draw(pkts_data, pkts_options);

            bytes_data.removeRow(0);
            bytes_object.draw(bytes_data, bytes_options);
        }

        function drawChart()
        {
            pkts_object = new google.charts.Line(pkts_chart);
            bytes_object = new google.charts.Line(bytes_chart);

            pkts_object.draw(pkts_data, pkts_options);
            bytes_object.draw(bytes_data, bytes_options);
        }
        </script>
        <style>
         table {
             border: 3pt solid black;
             border-collapse: collapse;
             text-align: left;
         }
         tr {
             border: 1pt solid black;
         }
         td {
             border: 1pt solid grey;
         }
         input:invalid+span:after {
             content: '✖';
             padding-left: 5px;
         }
         input:valid+span:after {
             content: '✓';
             padding-left: 5px;
         }
        </style>
    </head>
    <body>
        <h1>{{.NodeName}}</h1>
        <table>
            <tr><th>Data</th><th>Total</th><th>Delta</th>
            <tr>
                <td>Packets processed</td>
                <td><div id="pktsProcessedTotal">no data</div></td>
                <td><div id="pktsProcessedDelta">no data</div></td>
            </tr><tr>
                <td>Packets dropped</td>
                <td><div id="pktsDroppedTotal">no data</div></td>
                <td><div id="pktsDroppedDelta">no data</div></td>
            </tr><tr>
                <td>Bytes processed</td>
                <td><div id="bytesProcessedTotal">no data</div></td>
                <td><div id="bytesProcessedDelta">no data</div></td>
            </tr>
        </table>
        <label for="timeframe_input">Number of seconds to show on graph (10-100):</label>
        <input id="timeframe_input" type="number" value="30" min="10" max="100" required></input>
        <span class="validity"></span>
        <input onclick="reset_data()" type="button" value="Set"></input>
        <form action="/action_page.php">
            <input id="delta_button" type="radio" onclick="reset_data()" name="type" value="delta" checked="true"/> Show delta<br>
            <input id="total_button" type="radio" onclick="reset_data()" name="type" value="total"/> Show total<br>
        </form>
        <label for="interval_input">Refresh interval in ms (100-100000):</label>
        <input id="interval_input" type="number" value="1000" min="100" max="100000" required></input>
        <span class="validity"></span>
        <input onclick="reset_data()" type="button" value="Set"></input>
        <div id="pkts_chart" style="width: 100%; height: 500px"></div>
        <div id="bytes_chart" style="width: 100%; height: 500px"></div>
    </body>
</html>`
)

var (
	rxtxstats            map[string]*common.RXTXStats = map[string]*common.RXTXStats{}
	statsSummaryTemplate *template.Template
	statsTemplate        *template.Template

	countersEnabledInFramework   bool = low.CountersEnabledInFramework
	countersEnabledInApplication bool = false
	useInterlockedCounters       bool = low.UseInterlockedCounters
	analyzePacketSizes           bool = low.AnalyzePacketSizes
)

func init() {
	statsSummaryTemplate = template.New("summary")
	statsSummaryTemplate = template.Must(statsSummaryTemplate.Parse(statsSummaryTemplateText))
	statsTemplate = template.New("node")
	statsTemplate = template.Must(statsTemplate.Parse(statsTemplateText))
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	url := strings.Split(r.URL.Path, "/")
	if len(url) < 2 || url[1] == "" || url[1] == "index.html" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, rootText)
	} else {
		http.Error(w, "Bad root request: "+r.URL.Path, http.StatusBadRequest)
		return
	}
}

func handleRXTXStats(w http.ResponseWriter, r *http.Request) {
	data := struct {
		StatsName string
		Values    map[string]*common.RXTXStats
	}{
		StatsName: "rxtx",
		Values:    rxtxstats,
	}
	err := statsSummaryTemplate.Execute(w, &data)
	if err != nil {
		fmt.Println("Error in RXTX summary stats", err)
	}
}

func handleRXTXStatsNode(w http.ResponseWriter, r *http.Request) {
	url := strings.Split(r.URL.Path, "/")
	sendNodeVisualization(w, r, "rxtx", url[2], true)
}

func sendNodeVisualization(w http.ResponseWriter, r *http.Request, statsName, nodeName string, doDropped bool) {
	data := struct {
		StatsName string
		NodeName  string
		DoDropped bool
	}{
		StatsName: statsName,
		NodeName:  nodeName,
		DoDropped: doDropped,
	}
	err := statsTemplate.Execute(w, &data)
	if err != nil {
		fmt.Println("Error in", statsName, "node", nodeName, "stats", err)
	}
}

func handleJSONRXTXStats(w http.ResponseWriter, r *http.Request) {
	enc := json.NewEncoder(w)

	w.Header().Set("Content-Type", "application/json")
	names := make([]string, len(rxtxstats))
	index := 0
	for keys := range rxtxstats {
		names[index] = keys
		index++
	}
	enc.Encode(names)
}

func handleJSONRXTXStatsNode(w http.ResponseWriter, r *http.Request) {
	url := strings.Split(r.URL.Path, "/")
	enc := json.NewEncoder(w)

	stats, ok := rxtxstats[url[3]]
	if !ok {
		http.Error(w, "Bad node name: "+url[3], http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc.Encode(stats)
}

func initCounters(addr *net.TCPAddr) error {
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/rxtx/", handleRXTXStatsNode)
	http.HandleFunc("/rxtx", handleRXTXStats)
	http.HandleFunc("/json/rxtx/", handleJSONRXTXStatsNode)
	http.HandleFunc("/json/rxtx", handleJSONRXTXStats)

	server := &http.Server{}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil
	}

	go func() {
		if err := server.Serve(listener); err != nil {
			common.LogWarning(common.Initialization, "Error while serving HTTP requests:", err)
			server.Close()
		}
	}()

	low.SetCountersEnabledInApplication(true)
	countersEnabledInApplication = true

	return nil
}

func registerRXTXStatitics(s *common.RXTXStats, name string) {
	rxtxstats[name] = s
}
