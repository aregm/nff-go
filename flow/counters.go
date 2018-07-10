// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package flow

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/intel-go/nff-go/common"
)

const (
	countersEnabled        = true
	useInterlockedCounters = true
	analyzePacketSizes     = true
)

var (
	rxtxstats map[string]*common.RXTXStats     = map[string]*common.RXTXStats{}
	telemetry map[string]*common.NodeTelemetry = map[string]*common.NodeTelemetry{}
)

func handler(w http.ResponseWriter, r *http.Request) {
	url := strings.Split(r.URL.Path, "/")
	if len(url) < 2 || url[1] == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>
/<a href="/rxtxstats">rxtxstats</a> for protocol statistics gathered on all send and
receive or /rxtxstats/name for individual send/receiver node.<br>
<br>
/<a href="/telemetry">telemetry</a> for all nodes names and their counters which include
received, send, processed, lost and dropped packets. Using
/telemetry/name returns information about individual node.
</body></html>`)
		return
	}

	enc := json.NewEncoder(w)

	if url[1] == "rxtxstats" {
		if len(url) > 2 {
			stats, ok := rxtxstats[url[2]]
			if !ok {
				http.Error(w, "Bad node name: "+url[2], http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			enc.Encode(stats)
		} else {
			w.Header().Set("Content-Type", "application/json")
			enc.Encode(rxtxstats)
		}
	} else if url[1] == "telemetry" {
		if len(url) > 2 {
			stats, ok := telemetry[url[2]]
			if !ok {
				http.Error(w, "Bad node name: "+url[2], http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			enc.Encode(stats)
		} else {
			w.Header().Set("Content-Type", "application/json")
			enc.Encode(telemetry)
		}
	} else {
		http.Error(w, "Bad request: "+url[1], http.StatusBadRequest)
		return
	}
}

func initCounters(addr *net.TCPAddr) error {
	http.HandleFunc("/", handler)
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

	return nil
}

func registerRXTXStatitics(s *common.RXTXStats, name string) {
	rxtxstats[name] = s
}

func registerNodeStatitics(t *common.NodeTelemetry, name string) {
	telemetry[name] = t
}
