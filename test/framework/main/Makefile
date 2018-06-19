# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

% : %.go
	go build $<

all: tf perf_compare report_compare

tf: tf.go ../apptype_string.go ../config.go ../dockerlauncher.go ../logging.go ../testsuite.go ../types.go ../report.go

report_compare: report_compare.go ../types.go ../report.go ../dockerlauncher.go

clean:
	-rm tf perf_compare

images: all
deploy: all
clean-images: clean
cleanall: clean
