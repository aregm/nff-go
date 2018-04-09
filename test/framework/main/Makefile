# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

all: tf

tf: tf.go ../config.go ../dockerlauncher.go ../logging.go ../testsuite.go ../types.go ../report.go
	go build $<
	go build perf_compare.go

clean:
	-rm tf perf_compare

images: all
deploy: all
clean-images: clean
cleanall: clean
