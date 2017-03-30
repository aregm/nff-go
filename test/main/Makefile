# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

all: main

main: main.go ../config.go ../dockerlauncher.go ../logging.go ../testsuite.go ../types.go ../report.go
	go build $<

clean:
	-rm main

images: all
deploy: all
clean-images: clean
cleanall: clean
