# Copyright 2018 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

% : %.go
	go build $<

all: client ../updatecfg/updatecfg.pb.go

../updatecfg/updatecfg.pb.go: ../updatecfg/updatecfg.proto
	protoc -I ../updatecfg --go_out=plugins=grpc:../updatecfg ../updatecfg/updatecfg.proto

clean:
	-rm client

images: all
deploy: all
clean-images: clean
cleanall: clean
