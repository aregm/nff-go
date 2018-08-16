#!/bin/bash

# check if go is installed
if ! type -P  go > /dev/null; then
	echo "[INFO] Installing go"
	wget https://dl.google.com/go/go1.10.3.linux-amd64.tar.gz
	tar -xvzf go1.10.3.linux-amd64.tar.gz > /dev/null
else
	echo "[INFO] $(go version) detected using the same"
	sed -i "s#export GOROOT=.*#export GOROOT=$GOROOT#g" setgoenv.sh
fi

if [ ! -d "nff" ]; then
	# create nff directory
	mkdir nff

	# source nevironment file
	source setgoenv.sh

	# download nff-go packages
	go get -v -d github.com/intel-go/nff-go > /dev/null

	cd $GOPATH/src/github.com/intel-go/nff-go

	# switch to fixed_bng branch
	git fetch origin
	git checkout -b fixed_bng origin/fixed_bng

	# get dependancies
	./scripts/get-depends.sh

	# build nff-go
	make -j8

else
	echo "[ERROR] nff directory exist !!! quiting"

fi
