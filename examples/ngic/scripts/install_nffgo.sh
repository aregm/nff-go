#!/bin/bash

BASE_DIR=$PWD

# check if go is installed
if ! type -P  go > /dev/null; then
	echo "[INFO] Installing go"
	wget https://dl.google.com/go/go1.10.3.linux-amd64.tar.gz
	tar -xvzf go1.10.3.linux-amd64.tar.gz > /dev/null
	export GOROOT=$PWD/go
fi

if [ ! -d "nff" ]; then
	# create nff directory
	mkdir nff
    
	# set  environment file
	export GOPATH=$PWD/nff
    	export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
              
	# download nff-go packages
	go get -v -d github.com/intel-go/nff-go > /dev/null

	cd $GOPATH/src/github.com/intel-go/nff-go

	# switch to fixed_bng branch
	git fetch origin
	git checkout -b fixed_bng origin/fixed_bng

	# get dependancies
	./scripts/get-depends.sh

	# build nff-go
	make
	
	#generate nff go env file
	DPDK_VERSION=$(cat mk/include.mk | grep DPDK_VERSION | awk 'NR==1' | awk -F " = " '{print $2}')
        # update env file with DPDK_VERSION
	sed -i "s/DPDK_VERSION=.*/DPDK_VERSION=$DPDK_VERSION/g" $BASE_DIR/setgoenv.sh
else
	echo "[ERROR] nff directory exist !!! quiting"
fi
