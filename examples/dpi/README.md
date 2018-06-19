For DPI example application gohs package is required.

## Build gohs
1. Install [Intel Hyperscan](https://github.com/intel/hyperscan.git) with your package manager.
If hyperscan can not be installed from repo, first use [instruction](#Build-Hyperscan) below.

2. Download and build gohs package:

        go get -v github.com/flier/gohs/hyperscan


## Build Hyperscan

1. Download and build [Intel Hyperscan](https://github.com/intel/hyperscan.git) library.

        git clone https://github.com/intel/hyperscan.git
        cd hyperscan
        cmake . && make -j10

2. Set variables:

        HSDIR=/path/to/hyperscan
        export PKG_CONFIG_PATH=$HSDIR
        export CGO_LDFLAGS="-L$HSDIR/lib -lhs"
        export CGO_CFLAGS=-I$HSDIR/src

