#! /bin/sh -x

# This is helper file for Travis CI build in Ubuntu xenial

sudo apt-get install ragel libboost-all-dev

cd ~
git clone https://github.com/intel/hyperscan.git
cd hyperscan
cmake . && make -j6

export PKG_CONFIG_PATH=$HOME/hyperscan
export LD_LIBRARY_PATH=$HOME/hyperscan/lib
export CGO_LDFLAGS="-lstdc++ -L$HOME/hyperscan/lib -lhs"
export CGO_CFLAGS="-I$HOME/hyperscan/src"

go get -v github.com/flier/gohs/hyperscan
