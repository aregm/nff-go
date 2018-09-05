#! /bin/sh -x

go get -v -d github.com/docker/docker/client
rm -rf $GOPATH/src/github.com/docker/docker/vendor/github.com/docker/go-connections
go get -v github.com/Sirupsen/logrus
go get -v github.com/pkg/errors
go get -v golang.org/x/net/proxy
go get -v github.com/docker/go-connections
go get -v golang.org/x/tools/cmd/stringer
go get -v github.com/vishvananda/netlink
go get -v github.com/google/gopacket

# GRPC support for NAT example
go get -v google.golang.org/grpc
go get -v github.com/golang/protobuf/protoc-gen-go
if ! command -v protoc &> /dev/null; then
    echo You should install protobuf compiler package, e.g. \"sudo dnf install protobuf-compiler\" or \"sudo apt-get install protobuf-compiler\"
fi
