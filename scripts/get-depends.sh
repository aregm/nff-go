#! /bin/sh -x

go get -v -d github.com/docker/docker/client
rm -rf $GOPATH/src/github.com/docker/docker/vendor/github.com/docker/go-connections
go get -v github.com/Sirupsen/logrus
go get -v github.com/pkg/errors
go get -v golang.org/x/net/proxy
go get -v github.com/docker/go-connections
go get -v github.com/vishvananda/netlink
go get -v github.com/google/gopacket
go get -v golang.org/x/tools/cmd/stringer
go get -v gopkg.in/ini.v1
go get -v github.com/golang-collections/go-datastructures/queue
