[![Go Report Card](https://goreportcard.com/badge/github.com/intel-go/nff-go)](https://goreportcard.com/report/github.com/intel-go/nff-go) 
[![GoDoc](https://godoc.org/github.com/intel-go/nff-go?status.svg)](https://godoc.org/github.com/intel-go/nff-go)
[![Dev chat at https://gitter.im/intel-yanff/Lobby](https://img.shields.io/badge/gitter-developer_chat-46bc99.svg)](https://gitter.im/intel-yanff/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Build Status](https://travis-ci.org/intel-go/nff-go.svg?branch=develop)](https://travis-ci.org/intel-go/nff-go)
# Network Function Framework for Go (former YANFF)

__Wonderful news__ : we are now supporting AF_XDP and supporting(almost) getting packets directly from Linux. So you do not need to write 3(three) different applications to process packets coming from different type of drivers of PMDs. You just write everything in NFF-Go, and it can dynamically use whatever you would like underneath. Contact [us](mailto:edwin.verplanke@intel.com) if you need help.

## What it is
NFF-Go is a set of libraries for creating and deploying cloud-native Network
Functions (NFs). It simplifies the creation of network functions without
sacrificing performance. 
* Higher level abstractions than DPDK. Using DPDK as a fast I/O engine for performance
* Go language: safety, productivity, performance, concurrency
* Network functions are application programs not virtual machines
* Built-in scheduler to auto-scale processing based on input traffic. Both up and down.

### Benefits:
* Easily leverage Intel hardware capabilities: multi-cores, AES-NI, CAT, QAT, DPDK
* 10x reduction in lines of code
* No need to be an expert network programmer to develop performant network function
* Similar performance with C/DPDK per box 
* No need to worry on elasticity - done automatically
* Take advantage of cloud native deployment: continuous delivery, micro-services, containers

### Feel the difference
Simple ACL based firewall
```Go

func main() {
	// Initialize NFF-GO library to use 8 cores max.
	config := flow.Config{
		CPUCoresNumber: 8,
	}
	flow.CheckFatal(flow.SystemInit(&config))

	// Get filtering rules from access control file.
	L3Rules, err := packet.GetL3ACLFromTextTable("Firewall.conf")
	flow.CheckFatal(err)

	// Receive packets from zero port. Receive queue will be added automatically.
	inputFlow, err := flow.SetReceiver(uint8(0))
	flow.CheckFatal(err)

	// Separate packet flow based on ACL.
	rejectFlow, err := flow.SetSeparator(inputFlow, L3Separator, nil)
	flow.CheckFatal(err)

	// Drop rejected packets.
	flow.CheckFatal(flow.SetStopper(rejectFlow))

	// Send accepted packets to first port. Send queue will be added automatically.
	flow.CheckFatal(flow.SetSender(inputFlow, uint8(1)))

	// Begin to process packets.
	flow.CheckFatal(flow.SystemStart())
}

// User defined function for separating packets
func L3Separator(currentPacket *packet.Packet, context flow.UserContext) bool {
	currentPacket.ParseL4()
	// Return whether packet is accepted or not. Based on ACL rules.
	return currentPacket.L3ACLPermit(L3Rules)
}
```
NFF-GO is an Open Source BSD licensed project that runs mostly in Linux user
land. The most recent patches and enhancements provided by the community are
available in the *_develop_* branch. master branch provides the latest stable released version under the appropriate tag. 

## Getting NFF-GO

Starting with release 0.7.0 NFF-Go uses go.mod for getting dependencies,
therefore Go version 1.11 or later is required. To checkout NFF-Go
sources use the following command

        git clone --recurse-submodules http://github.com/intel-go/nff-go

## Setting up the build and run environment

### DPDK
    
NFF-GO uses DPDK, so you must setup your system to build and run DPDK. See [System
Requirements in the DPDK Getting Started Guide for
Linux](http://dpdk.org/doc/guides/linux_gsg/sys_reqs.html) for more
information.

By default NFF-Go is build with Mellanox cards support out of the box you
need to install additional dependencies required for MLX network
drivers. On Ubuntu they are called `libmnl-dev` and
`libibverbs-dev`. For more details see MLX drivers respective pages
for [MLX4](https://doc.dpdk.org/guides/nics/mlx4.html) and
[MLX5](https://doc.dpdk.org/guides/nics/mlx5.html). If these
dependencies cannot be satisfied, and Mellanox drivers are not needed,
you can set variable `NFF_GO_NO_MLX_DRIVERS` to some unempty value to
disable MLX drivers compilation.

Additional dependencies are required for pktgen, especially if you are
running RedHat or CentOS Linux distributions. See [this
file](https://git.dpdk.org/apps/pktgen-dpdk/tree/INSTALL.md?h=pktgen-3.5.9&id=d469543f651506a8c9fb7c667a060950c5d92649)
for details. LUA section for RedHat and CentOS is in its end.

After building a DPDK driver with the make command, you must register network
cards to work with the DPDK driver, load necessary kernel modules, and bind
cards to the modules. See [Compiling the DPDK Target from
Source](http://dpdk.org/doc/guides/linux_gsg/build_dpdk.html) and [How to get
best performance with NICs on Intel
platforms](http://dpdk.org/doc/guides/linux_gsg/nic_perf_intel_platform.html)
in the DPDK Getting Started Guide for Linux for more information.

The kernel module, which is required for DPDK user-mode drivers, is built but
not installed into kernel directory. You can load it using the full path to the
module file:
nff-go/test/dpdk/dpdk/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko

### Go

Use Go version 1.11.4 or higher. To check the version of Go, do:

        go version
        
### AF_XDP support

AF_XDP support is enabled by default, and it requires you to install
`libbpf` package. At the time of writing Ubuntu doesn't have this
library among its packages, so it is necessary to build `libbpf` from
sources or disable AF_XDP socket support.

To disable it set variable `NFF_GO_NO_BPF_SUPPORT` to some unempty
value. When NFF_GO is built with it, AF_XDP support is disaled and
using it results in errors.

If you want to build `libbpf` from sources you can do it in two
different ways.
* If you are using stock Linux kernel from distribution, [download
  `libbpf` from GitHub](https://github.com/libbpf/libbpf), then
  execute `cd src; make; sudo make install`. Add /usr/lib64 to your
  ldconfig path.
* If you build Linux kernel from sources, you can build `libbpf` from
  Linux source tree using commands `cd tools/lib/bpf; make; sudo make
  install install_headers`. Add /usr/local/lib64 to your ldconfig path.

## Building NFF-GO

When Go compiler runs for the first time it downloads all dependent
packages listed in `go.mod` file. This operation cannot be done in
parallel because otherwise Go package cache gets corrupted. Because of
that it is necessary to run command `go mod download` before first
`make` is done. Another option is to use single process `make -j1`
when it is run for the first time, but may be quite slow.

        cd nff-go
        go mod download        # do it once before first build
        make -j8

## Building NFF-GO in debug mode

		make debug -j8

# Running NFF-GO

## Documentation 

Online API documentation is available on [godoc.org
site](https://godoc.org/github.com/intel-go/nff-go). API usage is
explained on our [Wiki pages](https://github.com/intel-go/nff-go/wiki).

## Tests

Invoking make in the top-level directory builds the testing framework and
examples. NFF-GO distributed tests are packaged inside of Docker container
images. There are also single node unit tests in some packages that you can
run using the command:

         make testing

### Docker images

To create Docker images on the local default target (either the default UNIX
socket in /var/run/docker.sock or whatever is defined in the DOCKER_HOST
variable), use the **make images** command.

To deploy Docker images for use in distributed testing, use the **make deploy**
command. This command requires two environment variables:

* NFF_GO_HOSTS="hostname1 hostname2 ... hostnameN"* - a list of all hostnames for deployed test Docker images
* DOCKER_PORT=2375* - the port number to connect to Docker daemons running on hosts in the NFF_GO_HOSTS variable

To delete generated images in the default Docker target, use the **make
clean-images** command.

### Running tests

After the Docker images are deployed on all test hosts, you can run distributed
network tests. The test framework is located in the test/main directory and
accepts a JSON file with a test specification. There are predefined configs for
performance and stability tests in the same directory. To run these tests,
change **hostname1** and **hostname2** to the hosts from the NFF_GO_HOSTS list
in these JSON files.

## Cleaning-up

To clean all generated binaries, use the **make clean** command.  To delete all
deployed images listed in NFF_GO_HOSTS, use the **make cleanall** command.

## Contributing

If you want to contribute to NFF-Go, check our [Contributing
guide](https://github.com/intel-go/nff-go/blob/master/CONTRIBUTING.md). We also
recommend checking the bugs with 'help-wanted' or 'easyfix' in our list of open issues; these bugs
can be solved without an extensive knowledge of NFF-Go. We would love to help
you start contributing.

You can reach the NFF-Go development team via our [mailing list](mailto:edwin.verplanke@intel.com).

    
