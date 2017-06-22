# YANFF - Yet Another Network Function Framework 

## What it is
YANFF is a set of libraries for creating and deploying cloud-native Network Functions (NFs). It is designed to simplify the creation of network functions with no performance sacrifice due to Data Plane Development Kit (DPDK) usage. But it is not DPDK wrapper library; it is an experimental and novel approach for creating network functions. YANFF is an Open Source BSD licensed project that runs mostly in Linux user land. The most recent patches and enhancements provided by the community are available in the master branch.

## Getting YANFF
To get YANFF you can use **go get -v -d github.com/intel-go/yanff**
This command will show an error that build cannot be done, but build is done differently because it is necessary to build and link with DPDK. 

**_Note_** If you just checkout the source tree from github, YANFF does not build unless placed into the correct subdirectory of $GOPATH.

## Build and run requirements
### Library requirements
Because YANFF uses and builds DPDK drivers, most YANFF build and run requirements are DPDK driver build and run requirements. See [System Requirements in the DPDK Getting Started Guide for Linux](http://dpdk.org/doc/guides/linux_gsg/sys_reqs.html) for more information.

### Test requirements
YANFF is dependent on several Go packages and a Docker* remote API that requires special installation:

1. Make sure you are using Go version 1.8 or higher.
2. Download Docker sources: go get -v -d github.com/docker/docker/api
3. Go to $GOPATH/src/github.com/docker/docker/vendor/github.com/docker and delete the "go-connections" directory
4. Install go-connections dependencies:
  * **go get -v github.com/Sirupsen/logrus**
  * **go get -v github.com/pkg/errors**
5. Install proxy support: **go get -v golang.org/x/net/proxy**
6. Install go-connections from the mainstream repository: **go get -v github.com/docker/go-connections**
7. Build the Docker remote API from sources: **go install github.com/docker/docker/api**
8. Install the stringer code generator: **go get -v golang.org/x/tools/cmd/stringer**
9. Set your PATH to point to the bin directory under your GOPATH. For example **export PATH="$PATH:$GOPATH"/bin**
10. You can now build a test framework using the **make main** command in the test sub-directory. _Note_ To build main.go without using first run **go generate** command from the "test" directory.

## Building YANFF
### Main library
Makefiles, which build examples and tests, do this should automatically set environment variables in the mk/include.mk file. If necessary, you must set these environment variables have to be set by handsmanually:
* **RTE_SDK=$GOPATH/src/github.com/intel-go/yanff/test/dpdk/dpdk-17.02** _Note:_ The DPDK version may change in the future_
* **RTE_TARGET=x86_64-native-linuxapp-gcc** _Note:_ Only the GNU GCC compiler is currently supported.
* **CGO_CFLAGS=-I$RTE_SDK/$RTE_TARGET/include** _Enables finding DPDK headers._
* **CGO_LDFLAGS=-L$RTE_SDK/$RTE_TARGET/lib** _Enables finding find DPDK libraries_

### Running YANFF
After building a DPDK driver with the make command, you must register network cards to work with the DPDK driver, load necessary kernel modules, and bind cards to themthe modules. See [Compiling the DPDK Target from Source](http://dpdk.org/doc/guides/linux_gsg/build_dpdk.html) and [How to get best performance with NICs on Intel platforms](http://dpdk.org/doc/guides/linux_gsg/nic_perf_intel_platform.html) in the DPDK Getting Started Guide for Linux for more information.

The kernel module, which is required for DPDK user-mode drivers, is built but not installed into kernel directory. You can load it using fill path to the module file: **$GOPATH/src/github.com/intel-go/yanff/test/dpdk/dpdk-17.02/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko**.

#### External DPDK driver usage

To use an external DPDK driver, apply a patch from test/dpdk/DPDK_17_02.patch. The patch makes it impossible to use indirect mbufs due to data races, but it improves YANFF performance (YANFF doesn't use indirect mbufs). If you use make commands from YANFF directories, the DPDK driver is downloaded and patched automatically.

### Documentation 
Use **make doc** command to generate full documentation. Alternatively, you can run the  **godoc -http=:6060** command and browse URLs:
* http://localhost:6060/pkg/yanff/flow/
* http://localhost:6060/pkg/yanff/rules/
* http://localhost:6060/pkg/yanff/packet/

### Tests
In addition to building tests, the **make** command in the top-level directory builds the testing framework and examples. YANFF distributed tests are packed inside of Docker container images. There are also unit non-distributed tests in some packages that you can run using the **make testing** command.

### Docker images
To create Docker images on the local default target (either the default UNIX socket in /var/run/docker.sock or whatever is defined in the DOCKER_HOST variable), use the **make images** command.

To deploy Docker images for use in distributed testing, use the **make deploy** command. This command requires two environment variables:
* YANFF_HOSTS="hostname1 hostname2 ... hostnameN"* - a list of all hostnames for deployed test Docker images
* DOCKER_PORT=2375* - the port number to connect to Docker daemons running on hosts in the YANFF_HOSTS variable

To delete generated images in the default Docker target, use the **make clean-images** command.

### Running tests
After Docker images are deployed on all test hosts, you can run distributed network tests. The test framework is located in the test/main directory and accepts a JSON file with a test specification. There are predefined configs for performance and stability tests in the same directory. To run these tests, change **hostname1** and **hostname2** to the hosts from the YANFF_HOSTS list in these JSON files.

### Cleaning-up
To clean all generated binaries, use the **make clean** command.
To delete all deployed images listed in YANFF_HOSTS, use the **make cleanall** command.

## Contribution
If you want to contribute to YANFF, check our [Contributing guide](https://github.com/intel-go/yanff/blob/master/CONTRIBUTING.md). We also recommend checking the 'janitorial' bugs in our list of open issues; these bugs can be solved without an extensive knowledge of YANFF. We would love to help you start contributing.

You can reach the YANFF development team via our [mailing list](mailto:areg.melik-adamyan@intel.com).
