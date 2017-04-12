# YANFF - Yet Another Network Function Framework 

## What it is
YANFF is a set of libraries for creating and deploying Virtualized Network Functions (VNFs). It was designed to ease the creation of network functions with no performance sacrifice due to DPDK usage. But it is not DPDK wrapper library. We can say that it is an experimental and novel approach for creating network functions. It runs mostly in Linux userland. 
YANFF is an Open Source BSD licensed project. The most recent patches and enhancements, provided by the community, are available in master branch.

## Getting YANFF
To get YANFF you can use go get -v -d github.com/intel-go/yanff
This command will show an error that build cannot be done, but build is done differently because it is necessary to build and link with DPDK.

## Build and run requirements
### Library requirements
Since YANFF uses and builds DPDK, most of the build and run requrements are DPDK build and run requirements. Please refer to [this page](http://dpdk.org/doc/guides/linux_gsg/sys_reqs.html "DPDK requirements"), install necessary software packages and configure huge pages.

### Tests requirements
YANFF test framework has dependencies from several Go packages. The testing framework requires Docker remote API to be built successfully. Docker remote API currently has a problem with one of its vendored dependencies, so to build testing framework it has to be modified. Here is a step-by-step manual of installing Docker remote API to fulfill the needs of YANFF testing framework.

1. Make sure you are using Go version 1.8 or higher.
2. Download Docker sources: go get -v -d github.com/docker/docker/api
3. Go to $GOPATH/src/github.com/docker/docker/vendor/github.com/docker and delete directory named "go-connections."
4. Install go-connections dependencies:
  * go get -v github.com/Sirupsen/logrus
  * go get -v github.com/pkg/errors
5. Install proxy support: go get -v golang.org/x/net/proxy
6. Install go-connections from its mainstream repository: go get -v github.com/docker/go-connections
7. Build docker from sources: go install github.com/docker/docker/api
8. Install stringer code generator: go get -v golang.org/x/tools/cmd/stringer
9. Set your PATH to point to bin directory under your GOPATH, e.g. export PATH="$PATH:$GOPATH"/bin
10. You should be able to build test framework now with "make main" in test sub-directory.

## Building YANFF
### Main library
To build YANFF run **make** from top directory.

### Running YANFF applications
It is necessary to register network cards to work with DPDK, load necessary kernel modules and bind cards to them. After DPDK is built with **make**, refer to [this page](http://dpdk.org/doc/guides/linux_gsg/build_dpdk.html "Binding network cards to DPDK driver") to configure network cards to work with DPDK driver. For Intel network cards there are also [useful instructions for getting best performance](http://dpdk.org/doc/guides/linux_gsg/nic_perf_intel_platform.html "Intel NICs performance advices").

#### External DPDK usage

To use external DPDK apply patch from "test/dpdk/DPDK_17_02.patch" to DPDK. The patched version should be deliberately used for YANFF. After this it will be impossible to use indirect mbufs from patched DPDK due to data races,  but it will improve YANFF performance (YANFF doesn't use indirect mbufs). If you use make commands from YANFF directories, DPDK will be downloaded and patched automatically.

### Documentation 
Use **make doc** to generate full documentation. Alternatively, you can run command **godoc -http=:6060** and browse URLs
* http://localhost:6060/pkg/yanff/flow/
* http://localhost:6060/pkg/yanff/rules/ and
* http://localhost:6060/pkg/yanff/packet/

### Tests
In addition to building tests, **make** command on the top level also builds the testing framework and examples. YANFF distributed tests are packed inside of Docker container images. There are also unit non-distributed tests in some packages which may be run using **make testing** command.

### Docker images
To create Docker images on the local default target (either default UNIX socket in /var/run/docker.sock or whatever is defined in DOCKER_HOST variable) use **make images**.

To deploy Docker images to be used in distributed testing do **make deploy**. This command requires two environment variables:
* YANFF_HOSTS="hostname1 hostname2 ... hostnameN"* - a list of all hostnames where it is necessary to deploy test docker images.
* DOCKER_PORT=2375* - port number to be used to connect to Docker daemons running on hosts in YANFF_HOSTS variable.

To delete generated images to the default Docker target use **make clean-images**.

### Running tests
After docker images are deployed on all test hosts, it is possible to run distributed network tests. Test framework is located in test/main directory and accepts a JSON file with test specification. There are predefined configs for performance and stability tests in the same directory. To run these tests it is necessary to change hostnames "hostname1" and "hostname2" to the hosts from YANFF_HOSTS list in these JSON files.

### Clean-up
To clean all generated binaries use **make clean**.
To delete all deployed images listed in YANFF_HOSTS use **make cleanall**.

## Contribution
If you would like to contribute to YANFF, check our Contributing guide. We also recommend taking a look at the 'janitorial' bugs in our list of open issues as these bugs can be solved without an extensive knowledge of YANFF. We would love to help you start contributing!

The YANFF development team can be reached via our mailing list and on IRC in channel #YANFF on Freenode.
