# Fixed BNG-PGW Data Path (DP) VNF
==============================================

### Introduction
----------------
Evolved Packet Core (EPC) is a critical node in the wireless infrastructure,
which provides the data services to the end users. The PGW is a virtualized application
providing the same service as the standalone node.

### Feature List
----------------
The VNF currently supports the following PGW Data Path(DP) features:
* PCC (Policy Control and Charging) rules configuration.
* ADC (Application Detection and control) rules configuration.
* Packet Filters for Service Data Flow (SDF) configuration.
* Packet Selectors/Filters for ADC configuration.
* UE sessions with multiple Bearer support.
* KNI with static ARP and dynamic arp support
* Using Netlink for route and arp cache discovery and lookup.
* CP (Control Path) Simulator for establishing UE session.

### High Level Design
----------------------
For High level design refer : Fixed BNG PGW on GO over NFF.ppt

Basic Flow Diagram:
> ```
>                     +------------------+
>       Uplink (UL)   |                  |
>       ------------> +      BNG-PGW     +---------->
>                     |                  |
>         GTP-U       | S1U          SGI |      UDP
>                     |                  |
>    Downlink(DL)     |                  |
>       <------------+                   +<----------
>                     +------------------+
> ```

### Build, install, configure and test
------------------------------------------

##### Install

1. Install Go , set GOPATH and GOROOT
2. Install go-nff go get <url>
3. Install dependancies

##### Build
```
make clean;make
```
DP Configuration
```
config/dp_config.cfg
```
Simu CP configuraton
```
config/simu_cp.cfg
```
Static ARP configuraton
```
config/static_arp.cfg
```
#### Compile time options

Edit the MakeFile and comment and uncomment the options mentioned in the make file comments

1. Enable CP (Control Plane) Simulator
```
#LDFLAGS += -X main.RunCPSimu=true
```
2. Enable static ARP

```
#LDFLAGS += -X main.EnableStaticARP=true
```

3. Enable PCAP
```
#LDFLAGS += -X main.EnablePcap=true
```

Note: For pcap we need to add additional 2 cores in the core list.

##### Run
1. Run DP using the following command
```
./run.sh
```
2. After the PGW is in running state ( which starts printing the stats every sec.) run the following the scripts:
```
./kni_ifcfg/kni-S1Udevcfg.sh
./kni_ifcfg/kni-SGIdevcfg.sh
```
These script will set the IP configuration on the S1U and SGI Kni interfaces.This is required in case of static arp is disabled.

##### Logs
Log File location
```
log/dp.log
```
Enable debug log
1. Enable ngic debug log set DEBUG=true
Edit run.sh
```
DEBUG=true
```
2. Enable flow log set FLOW_DEBUG=true
Edit run.sh
```
FLOW_DEBUG=true
```

