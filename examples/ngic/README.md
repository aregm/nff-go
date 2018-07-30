# Infrastructure Core (NGIC) VNF
==============================================

### Introduction
----------------
Evolved Packet Core (EPC) is a critical node in the wireless infrastructure,
which provides the data services to the end users. The NGIC is a
virtualized application providing the same service as the standalone node.

### Feature List
----------------
The NGIC VNF currently supports the following PGW features:
* PCC (Policy Control and Charging) rules configuration.
* ADC (Application Detection and control) rules configuration.
* Packet Filters for Service Data Flow (SDF) configuration.
* Packet Selectors/Filters for ADC configuration.
* UE sessions with multiple Bearer support.
* KNI with static ARP support

### High Level Design
----------------------
For High level design refer : Fixed BNG PGW on GO over NFF.ppt

Basic Flow Diagram:
> ```
>                     +------------------+
>       Uplink (UL)   |                  |
>       ------------> +      NGIC-DP     +---------->
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

