# Fixed BNG-PGW Data Plane (DP) VNF
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
For High level design refer : nff-go/Fixed BNG PGW on GO over NFF.ppt

Basic Flow Diagram:
> ```
>                     +------------------+
>       Uplink (UL)   |                  |
>       ------------> +      NGIC-DP     +---------->
>                     |                  |
>         GTP-U       | S1U          SGI |
>                     |                  |
>    Downlink(DL)     |                  |
>       <------------+                   +<----------
>                     +------------------+
> ```

#### Install
---------------

- ../nff-go/scripts/install_nffgo.sh
    This script will do the following:
    1. Install Go (if not installed) , set GOPATH and GOROOT
    2. Create a nff directory set it as GOROOT
    3. Download nff-go into GOROOT (fixed_bng branch with ngic-dp example)
    4. Download and install dependancies
    5. Build nff-go which will build ngic-dp example under example/ngic/

   How to use it ?
   Just copy this script and setgoenv.sh script to a directory where you want to setup nff-go and execute this script.e.g. copy it to /opt/ directory and give it executable permission and excute it as
   ```
   sudo ./install_nffgo.sh
   ```
   it will create /opt/nff directory and set it as GOROOT and install the nff-go with ngic-dp example.

- ../nff-go/scripts/setgoenv.sh
This script sets up the environment variables(GOPATH and GOROOT) once nff-go is installed as described in the above step. User can just source this file (from the location where it setup e.g. /opt/) and it will export the required environment variables and land the user to nff-go directory.

#### Configuration
-------------------------

DP Configuration
```
Config File : config/dp_config.cfg
```
DP configuration parameters
```
NeedKNI       - Enable KNI support(default true)
CPUList       - specify the core list (1-13) required 13 cores
S1U_PORT_IDX  - S1U port index
SGI_PORT_IDX  - SGI port index
S1U_IP        - S1U Ipv4 address
SGI_IP        - SGI Ipv4 address
S1UDeviceName - S1U kni tap device name
SGIDeviceName - SGI kni tap device name
MEMORY        - memory required in case of numa enabled for numa 1 e.g. MEMORY="0,4096"

```

Simu CP configuration

This is compile time option and it will help create/establish UE sessions without requiring
control plane VNF.

```
config/simu_cp.cfg
```
Simu CP configuration parameters :

```
S1U_SGW_IP    	  - S1U Source G/w ip address
ENODEB_IP_START   - eNodeB start IP
UE_IP_START       - User Equipment IP start
UE_IP_START_RANGE - User Equipment IP range
AS_IP_START		  - Application Server IP start
MAX_UE_SESS		  - Max UE session/no of flows
TPS				  - Transaction per second
BREAK_DURATION    - Break duration
DEFAULT_BEARER    - default bearers
MAX_UE_RAN        - Maximum UE RAN count
MAX_ENB_RAN       - Maximum eNB RAN count
StartS1U_TEID     - Start teid for S1U teid
StartENB_TEID     - Start teid for eNB teid

```

Static ARP configuration
```
config/static_arp.cfg
```

### Compile time options
----------------------------

Comment/uncomment the options mentioned below to enable/disable the feature in the Makefile and rebuild.

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

#### Run
----------------

1. Run DP using the following command
   ```
   ./run.sh
   ```
2. After the DP is in running state ( which starts printing the stats every sec.) run the following scripts:

   ```
   ./kni_ifcfg/kni-S1Udevcfg.sh
   ./kni_ifcfg/kni-SGIdevcfg.sh
   ```
These script will set the IP configuration on the S1U and SGI Kni interfaces.This is required in case of static arp is disabled.

#### Logs
--------------

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



