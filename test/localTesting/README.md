# Local testing tools

## What it is
Tools for testing and running yanff applications on one local machine by writing to file and reading from file instead of sending and receiving packets.

### Pktgen
Pktgen parses config in json format and generates packets according to it in pcap file that can be read by YANFF reader, Wireshark, tcpdump and other tools reading pcap files.
More detailed information can be found in [pktgen directory](https://github.com/intel-go/yanff/test/localTesting/pktgen)