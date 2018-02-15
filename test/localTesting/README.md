# Local testing tools

## What it is
Tools for testing and running nff-go applications on one local machine by writing to file and reading from file instead of sending and receiving packets.

### Pktgen
Pktgen parses config in json format and generates packets according to it in pcap file that can be read by NFF-GO reader, Wireshark, tcpdump and other tools reading pcap files.
More detailed information can be found in [pktgen directory](https://github.com/intel-go/nff-go/tree/master/test/localTesting/pktgen)
