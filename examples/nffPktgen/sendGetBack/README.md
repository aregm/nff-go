# Packet generation, sending and receiving

## What it is
Parses config files, generates output and sends to file or port and counts them. Receives packets back and counts.

### Command-line options:
* --number sets the number of packets to get back and stop, default value is 10000000
* --speed sets the speed of generator
* --cycle sets cycle execution to generate infinite number of packets
* --outConfig specifies config per port portNum or file: 'path', 'path3': 'path2'. For example: 1: 'ip4.json', 'mix.pcap': 'mix.json'
* --inConfig specifies input ports and files: 'path', 'portNum2', 'path2'. For example: 1, 'ip4.pcap', 0, 'mix.pcap'

### Example of usage:
To run generation from "mix.json" config to port number 1 and from "../../ip4tcp.json" to file "ip4tcp.pcap" and receive packets from 
port 0 and file "../../ip4tcp.pcap" run:
```
    ./sendGetBack --outConfig "1: 'mix.json', ip4tcp.pcap: '../../ip4tcp.json'" --inConfig "0, '../../ip4tcp.json'"
```