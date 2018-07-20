# Packet generation to file

## What it is
Pktgen parses config in json format and generates packets according to it and sends to port or pcap file that can be read by NFF-GO reader, Wireshark, tcpdump and other tools reading pcap files.
Generator package has public API which can be used for own generator.

### API:

```go
func GetGenerator() *generator 
```
returns generator object pointer which is singleton, so will be created only once.

```go
func (g *generator) GetGeneratedNumber() uint64
```
returns how much packets were generated.

```go
func (g *generator) ResetCounter() {
```
sets counter of generated packets to 0.

```go
func (g *generator) SetGenerateNumber(number uint64)
```
sets number to generate. When generated counter will reach it, generation will be stopped.

```go
func (g *generator) ResetGenerateNumber()
```
sets number to generate to infinity (by default).

```go
func ReadConfig(fileName string) ([]*parseConfig.MixConfig, error)
```
returns read and parsed config from file.

```go
func GetContext(mixConfig []*parseConfig.MixConfig) (genParameters, error)
```
returns context that chould be sent to generator according to configuration.

```go
func Generate(pkt *packet.Packet, context flow.UserContext)
```
is a main generator nunction. Context is obligatory.

### Example of usage:
```go
    // parse config
    configuration, err := generator.ReadConfig(pathToConfigJSON)
    // check error
	flow.CheckFatal(err)
    // generate context by config
    context, err := generator.GetContext(configuration)
    // check error
    flow.CheckFatal(err)
    // set generator
    outFlow, err := flow.SetFastGenerator(generator.Generate, speed, &context)
    // check error
    flow.CheckFatal(err)
    // send
    flow.CheckFatal(flow.SetSender(outFlow, uint16(port)))

    // periodically print statistics
	go func() {
        g :=  generator.GetGenerator()
		for {
			println("Sent", g.GetGeneratedNumber(), "packets")
			time.Sleep(time.Second * 5)
		}
	}()
```

### Configuration syntax:
File should be a structure containing structure with ethernet header or mix configuration:
```json
{
    "ether": {
    }
}
```
or mix following regexp "mix[0-9]*"
```json
{
    "mix1": {
    },
    "mix2": {
    },
    "mix3": {
    }
}
```
Inside each packet header can be either data or next level header, inside mix is packet header and quantity.
#### packet data configuration:
possible options are:
* "raw":
```json
"raw": {
  "data": "string with data that will be copied in packet.data"
}
```
* "randbytes":
```json
"randbytes": {
  "size": 50,
  "deviation": 10
}
```
size +-deviation random bytes will be generated, deviation field can be omitted
* "pdist":
```json
"pdist": [
    {
        "probability": 0.5,
        "randbytes":    {
            "size": 50,
            "deviation": 10
        }
    },
    {
        "probability": 0.5,
        "raw": {
            "data": "sfsfsfs"
        }
    }
]
```
pdist is an array of structures with data and probability of this data to be chosen
sum of probabilitis should be (0,1]

so, minimum config file example is:
```json
{
    "ether": {
        "raw": {
            "data": "111"
        }
    }
}
```

#### range structure:
```json
"range": {
    "min": "00:25:96:FF:FE:12",
    "start": "00:30:00:FF:FE:12",
    "max": "00:FF:96:FF:FE:12",
    "incr": 3
}
```
Range is available for IP, MAC addresses and TCP ports.
min and max fields are obligatory, start should be [min, max], by defauld start = min, incr by default is 0.
#### l2 config:
possible fields are:
* saddr which can be string or structure "range"
```json
"saddr": {
    "range": {
        "min": "00:25:96:FF:FE:12",
        "start": "00:30:00:FF:FE:12",
        "max": "00:FF:96:FF:FE:12",
        "incr": 3
    }
}
```
* daddr which can be string or structure "range"
```json
"daddr": "00:FF:96:FF:FE:12"
```
* VLAN tagging:
to each packet vlan tag can be added: "vlan-tci" and then numeric TCI information
```json
{
    "ether": {
                "saddr": "00:25:96:FF:FE:12",
                "daddr": "00:00:96:FF:00:00",
                "vlan-tci": 123,
                "ip": {
                    "version": 6,
                    "saddr": "2001:db8:a0b:12f0::",
                    "randbytes":    {
                        "size": 70
                    }
                }
            }
}
```

* l3 configuration or data, possible values are: "ip", "arp", "raw", "randbytes", "pdist":
```json
{
    "ether": {
                "saddr": {
                    "range": {
                        "min": "00:25:96:FF:FE:12",
                        "start": "00:30:00:FF:FE:12",
                        "max": "00:FF:96:FF:FE:12",
                        "incr": 3
                    }
                },
                "daddr": "00:FF:96:FF:FE:12",
                "pdist": [
                    {
                        "probability": 0.5,
                        "randbytes":    {
                            "size": 50,
                            "deviation": 10
                        }
                    },
                    {
                        "probability": 0.5,
                        "raw": {
                            "data": "sfsfsfs"
                        }
                    }
                ]
            }
}
```
#### l3 config:
Ip of 4 and 6 versions are supported
* "version" numeric vield with abailable values 4 or 6:
```json
"version": 6
```
* "saddr" sets a source ip address, can be string or range
for ip v4:
```json
"saddr": "1.1.127.1"
```
for ip v6:
```json
"saddr": "2001:db8:a0b:12f0::"
```
* "daddr" sets a destination ip address, can be string or range
for ip v4:
```json
"daddr": "1.1.127.1"
```
for ip v6:
```json
"daddr": "2001:db8:a0b:12f0::"
```
* l4 configuration or data, so probable values are: "tcp", "udp", "icmp", "raw", "randbytes" or "pdist"
```json
"ip": {
    "version": 4,
    "saddr": "1.1.127.1",
    "daddr": {
        "range": {
            "min": "1.1.1.1.",
            "max": "3.3.3.3"
        }
    },
    "raw": {
        "data": "023a0232ff9340x0340123"
    }
}
```

also arp packets are supported:
```json
{
    "ether": {
                "arp": {
                    "opcode": 1,
                    "gratuitous" : true,
                    "sha": "99:25:96:FF:FE:12",
                    "spa": "1.1.1.1"
                }
            }
}
```
* "opcode" is the operation code, supported only two values 1 for ARP Request and 2 for ARP Reply
* "gratuitous" is boolean field, can be ommited (false by default), but can be set to true to make announcement
* "sha" is a string with sender hardware address
* "tha" is a string with target hardware address
* "spa" is a string with sender protocol address
* "tpa" is a string with target protocol address
Ethernet source is set to sha by default, destination is broadcast.

#### l4 configuration:
##### "tcp" options:
* "sport" sets a source port can be numeric value of range
``` json
"sport": {
    "range": {
        "min": 1,
        "max": 8080,
        "incr": 100
    }
}
```
* "dport" sets a destination port can be numeric value of range
``` json
"dport": 1024
```
* "seq" sets a sequence number can be "incr"/"increasing" or "rand"/"random"
```json
 "seq": "increasing"
```
* "flags" sets tcp flags
```json
 "flags": ["ack", "psh"]
```
* data configuration: "raw", "randbytes", "pdist"
```json
"tcp": {
    "sport": {
        "range": {
            "min": 1,
            "max": 8080,
            "incr": 100
        }
    },
    "dport": 2000,
    "seq": "increasing",
    "flags": ["ack", "psh"],
    "pdist": [
        {
            "probability": 0.7,
            "randbytes":    {
                "size": 50,
                "deviation": 10
            }
        },
        {
            "probability": 0.2,
            "raw": {
                "data": "sfsfsfs"
            }
        }
    ]
}
```
##### udp options:
* "sport" sets a source port can be numeric value of range
``` json
"sport": {
    "range": {
        "min": 1,
        "max": 8080,
        "incr": 100
    }
}
```
* "dport" sets a destination port can be numeric value of range
``` json
"dport": 1024
```
* data configuration: "raw", "randbytes", "pdist"
```json
"udp": {
    "sport": 1,
    "dport": 2,
    "randbytes":    {
        "size": 100,
        "deviation": 20
    }
}
```
##### icmp options:
* "type" is a numeric field, sets type value in header:
```json
"type": 3
```
* "code" is a numeric field, sets code value in header:
```json
"code": 0
```
* "identifier" or "id" is a numeric field, sets identifier value in header:
```json
"id": 0
```
* "seq" or "seqNum" can be "incr"/"increasing" or "rand"/"random" sets a sequence number in header:
```json
"seq": "rand"
```
* data configuration: "raw", "randbytes", "pdist":
```json
"icmp": {
    "type": 10,
    "code": 1,
    "seq": "increasing",
    "pdist": [
        {
            "probability": 0.3,
            "randbytes":    {
                "size": 50,
                "deviation": 10
            }
        },
        {
            "probability": 0.3,
            "raw": {
                "data": "0000000000000000000000000000000000"
            }
        }
    ]
}
```
#### mix config:
Mix should contain packet configuration "ether" and "quantity".
```json
"mix1": {
    "ether": {
                "saddr": {
                    "range": {
                        "min": "00:25:96:FF:FE:12",
                        "start": "00:30:00:FF:FE:12",
                        "max": "00:FF:96:FF:FE:12",
                        "incr": 10
                    }
                },
                "daddr": "00:FF:96:FF:FE:12",
                "randbytes":    {
                    "size": 40,
                    "deviation": 0
                }   
             },
    "quantity": 6
},
"mix2": {
    "ether": {
                "saddr": "00:FF:96:FF:FE:12",
                "daddr": "00:FF:96:FF:FE:12",
                "randbytes":    {
                    "size": 500,
                    "deviation": 0
                }   
             },
    "quantity": 3
},
"mix3": {
            "ether": {
                        "saddr": "00:25:96:FF:FE:12",
                        "daddr": "00:00:96:FF:00:00",
                        "ip": {
                            "version": 4,
                            "saddr": "1.1.127.1",
                            "daddr": "1.1.1.3",
                            "tcp": {
                                "sport": 8080,
                                "dport": 2000,
                                "seq": "increasing",
                                "flags": ["ack", "fin", "syn"],
                                "randbytes":    {
                                    "size": 1466,
                                    "deviation": 0
                                }
                            }
                        }
                    },
            "quantity": 1
        }
```
The following sequence of packets will be generated for config above:
6 packets "mix1" configuration, 3 packets "mix2" configuration and 1 packet "mix3" and this chain will be repeated until a needed number is generated.
