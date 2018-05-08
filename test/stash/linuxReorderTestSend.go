// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "encoding/binary"
import "flag"
import "log"
import "net"
import "strconv"
import "sync"

const (
	network = "udp"
)

func main() {
	target := flag.String("t", "", "Target host to send packets to.")
	port := flag.Uint("p", 33333, "First queue UDP port to send traffic to. Other queues use subsequent port numbers.")
	size := flag.Uint("s", 8, "Datagram packet size.")
	num := flag.Uint64("n", 10000, "Number of packets to send.")
	queues := flag.Uint("q", 1, "Number of simultaneous queues.")
	flag.Parse()

	if *size < uint(8) {
		log.Fatal("Packet size should not be less than 8 bytes.")
	}

	var wg sync.WaitGroup
	for q := uint(0); q < *queues; q++ {
		wg.Add(1)
		go send(&wg, *target, *port+q, *size, *num)
	}
	wg.Wait()
}

func send(wg *sync.WaitGroup, target string, port, size uint, num uint64) {
	defer wg.Done()
	addr, err := net.ResolveUDPAddr(network, target+":"+strconv.Itoa(int(port)))
	if err != nil {
		log.Fatal("ResolveUDPAddr returned ", err)
	}

	conn, err := net.DialUDP(network, nil, addr)
	if err != nil {
		log.Fatal("DialUDP returned ", err)
	}
	defer conn.Close()

	buffer := make([]byte, size)
	for i := uint64(1); i <= num; i++ {
		binary.BigEndian.PutUint64(buffer, uint64(i))
		n, err := conn.Write(buffer)
		if err != nil {
			log.Fatal("Write returned ", err)
		}
		if uint(n) != size {
			log.Fatal("Failed to send a complete packet of size ", strconv.Itoa(int(size)),
				", sent ", strconv.Itoa(n), " bytes instead")
		}
	}
}
