// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "encoding/binary"
import "flag"
import "fmt"
import "log"
import "net"
import "strconv"
import "sync"
import "time"

const (
	network = "udp"
)

type stats struct {
	count, reordered uint64
	duration         time.Duration
}

func main() {
	port := flag.Uint("p", 33333, "First queue UDP port to send traffic to. Other queues use subsequent port numbers.")
	size := flag.Uint("s", 8, "Datagram packet size.")
	timeout := flag.Uint("t", 10, "Timeout in seconds on how long to wait for transmission to finish.")
	queues := flag.Uint("q", 1, "Number of simultaneous queues.")
	flag.Parse()

	if *size < uint(8) {
		log.Fatal("Packet size should not be less than 8 bytes.")
	}

	s := make([]stats, *queues)
	var wg sync.WaitGroup
	for q := uint(0); q < *queues; q++ {
		wg.Add(1)
		go recv(&s[q], &wg, *port+q, *size, *timeout)
	}

	wg.Wait()

	count := uint64(0)
	reordered := uint64(0)
	duration := time.Duration(0)
	for q := uint(0); q < *queues; q++ {
		count += s[q].count
		reordered += s[q].reordered
		duration += s[q].duration
	}
	count /= uint64(*queues)
	reordered /= uint64(*queues)
	duration /= time.Duration(*queues)
	fmt.Printf("Average received %d in %v, reordered %d (%02.2f%%)\n",
		count, duration, reordered, float64(reordered)/float64(count)*100.0)
}

func recv(s *stats, wg *sync.WaitGroup, port, size, timeout uint) {
	defer wg.Done()
	addr, err := net.ResolveUDPAddr(network, ":"+strconv.Itoa(int(port)))
	if err != nil {
		log.Fatal("ResolveUDPAddr returned ", err)
	}

	conn, err := net.ListenUDP(network, addr)
	if err != nil {
		log.Fatal("ListenUDP returned ", err)
	}
	defer conn.Close()

	buffer := make([]byte, size)
	var count uint64
	var reordered uint64
	var start, stop time.Time
	var started bool
	for {
		// Set timestamps
		if !started {
			start = time.Now()
			started = true
		}
		stop = time.Now()

		// Set receive timeout
		err = conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
		if err != nil {
			log.Fatal("SetReadDeadline returned ", err)
		}

		// Receive a packet
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if err.(*net.OpError).Timeout() {
				break
			} else {
				log.Fatal("ReadFromUDP returned ", err)
			}
		}
		if uint(n) != size {
			log.Fatal("Failed to receive a complete packet of size ", strconv.Itoa(int(size)),
				", received ", strconv.Itoa(n), " bytes instead")
		}

		// Parse packet counter
		num := binary.BigEndian.Uint64(buffer)
		if num != count+1 {
			reordered++
		}
		count = num
	}

	s.count = count
	s.reordered = reordered
	s.duration = stop.Sub(start)
	fmt.Printf("Queue on port %d received %d packets in %v, reordered: %d (%02.2f%%)\n",
		port, count, s.duration, reordered, float64(reordered)/float64(count)*100.0)
}
