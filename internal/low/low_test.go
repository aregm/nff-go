// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package low

import (
	"log"
	"math/rand"
	"testing"
	"time"
	"unsafe"
)

func init() {
	argc, argv := InitDPDKArguments([]string{})
	// Default: burstSize=32, mbufNumber=8191, mbufCacheSize=250
	if err := InitDPDK(argc, argv, 32, 8191, 250, 0, false, false, false, false); err != nil {
		log.Fatalf("fail to initialize with error: %+v\n", err)
	}
	rand.Seed(time.Now().UTC().UnixNano())
}

func TestReorder(t *testing.T) {
	const sliceLength = 500
	input := make([]int, sliceLength, sliceLength)
	inputPointers := make([]uintptr, sliceLength, sliceLength)
	outputPointers := make([]uintptr, sliceLength, sliceLength)

	for i := 0; i < sliceLength; i++ {
		input[i] = i
		inputPointers[i] = uintptr(unsafe.Pointer(&input[i]))
	}

	// Real usable ring size is count-1
	ring := CreateRing(64)
	a1 := uint(63)
	a2 := uint(29)
	a3 := uint(14)
	a4 := uint(1)
	for k := 0; k < 100; k++ {
		if k != 0 {
			a1 = uint(rand.Intn(64))
			a2 = uint(rand.Intn(64))
			a3 = uint(rand.Intn(64))
			a4 = uint(rand.Intn(int(64 - a3)))
		}
		for j := 0; j < 1000; j++ {
			if ring.EnqueueBurst(inputPointers[:a1], a1) != a1 {
				t.Errorf("Incorrect enqueueBurst 1")
			}
			if ring.DequeueBurst(outputPointers[:a1], a1) != a1 {
				t.Errorf("Incorrect dequeueBurst 1")
			}
			if ring.EnqueueBurst(inputPointers[a1:a1+a2], a2) != a2 {
				t.Errorf("Incorrect enqueueBurst 2")
			}
			if ring.DequeueBurst(outputPointers[a1:a1+a2], a2) != a2 {
				t.Errorf("Incorrect dequeueBurst 2")
			}
			if ring.EnqueueBurst(inputPointers[a1+a2:a1+a2+a3], a3) != a3 {
				t.Errorf("Incorrect enqueueBurst 3")
			}
			if ring.EnqueueBurst(inputPointers[a1+a2+a3:a1+a2+a3+a4], a4) != a4 {
				t.Errorf("Incorrect enqueueBurst 4")
			}
			if ring.DequeueBurst(outputPointers[a1+a2:a1+a2+a3+a4], a3+a4) != a3+a4 {
				t.Errorf("Incorrect dequeueBurst 3")
			}
			for i := 0; i < int(a1+a2+a3+a4); i++ {
				if *(*int)(unsafe.Pointer(outputPointers[i])) != i {
					t.Errorf("Ring reorder packet. %d element is %d instead of %d.", i, *(*int)(unsafe.Pointer(outputPointers[i])), i)
					t.FailNow()
				}
			}
		}
	}
}
