package dpdk

import (
	"github.com/intel-go/nff-go/internal/low"
)

// SetCpuAffinity sets cpu affinity for dpdkr port thread.
func SetCpuAffinity(coreID int) error {
	return low.SetAffinity(coreID)
}

// DPDKRingInit initializes the EAL.
func DPDKRingInit(args []string) error {
	argc, argv := low.InitDPDKArguments(args)

	var err error

	mbufNumber := uint(0)

	mbufCacheSize := uint(0)

	needKNI := 0

	NoPacketHeadChange := true

	needChainedReassembly := false

	needChainedJumbo := false

	needMemoryJumbo := false
	if err := low.InitDPDK(argc, argv, low.burstSize, mbufNumber, mbufCacheSize, needKNI,
		NoPacketHeadChange, needChainedReassembly, needChainedJumbo, needMemoryJumbo); err != nil {
		return err
	}
	return nil
}

type Ring low.Ring

// LookupDPDKRing lookup the ring of dpdkr port.
func LookupDPDKRing(name string) *Ring {
	return low.LookupRing(name)
}

// The caller must be pointer.
// RingDequeueBurst deueues data from dpdkr port ring.
func (ring *Ring) RingDequeueBurst(buffer []uintptr, count uint) uint {
	return ((*low.Ring)(ring)).DequeueBurst(buffer, count)
}
