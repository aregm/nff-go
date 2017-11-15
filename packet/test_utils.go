// +build !test

package packet

import (
	"github.com/intel-go/yanff/low"
)

// testMempool is common for all tests
var testMempool *low.Mempool

// GetMempoolForTest initialize DPDK and testMempool.
// Calling this function guarantee initialization is done once during all tests in package.
func GetMempoolForTest() *low.Mempool {
	if testMempool == nil {
		argc, argv := low.InitDPDKArguments([]string{})
		// burstSize=32, mbufNumber=8191, mbufCacheSize=250
		low.InitDPDK(argc, argv, 32, 8191, 250, 0)
		testMempool = low.CreateMempool()
	}
	return testMempool
}
