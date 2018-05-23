package pattern

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"

	"github.com/flier/gohs/hyperscan"
)

const (
	// TotalNumFlows keeps last flow for dropped packets
	TotalNumFlows uint = 2
	// NumFlows = 1 is enough to process packets from file
	NumFlows uint = TotalNumFlows - 1
)

// HSdb keeps Hyperscan db and scratches
type HSdb struct {
	// Bdb is Hyperscan block database
	Bdb hyperscan.BlockDatabase
	// Scratches keep separate scratch for each handler
	Scratches [NumFlows]*hyperscan.Scratch
}

// Pattern describes one regex and action on match (allow/disallow packet)
type Pattern struct {
	Name   string
	Regexp string
	Re     *regexp.Regexp
	Allow  bool
}

// GetPatternsFromFile reads JSON file
func GetPatternsFromFile(filename string) ([]Pattern, error) {
	f, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	patterns := make([]Pattern, 0)
	if err := json.Unmarshal(f, &patterns); err != nil {
		return nil, err
	}
	return patterns, nil
}

// SetupGoRegexps compiles each regexp in pattern array and keep result
// in pattern.Re
func SetupGoRegexps(patterns []Pattern) {
	for i := 0; i < len(patterns); i++ {
		patterns[i].Re = regexp.MustCompile(patterns[i].Regexp)
	}
}

// SetupHyperscan makes setup of Hyperscan DB and preallocates Scratches
func (hsdb *HSdb) SetupHyperscan(patterns []Pattern) {
	unparsed := getAllowPatterns(patterns)
	parsed := parsePatterns(unparsed)
	var err error
	hsdb.Bdb, err = hyperscan.NewBlockDatabase(parsed...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Could not compile patterns, %s", err)
		os.Exit(-1)
	}

	// Allocate one scratch per flow
	for i := uint(0); i < NumFlows; i++ {
		hsdb.Scratches[i], err = hyperscan.NewScratch(hsdb.Bdb)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Could sot allocate scratch space i=%d for block db: %s", i, err)
			os.Exit(-1)
		}
	}
}

// CleanupHyperscan close DB and deallocate Scratches
func (hsdb *HSdb) CleanupHyperscan() {
	for i := uint(0); i < NumFlows; i++ {
		hsdb.Scratches[i].Free()
	}
	hsdb.Bdb.Close()
}

func getAllowPatterns(patterns []Pattern) (ret []string) {
	for _, p := range patterns {
		if p.Allow == true {
			ret = append(ret, p.Regexp)
		}
	}
	if len(ret) == 0 {
		fmt.Fprintf(os.Stderr, "ERROR: no 'allow' rules in file. HS mode support only allow rules")
		os.Exit(-1)
	}
	return
}

func parsePatterns(unparsed []string) (patterns []*hyperscan.Pattern) {
	for k, v := range unparsed {
		p, err := hyperscan.ParsePattern(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: could not parse pattern: %s", err)
			os.Exit(-1)
		}
		p.Id = k
		patterns = append(patterns, p)
	}
	return
}
