package common_test

import (
	"github.com/intel-go/yanff/common"
	"reflect"
	"strconv"
	"testing"
)

const (
	BigCPUNum   = 40
	SmallCPUNum = 3
)

var cpuParseTests = []struct {
	line        string // input
	cpuNum      uint   // max number of cpus
	expected    []uint // expected result
	expectedErr error
}{
	{"", BigCPUNum, []uint{}, nil},
	{"1-5", BigCPUNum, []uint{1, 2, 3, 4, 5}, nil},
	{"18-21", BigCPUNum, []uint{18, 19, 20, 21}, nil},
	{"11,12,450", BigCPUNum, []uint{}, common.ErrMaxCPUExceed},
	{"1,10-13,9", BigCPUNum, []uint{1, 10, 11, 12, 13, 9}, nil},
	{"10-14,13-15", BigCPUNum, []uint{10, 11, 12, 13, 14, 15}, nil},
	{"10-14,11-12", BigCPUNum, []uint{10, 11, 12, 13, 14}, nil},
	{"", SmallCPUNum, []uint{}, nil},
	{"1-5", SmallCPUNum, []uint{1, 2, 3}, nil},
	{"18-21", SmallCPUNum, []uint{18, 19, 20}, nil},
	{"11,12,450", SmallCPUNum, []uint{}, common.ErrMaxCPUExceed},
	{"1,10-13,9", SmallCPUNum, []uint{1, 10, 11}, nil},
	{"10-14,13-15", SmallCPUNum, []uint{10, 11, 12}, nil},
	{"10-14,11-12", SmallCPUNum, []uint{10, 11, 12}, nil},
	{"1-3,6-", BigCPUNum, []uint{1, 2, 3}, &strconv.NumError{"Atoi", "", strconv.ErrSyntax}},
	{"-1", BigCPUNum, []uint{}, &strconv.NumError{"Atoi", "", strconv.ErrSyntax}},
	{"10-6", SmallCPUNum, []uint{}, common.ErrInvalidCPURange},
	{"1-3,10-6", SmallCPUNum, []uint{1, 2, 3}, common.ErrInvalidCPURange},
}

// TestParseCPUs require minumum 22 cores to pass without error.
// If machine has less cores, test fail with ErrMaxCPUExceed error
func TestParseCPUs(t *testing.T) {
	for _, tt := range cpuParseTests {
		actual, err := common.ParseCPUs(tt.line, tt.cpuNum)
		if !reflect.DeepEqual(err, tt.expectedErr) {
			t.Errorf("ParseCpuList(\"%s\",%d): unexpected error:\ngot: %v,\nwant: %v\n", tt.line, tt.cpuNum, err, tt.expectedErr)
			continue
		}
		if !reflect.DeepEqual(actual, tt.expected) {
			t.Errorf("ParseCpuList(\"%s\",%d): got %v, want %v", tt.line, tt.cpuNum, actual, tt.expected)
		}
	}
}
