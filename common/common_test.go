package common_test

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/intel-go/yanff/common"
)

const (
	BigCPUNum   = 40
	SmallCPUNum = 3
)

var maxCpuErr = common.WrapWithNFError(nil, "requested cpu exceeds maximum cores number on machine", common.MaxCPUExceedErr)
var invalidCpuRangeErr = common.WrapWithNFError(nil, "CPU range is invalid, min should not exceed max", common.InvalidCPURangeErr)

var cpuParseTests = []struct {
	line        string // input
	cpuNum      uint   // max number of cpus
	expected    []uint // expected result
	expectedErr error
}{
	{"", BigCPUNum, []uint{}, nil},
	{"1-5", BigCPUNum, []uint{1, 2, 3, 4, 5}, nil},
	{"18-21", BigCPUNum, []uint{18, 19, 20, 21}, nil},
	{"11,12,450", BigCPUNum, []uint{}, common.GetNFError(maxCpuErr)},
	{"1,10-13,9", BigCPUNum, []uint{1, 10, 11, 12, 13, 9}, nil},
	{"10-14,13-15", BigCPUNum, []uint{10, 11, 12, 13, 14, 15}, nil},
	{"10-14,11-12", BigCPUNum, []uint{10, 11, 12, 13, 14}, nil},
	{"", SmallCPUNum, []uint{}, nil},
	{"1-5", SmallCPUNum, []uint{1, 2, 3}, nil},
	{"18-21", SmallCPUNum, []uint{18, 19, 20}, nil},
	{"11,12,450", SmallCPUNum, []uint{}, common.GetNFError(maxCpuErr)},
	{"1,10-13,9", SmallCPUNum, []uint{1, 10, 11}, nil},
	{"10-14,13-15", SmallCPUNum, []uint{10, 11, 12}, nil},
	{"10-14,11-12", SmallCPUNum, []uint{10, 11, 12}, nil},
	{"1-3,6-", BigCPUNum, []uint{1, 2, 3}, &strconv.NumError{"Atoi", "", strconv.ErrSyntax}},
	{"-1", BigCPUNum, []uint{}, &strconv.NumError{"Atoi", "", strconv.ErrSyntax}},
	{"10-6", SmallCPUNum, []uint{}, common.GetNFError(invalidCpuRangeErr)},
	{"1-3,10-6", SmallCPUNum, []uint{1, 2, 3}, common.GetNFError(invalidCpuRangeErr)},
}

// TestParseCPUs require minumum 22 cores to pass without error.
// If machine has less cores, test fail with ErrMaxCPUExceed error
func TestParseCPUs(t *testing.T) {
	for _, tt := range cpuParseTests {
		actual, err := common.ParseCPUs(tt.line, tt.cpuNum)
		if !reflect.DeepEqual(common.GetNFError(err).Cause(), tt.expectedErr) {
			t.Errorf("ParseCpuList(\"%s\",%d): unexpected error:\ngot: %v,\nwant: %v\n", tt.line, tt.cpuNum, err, tt.expectedErr)
			continue
		}
		if !reflect.DeepEqual(actual, tt.expected) {
			t.Errorf("ParseCpuList(\"%s\",%d): got %v, want %v", tt.line, tt.cpuNum, actual, tt.expected)
		}
	}
}

var ErrorCauseTests = []struct {
	testError        error
	expectedCause    error
	expectedGetNFErr *common.NFError
	expectedCode     common.ErrorCode
}{
	{&strconv.NumError{"Atoi", "", strconv.ErrSyntax}, nil, nil, -1},

	{common.WrapWithNFError(&strconv.NumError{"Atoi", "", strconv.ErrSyntax}, "dailed to parse cpu", common.ParseCPUListErr),
		&strconv.NumError{"Atoi", "", strconv.ErrSyntax},
		&(common.NFError{CauseErr: &strconv.NumError{"Atoi", "", strconv.ErrSyntax}, Message: "dailed to parse cpu", Code: common.ParseCPUListErr}),
		common.ParseCPUListErr},

	{common.WrapWithNFError(maxCpuErr, "dailed to parse cpu", common.ParseCPUListErr),
		&(common.NFError{CauseErr: nil, Message: "requested cpu exceeds maximum cores number on machine", Code: common.MaxCPUExceedErr}),
		&(common.NFError{CauseErr: maxCpuErr, Message: "dailed to parse cpu", Code: common.ParseCPUListErr}), common.ParseCPUListErr},

	{common.WrapWithNFError(nil, "dailed to parse cpu", common.ParseCPUListErr),
		&(common.NFError{CauseErr: nil, Message: "dailed to parse cpu", Code: common.ParseCPUListErr}),
		&(common.NFError{CauseErr: nil, Message: "dailed to parse cpu", Code: common.ParseCPUListErr}), common.ParseCPUListErr},

	{nil, nil, nil, -1},
}

// TestErrorCause checks GetNFError, GetNFErrorCode, and Cause methods.
func TestErrorCause(t *testing.T) {
	for _, tt := range ErrorCauseTests {
		if !reflect.DeepEqual(common.GetNFError(tt.testError), tt.expectedGetNFErr) {
			t.Errorf("GetNFError: got: %v, want: %v\ntypes: %v, %v", common.GetNFError(tt.testError), tt.expectedGetNFErr,
				reflect.TypeOf(common.GetNFError(tt.testError)), reflect.TypeOf(tt.expectedGetNFErr))
		}
		if !reflect.DeepEqual(common.GetNFError(tt.testError).Cause(), tt.expectedCause) {
			t.Errorf("GetNFError.Cause: got: %v, want: %v\ntypes: %v, %v", common.GetNFError(tt.testError).Cause(), tt.expectedCause,
				reflect.TypeOf(common.GetNFError(tt.testError).Cause()), reflect.TypeOf(tt.expectedCause))
		}
		if !reflect.DeepEqual(common.GetNFErrorCode(tt.testError), tt.expectedCode) {
			t.Errorf("NFError code: got: %v, want: %v\n", common.GetNFError(tt.testError), tt.expectedGetNFErr)
		}
	}
}
