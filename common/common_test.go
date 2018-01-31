package common

import (
	"reflect"
	"strconv"
	"testing"
)

const (
	BigCPUNum   = 40
	SmallCPUNum = 3
)

var maxCpuErr = WrapWithNFError(nil, "requested cpu exceeds maximum cores number on machine", MaxCPUExceedErr)
var invalidCpuRangeErr = WrapWithNFError(nil, "CPU range is invalid, min should not exceed max", InvalidCPURangeErr)

var cpuParseTests = []struct {
	line        string // input
	expected    []uint // expected result
	expectedErr error
}{
	{"", []uint{}, nil},
	{"1-5", []uint{1, 2, 3, 4, 5}, nil},
	{"1,10-13,9", []uint{1, 10, 11, 12, 13, 9}, nil},
	{"10-14,13-15", []uint{10, 11, 12, 13, 14, 13, 14, 15}, nil},
	{"1-3,6-", []uint{1, 2, 3}, &strconv.NumError{"Atoi", "", strconv.ErrSyntax}},
	{"-1", []uint{}, &strconv.NumError{"Atoi", "", strconv.ErrSyntax}},
	{"10-6", []uint{}, GetNFError(invalidCpuRangeErr)},
	{"1-3,10-6", []uint{1, 2, 3}, GetNFError(invalidCpuRangeErr)},
}

func TestParseCPUs(t *testing.T) {
	for _, tt := range cpuParseTests {
		actual, err := parseCPUs(tt.line)
		if !reflect.DeepEqual(GetNFError(err).Cause(), tt.expectedErr) {
			t.Errorf("ParseCpuList(\"%s\"): unexpected error:\ngot: %v,\nwant: %v\n", tt.line, err, tt.expectedErr)
			continue
		}
		if !reflect.DeepEqual(actual, tt.expected) {
			t.Errorf("ParseCpuList(\"%s\"): got %v, want %v", tt.line, actual, tt.expected)
		}
	}
}

var dropInvalidCPUsTests = []struct {
	cpus     []uint
	maxcpu   uint
	expected []uint // expected valid cpu list
}{
	{[]uint{}, 20, []uint{}},
	{[]uint{1, 2, 100, 1, 2, 100}, 20, []uint{1, 2, 1, 2}},
	{[]uint{1, 2, 100, 100, 2, 100}, 20, []uint{1, 2, 2}},
}

func TestDropInvalidCPUs(t *testing.T) {
	for _, tt := range dropInvalidCPUsTests {
		actual := dropInvalidCPUs(tt.cpus, tt.maxcpu)
		if !reflect.DeepEqual(actual, tt.expected) {
			t.Errorf("DropInvalidCPUs(\"%v,%d\"): got %v, want %v", tt.cpus, tt.maxcpu, actual, tt.expected)
		}
	}
}

var removeDuplicatesTests = []struct {
	cpus     []uint
	expected []uint
}{
	{[]uint{}, []uint{}},
	{[]uint{1, 2, 100, 100, 2, 100}, []uint{1, 2, 100}},
	{[]uint{1, 2, 100, 3}, []uint{1, 2, 100, 3}},
	{[]uint{1, 2, 1, 100, 100, 3}, []uint{1, 2, 100, 3}},
}

func TestRemoveDuplicates(t *testing.T) {
	for _, tt := range removeDuplicatesTests {
		actual := removeDuplicates(tt.cpus)
		if !reflect.DeepEqual(actual, tt.expected) {
			t.Errorf("removeDuplicates(\"%v\"): got %v, want %v", tt.cpus, actual, tt.expected)
		}
	}
}

var ErrorCauseTests = []struct {
	testError        error
	expectedCause    error
	expectedGetNFErr *NFError
	expectedCode     ErrorCode
}{
	{&strconv.NumError{"Atoi", "", strconv.ErrSyntax}, nil, nil, -1},

	{WrapWithNFError(&strconv.NumError{"Atoi", "", strconv.ErrSyntax}, "dailed to parse cpu", ParseCPUListErr),
		&strconv.NumError{"Atoi", "", strconv.ErrSyntax},
		&(NFError{CauseErr: &strconv.NumError{"Atoi", "", strconv.ErrSyntax}, Message: "dailed to parse cpu", Code: ParseCPUListErr}),
		ParseCPUListErr},

	{WrapWithNFError(maxCpuErr, "dailed to parse cpu", ParseCPUListErr),
		&(NFError{CauseErr: nil, Message: "requested cpu exceeds maximum cores number on machine", Code: MaxCPUExceedErr}),
		&(NFError{CauseErr: maxCpuErr, Message: "dailed to parse cpu", Code: ParseCPUListErr}), ParseCPUListErr},

	{WrapWithNFError(nil, "dailed to parse cpu", ParseCPUListErr),
		&(NFError{CauseErr: nil, Message: "dailed to parse cpu", Code: ParseCPUListErr}),
		&(NFError{CauseErr: nil, Message: "dailed to parse cpu", Code: ParseCPUListErr}), ParseCPUListErr},

	{nil, nil, nil, -1},
}

// TestErrorCause checks GetNFError, GetNFErrorCode, and Cause methods.
func TestErrorCause(t *testing.T) {
	for _, tt := range ErrorCauseTests {
		if !reflect.DeepEqual(GetNFError(tt.testError), tt.expectedGetNFErr) {
			t.Errorf("GetNFError: got: %v, want: %v\ntypes: %v, %v", GetNFError(tt.testError), tt.expectedGetNFErr,
				reflect.TypeOf(GetNFError(tt.testError)), reflect.TypeOf(tt.expectedGetNFErr))
		}
		if !reflect.DeepEqual(GetNFError(tt.testError).Cause(), tt.expectedCause) {
			t.Errorf("GetNFError.Cause: got: %v, want: %v\ntypes: %v, %v", GetNFError(tt.testError).Cause(), tt.expectedCause,
				reflect.TypeOf(GetNFError(tt.testError).Cause()), reflect.TypeOf(tt.expectedCause))
		}
		if !reflect.DeepEqual(GetNFErrorCode(tt.testError), tt.expectedCode) {
			t.Errorf("NFError code: got: %v, want: %v\n", GetNFError(tt.testError), tt.expectedGetNFErr)
		}
	}
}
