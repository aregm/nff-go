//Package global ...
// Copyright (c) 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package global

const (
	//StaticARPFilePath static arp config file path
	StaticARPFilePath = "config/static_arp.cfg"
)

// stats counters
var (
	UlRxCounter uint64
	DlRxCounter uint64
	UlTxCounter uint64
	DlTxCounter uint64
)

//kni counters
var (
	KniUlRxCounter uint64
	KniDlRxCounter uint64
	KniUlTxCounter uint64
	KniDlTxCounter uint64
)
