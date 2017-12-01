package main

import (
	"fmt"
	"os"

	"github.com/intel-go/yanff/flow"
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}
func main() {
	// Init YANFF system
	config := flow.Config{}
	CheckFatal(flow.SystemInit(&config))

	initCommonState()

	CheckFatal(flow.SystemStart())
}
