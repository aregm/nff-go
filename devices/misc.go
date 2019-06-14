// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package devices helps to query DPDK compatibles devices and to bind/unbind drivers
package devices

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var defaultTimeoutLimitation = 5 * time.Second

// FindDefaultDpdkDriver returns a default DPDK driver that the given NIC can
// use.
func FindDefaultDpdkDriver(nicName string) string {
	driver, err := readlinkBaseCmd(pathSysClassNetDeviceDriver.With(nicName))
	if err != nil {
		return DefaultDpdkDriver
	}
	switch driver {
	case DriverHvNetvcs:
		return DriverUioHvGeneric
	default:
		return DefaultDpdkDriver
	}
}

// GetDeviceID returns the device ID of given NIC name.
func GetDeviceID(nicName string) (string, error) {
	// DEV_ID=$(basename $(readlink /sys/class/net/<nicName>))
	raw, err := readlinkCmd(pathSysClassNetDevice.With(nicName))
	if err != nil {
		return "", err
	}
	// raw should be like /sys/devices/pci0002:00/0000:00:08.0/virtio2/net/ens8
	raws := strings.Split(raw, "/")
	if len(raws) < 5 {
		return "", fmt.Errorf("path not correct")
	}
	return raws[4], nil

}

// IsModuleLoaded checks if the kernel has already loaded the driver or not.
func IsModuleLoaded(driver string) bool {
	output, err := cmdOutputWithTimeout(defaultTimeoutLimitation, "lsmod")
	if err != nil {
		// Can't run lsmod, return false
		return false
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if checkModuleLine(line, driver) {
			return true
		}
	}
	return false
}

func writeToTargetWithData(sysfs string, flag int, mode os.FileMode, data string) error {
	writer, err := os.OpenFile(sysfs, flag, mode)
	if err != nil {
		return fmt.Errorf("OpenFile failed: %s", err.Error())
	}
	defer writer.Close()

	_, err = writer.Write([]byte(data))
	if err != nil {
		return fmt.Errorf("WriteFile failed: %s", err.Error())
	}

	return nil
}

func readlinkCmd(path string) (string, error) {
	output, err := cmdOutputWithTimeout(defaultTimeoutLimitation, "readlink", "-f", path)
	if err != nil {
		return "", fmt.Errorf("Cmd Execute readlink failed: %s", err.Error())
	}
	outputStr := strings.Trim(string(output), "\n")
	return outputStr, nil
}

func readlinkBaseCmd(path string) (string, error) {
	outputStr, err := readlinkCmd(path)
	if err != nil {
		return "", fmt.Errorf("Cmd Execute readlink failed: %s", err.Error())
	}
	result := filepath.Base(outputStr)
	return result, nil
}

func checkModuleLine(line, driver string) bool {
	if !strings.Contains(line, driver) {
		return false
	}
	elements := strings.Split(line, " ")
	return elements[0] == driver
}

func cmdOutputWithTimeout(duration time.Duration, cmd string, parameters ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	output, err := exec.CommandContext(ctx, cmd, parameters...).Output()
	if err != nil {
		return nil, err
	}
	return output, nil
}
