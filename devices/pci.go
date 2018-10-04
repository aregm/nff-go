// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package devices helps to query DPDK compatibles devices and to bind/unbind drivers
package devices

import (
	"fmt"
	"os"
)

type pciDevice struct {
	id     string
	class  string
	vendor string
	device string
	driver string
}

// GetPciDeviceByPciID gets device info by PCI bus id.
func GetPciDeviceByPciID(pciID string) (Device, error) {
	output, err := cmdOutputWithTimeout(defaultTimeoutLimitation, "lspci", "-Dvmmnks", pciID)
	if err != nil {
		return nil, err
	}

	info := &pciDevice{id: pciID}

	match := rPciClass.FindSubmatch(output)
	if len(match) < 2 {
		return nil, fmt.Errorf("Bad lspci output: %s", output)
	}
	info.class = string(match[1][:])

	match = rPciVendor.FindSubmatch(output)
	if len(match) < 2 {
		return nil, fmt.Errorf("Bad lspci output: %s", output)
	}
	info.vendor = string(match[1][:])

	match = rPciDevice.FindSubmatch(output)
	if len(match) < 2 {
		return nil, fmt.Errorf("Bad lspci output: %s", output)
	}
	info.device = string(match[1][:])

	match = rPciDriver.FindSubmatch(output)
	// driver may be empty
	if len(match) >= 2 {
		info.driver = string(match[1][:])
	}

	return info, nil
}

func (p *pciDevice) Bind(driver string) error {
	var err error
	p.driver, err = BindPci(p.id, driver, p.vendor, p.device)
	return err
}

func (p *pciDevice) Unbind() error {
	return UnbindPci(p.id, p.driver)
}

func (p *pciDevice) Probe() error {
	var err error
	p.driver, err = ProbePci(p.id)
	return err
}

func (p *pciDevice) CurrentDriver() (string, error) {
	return GetCurrentPciDriver(p.id)
}

func (p *pciDevice) ID() string {
	return p.id
}

func (p *pciDevice) String() string {
	return pciDeviceStringer.With(p.ID, p.class, p.vendor, p.device, p.driver)
}

// BindPci binds the driver to the given device ID
func BindPci(devID, driver, vendor, device string) (string, error) {
	current, err := GetCurrentPciDriver(devID)
	if err != nil {
		return "", err
	}

	switch current {
	case driver:
		// already binding the same driver, skip binding it
		return driver, nil
	case "":
		// if not binding to any driver, continue to bind pci device driver
	default:
		// if there already binding to other driver, unbind it first
		if err := unbindPciDeviceDriver(devID, current); err != nil {
			return "", err
		}
	}

	if err := bindPciDeviceDriver(devID, driver, vendor, device); err != nil {
		return "", err
	}

	return driver, nil
}

// UnbindPci unbinds the driver that is bound to the given device ID
func UnbindPci(devID, driver string) error {
	current, err := GetCurrentPciDriver(devID)
	if err != nil {
		return err
	} else if current == "" {
		// this device is already not bound to any driver
		return nil
	}

	return unbindPciDeviceDriver(devID, current)
}

func ProbePci(devID string) (string, error) {
	if err := probePciDriver(devID); err != nil {
		return "", err
	}

	return GetCurrentPciDriver(devID)
}

// GetCurrentPciDriver returns the current driver that device bound to.
func GetCurrentPciDriver(devID string) (string, error) {
	output, err := cmdOutputWithTimeout(defaultTimeoutLimitation, "lspci", "-Dvmmnks", devID)
	if err != nil {
		return "", fmt.Errorf("Cmd Execute lspci failed: %s", err.Error())
	}

	match := rPciDriver.FindSubmatch(output)
	if len(match) >= 2 {
		return string(match[1][:]), nil
	}

	return "", nil
}

// bindPciDeviceDriver binds driver to device in the follow flow:
// 0. make sure device already unbound to any driver
// 1. set sysfs device driver_override to target driver
// 2. try binding driver
// 3. clean up device driver_override
// 4. if driver_override failed, try to use sysfs driver/.../new_id to bind device
func bindPciDeviceDriver(devID, driver, vendor, device string) error {
	if err := overrideDriver(devID, driver); err == nil {
		defer cleanOverrideDriver(devID)

		// normal way to bind pci driver
		if err := writeToTargetWithData(pathSysPciDriversBind.With(driver), os.O_WRONLY, 0200, devID); err != nil {
			return err
		}

		if current, _ := GetCurrentPciDriver(devID); current != driver {
			return ErrBind
		}
		return nil
	}

	// NOTE if driver_override failed, it means kernel version is less than
	// 3.15, so we need to use sysfs drivers/.../new_id to bind device
	return addToDriver(devID, driver, vendor, device)
}

func unbindPciDeviceDriver(devID, driver string) error {
	// first trying write to pathSysPciDevicesUnbindWithDevID, if fails, try next, write to pathSysPciDriversUnbindWithDriver
	if err := writeToTargetWithData(pathSysPciDevicesUnbind.With(devID), os.O_WRONLY, 0200, devID); err != nil {
		if err := writeToTargetWithData(pathSysPciDriversUnbind.With(driver), os.O_WRONLY, 0200, devID); err != nil {
			return err
		}
	}

	// check if unbind success
	current, err := GetCurrentPciDriver(devID)
	if err != nil {
		return err
	}

	if current != "" {
		return ErrUnbind
	}

	return nil
}

func probePciDriver(devID string) error {
	return writeToTargetWithData(PathSysPciDriverProbe, os.O_WRONLY, 0200, devID)
}

func overrideDriver(devID, driver string) error {
	return writeToTargetWithData(pathSysPciDevicesOverrideDriver.With(devID), os.O_WRONLY|os.O_TRUNC, 0755, driver)
}

func cleanOverrideDriver(devID string) error {
	return overrideDriver(devID, "\x00")
}

func addToDriver(devID, driver, vendor, device string) error {
	// see https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-bus-pci
	// The format of the device ID is: VVVV DDDD SVVV SDDD CCCC MMMM PPPP.
	// VVVV Vendor ID
	// DDDD Device ID
	// SVVV Subsystem Vendor ID
	// SDDD ubsystem Device ID
	// CCCC Class
	// MMMM Class Mask
	// PPPP Private Driver Data
	return writeToTargetWithData(pathSysPciDriversNewID.With(driver), os.O_WRONLY, 0200, vendor+" "+device)
}
