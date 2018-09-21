// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package devices helps to query DPDK compatibles devices and to bind/unbind drivers
package devices

import (
	"fmt"
	"os"
)

/*
   DEV_UUID=$(basename $(readlink /sys/class/net/eth1/device))

   # only on kernel 4.18 or later
   driverctl -b vmbus set-override $DEV_UUID uio_hv_generic

   # others
   modprobe uio_hv_generic
   NET_UUID="f8615163-df3e-46c5-913f-f2d2f965ed0e"
   echo $NET_UUID > /sys/bus/vmbus/drivers/uio_hv_generic/new_id // only run once
   echo $DEV_UUID > /sys/bus/vmbus/drivers/hv_netvsc/unbind
   echo $DEV_UUID > /sys/bus/vmbus/drivers/uio_hv_generic/bind
*/

type prepareFunc func() error

type vmbusDevice struct {
	UUID   string
	Driver string
}

// GetVmbusDeviceByUUID returns a VMBus device by given UUID.
func GetVmbusDeviceByUUID(uuid string) (Device, error) {
	result := &vmbusDevice{UUID: uuid}
	return result, nil
}

func (v *vmbusDevice) Bind(driver string) error {
	current, err := GetCurrentVmbusDriver(v.UUID)
	if err != nil {
		return fmt.Errorf("GetCurrentVmbusDriver: %s", err.Error())
	}
	var prepare prepareFunc

	switch current {
	case driver:
		// already binding the same driver, skip binding it
		return nil
	case "":
		// if not binding to any driver, continue to bind pci device driver
	default:
		// if there already binding to other driver, unbind it first
		prepare = func() error {
			if err := unbindVmbusDeviceDriver(v.UUID, current); err != nil {
				return fmt.Errorf("unbindVmbusDeviceDriver: %s", err.Error())
			}
			return nil
		}
	}

	if isValidDpdkVmbusDriver(driver) {
		if err := bindVmbusDeviceDpdkDriver(v.UUID, driver, prepare); err != nil {
			return fmt.Errorf("bindVmbusDeviceDriver: %s", err.Error())
		}
	} else {
		if err := bindVmbusDeviceDriver(v.UUID, driver, prepare); err != nil {
			return fmt.Errorf("bindVmbusDeviceDriver: %s", err.Error())
		}
	}

	// update Driver
	v.Driver = driver

	return nil
}

func (v *vmbusDevice) Unbind() error {
	current, err := GetCurrentVmbusDriver(v.UUID)
	if err != nil {
		return err
	}
	if current == "" {
		// NOTE: if no current vmbus driver, don't unbind it and don't return error
		return nil
	}
	return unbindVmbusDeviceDriver(v.UUID, current)
}

func (v *vmbusDevice) CurrentDriver() (string, error) {
	return GetCurrentVmbusDriver(v.UUID)
}

func (v *vmbusDevice) Probe() error {
	return ErrNotProbe
}

func (v *vmbusDevice) ID() string {
	return v.UUID
}

func (v *vmbusDevice) String() string {
	return vmbusDeviceStringer.With(v.UUID, v.Driver)
}

// GetCurrentVmbusDriver update the current driver device bound to.
func GetCurrentVmbusDriver(uuid string) (string, error) {
	output, err := cmdOutputWithTimeout(defaultTimeoutLimitation, "find", PathSysVmbusDrivers, "-type", "l", "-iname", uuid)
	if err != nil {
		return "", fmt.Errorf("Cmd Execute find failed: %s", err.Error())
	}

	matches := rVmbusDriver.FindSubmatch(output)
	if len(matches) >= 2 {
		return string(matches[1]), nil
	}

	return "", nil
}

func bindVmbusDeviceDriver(devUUID, driver string, prepares ...prepareFunc) error {
	for _, prepare := range prepares {
		if prepare == nil {
			continue
		}
		if err := prepare(); err != nil {
			return err
		}
	}
	return writeToTargetWithData(pathSysVmbusDriversBind.With(driver), os.O_WRONLY, 0200, devUUID)
}

func bindVmbusDeviceDpdkDriver(devUUID, driver string, prepares ...prepareFunc) error {
	// NOTE: ignore error of write vmbus driver new_id
	writeToTargetWithData(pathSysVmbusDriversNewID.With(driver), os.O_WRONLY, 0200, newNetUUID())
	return bindVmbusDeviceDriver(devUUID, driver, prepares...)
}

func unbindVmbusDeviceDriver(devUUID, driver string) error {
	return writeToTargetWithData(pathSysVmbusDriversUnbind.With(driver), os.O_WRONLY, 0200, devUUID)
}

func isValidDpdkVmbusDriver(driver string) bool {
	for _, dpdkDriver := range DpdkVmbusDrivers {
		if driver == dpdkDriver {
			return true
		}
	}
	return false
}

// newNetUUID returns a valid net UUID
// FIXME: Dummy implement, always return same result - see
// https://doc.dpdk.org/guides/nics/netvsc.html#installation NET_UUID
func newNetUUID() string {
	return "f8615163-df3e-46c5-913f-f2d2f965ed0e"
}

// bindVmbusDeviceDriverKernelGreaterThan418 is only available on linux kernel >= 4.18
// XXX: see https://doc.dpdk.org/guides/nics/netvsc.html#installation
func bindVmbusDeviceDriverKernelGreaterThan418(devUUID, driver string) error {
	// driverctl -b vmbus set-override $DEV_UUID uio_hv_generic
	_, err := cmdOutputWithTimeout(defaultTimeoutLimitation, "driverctl", "-b", "vmbus", "set-override", devUUID, driver)
	if err != nil {
		return fmt.Errorf("Cmd Execute driverctl failed: %s", err.Error())
	}
	return nil
}
