// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package devices helps to query DPDK compatibles devices and to bind/unbind drivers
package devices

// Device is a DPDK compatible device and should be able to bind, unbind and
// probe.
type Device interface {
	// Binds a driver to the device
	Bind(driver string) error
	// Unbinds the current driver from the device
	Unbind() error
	// Returns the name of the driver that is currently bound
	CurrentDriver() (string, error)
	// Probes the currently bound driver and checks if there is an error
	Probe() error
	// Returns the ID of the device
	ID() string
}

// New returns a corresponding device by given input
func New(input string) (Device, error) {
	switch {
	case IsPciID.Match([]byte(input)):
		return NewDeviceByPciID(input)
	case IsUUID.Match([]byte(input)):
		return NewDeviceByVmbusID(input)
	default:
		return NewDeviceByNicName(input)
	}
}

// NewDeviceByPciID returns a PCI device by given PCI ID
func NewDeviceByPciID(pciID string) (Device, error) {
	device, err := GetPciDeviceByPciID(pciID)
	if err != nil {
		return nil, err
	}

	return device, nil
}

// NewDeviceByVmbusID returns a VMBus device by given UUID
func NewDeviceByVmbusID(uuid string) (Device, error) {
	device, err := GetVmbusDeviceByUUID(uuid)
	if err != nil {
		return nil, err
	}

	return device, nil
}

// NewDeviceByNicName returns a device by given NIC name, e.g. eth0.
func NewDeviceByNicName(nicName string) (Device, error) {
	devID, err := GetDeviceID(nicName)
	if err != nil {
		return nil, err
	}

	device, err := newDevice(devID)
	if err != nil {
		return nil, err
	}

	return device, nil
}

func newDevice(id string) (Device, error) {
	if IsPciID.Match([]byte(id)) {
		return GetPciDeviceByPciID(id)
	}
	return GetVmbusDeviceByUUID(id)
}
