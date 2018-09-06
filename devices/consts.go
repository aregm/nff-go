package devices

import (
	"fmt"
	"regexp"
)

// Driver names
const (
	DriverHvNetvcs      = "hv_netvcs"
	DriverUioPciGeneric = "uio_pci_generic"
	DriverIgUio         = "ig_uio"
	DriverVfioPci       = "vfio-pci"
	DriverUioHvGeneric  = "uio_hv_generic"
)

// Path to PCI
const (
	PathSysPciDevices     = "/sys/bus/pci/devices"
	PathSysPciDrivers     = "/sys/bus/pci/drivers"
	PathSysPciDriverProbe = "/sys/bus/pci/drivers_probe"
)

// Path to VMBus
const (
	PathSysVmbusDevices = "/sys/bus/vmbus/devices"
	PathSysVmbusDrivers = "/sys/bus/vmbus/drivers"
)

// Path to net
const (
	PathSysClassNet = "/sys/class/net"
)

// Regular expressions for PCI-ID and UUID
var (
	IsPciID *regexp.Regexp
	IsUUID  *regexp.Regexp
)

// DPDK related drivers
var (
	DefaultDpdkDriver = DriverUioPciGeneric
	DpdkDrivers       = [...]string{DriverUioPciGeneric, DriverIgUio, DriverVfioPci, DriverUioHvGeneric}
	DpdkPciDrivers    = [...]string{DriverUioPciGeneric, DriverIgUio, DriverVfioPci}
	DpdkVmbusDrivers  = [...]string{DriverUioHvGeneric}
)

type stringBuilder string

func (s stringBuilder) With(args ...interface{}) string {
	return fmt.Sprintf(string(s), args...)
}

var (
	pathSysPciDevicesBind           stringBuilder = PathSysPciDevices + "/%s/driver/bind"
	pathSysPciDevicesUnbind         stringBuilder = PathSysPciDevices + "/%s/driver/unbind"
	pathSysPciDevicesOverrideDriver stringBuilder = PathSysPciDevices + "/%s/driver_override"

	pathSysPciDriversBind   stringBuilder = PathSysPciDrivers + "/%s/bind"
	pathSysPciDriversUnbind stringBuilder = PathSysPciDrivers + "/%s/unbind"
	pathSysPciDriversNewID  stringBuilder = PathSysPciDrivers + "/%s/new_id"
)

var (
	pathSysVmbusDriversBind   stringBuilder = PathSysVmbusDrivers + "/%s/bind"
	pathSysVmbusDriversUnbind stringBuilder = PathSysVmbusDrivers + "/%s/unbind"
	pathSysVmbusDriversNewID  stringBuilder = PathSysVmbusDrivers + "/%s/new_id"
)

var (
	pathSysClassNetDeviceDriver stringBuilder = PathSysClassNet + "/%s/device/driver"
	pathSysClassNetDevice       stringBuilder = PathSysClassNet + "/%s/device"
)

var (
	vmbusDeviceStringer stringBuilder = "ID: %s\nClass:\t%s\nDriver:\t%s"
	pciDeviceStringer   stringBuilder = "ID: %s\nClass:\t%s\nVendor:\t%s\nDevice:\t%s\nDriver:\t%s"
)

var (
	// for ethtool output
	rPciIDForEthtool *regexp.Regexp

	// for lspci output
	rPciClass  *regexp.Regexp
	rPciVendor *regexp.Regexp
	rPciDevice *regexp.Regexp
	rPciDriver *regexp.Regexp

	// for find output
	rVmbusDriver *regexp.Regexp
)

func init() {
	rPciIDForEthtool = regexp.MustCompile("bus-info:\\s([0-9:.]+)")

	rPciClass = regexp.MustCompile("[Cc]lass:\\s([0-9a-zA-Z]{4})")
	rPciVendor = regexp.MustCompile("[Vv]endor:\\s([0-9a-zA-Z]{4})")
	rPciDevice = regexp.MustCompile("[Dd]evice:\\s([0-9a-zA-Z]{4})")
	rPciDriver = regexp.MustCompile("[Dd]river:\\s(\\S+)")

	rVmbusDriver = regexp.MustCompile("/sys/bus/vmbus/drivers/(\\S+)/")

	IsPciID = regexp.MustCompile("^\\d{4}:\\d{2}:\\d{2}.\\d$")
	IsUUID = regexp.MustCompile("^[[:xdigit:]]{8}-[[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$")
}
