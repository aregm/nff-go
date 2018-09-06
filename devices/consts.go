package devices

import (
	"fmt"
	"regexp"
)

const (
	DriverHvNetvcs      = "hv_netvcs"
	DriverUioPciGeneric = "uio_pci_generic"
	DriverIgUio         = "ig_uio"
	DriverVfioPci       = "vfio-pci"
	DriverUioHvGeneric  = "uio_hv_generic"
)

const (
	PathSysPciDevices     = "/sys/bus/pci/devices"
	PathSysPciDrivers     = "/sys/bus/pci/drivers"
	PathSysPciDriverProbe = "/sys/bus/pci/drivers_probe"
)

const (
	PathSysVmbusDevices = "/sys/bus/vmbus/devices"
	PathSysVmbusDrivers = "/sys/bus/vmbus/drivers"
)

type stringBuilder string

func (s stringBuilder) With(args ...interface{}) string {
	return fmt.Sprintf(string(s), args...)
}

var (
	PathSysPciDevicesBind           stringBuilder = "/sys/bus/pci/devices/%s/driver/bind"
	PathSysPciDevicesUnbind         stringBuilder = "/sys/bus/pci/devices/%s/driver/unbind"
	PathSysPciDevicesOverrideDriver stringBuilder = "/sys/bus/pci/devices/%s/driver_override"

	PathSysPciDriversBind   stringBuilder = "/sys/bus/pci/drivers/%s/bind"
	PathSysPciDriversUnbind stringBuilder = "/sys/bus/pci/drivers/%s/unbind"
	PathSysPciDriversNewID  stringBuilder = "/sys/bus/pci/drivers/%s/new_id"
)

var (
	PathSysVmbusDriversBind   stringBuilder = "/sys/bus/vmbus/drivers/%s/bind"
	PathSysVmbusDriversUnbind stringBuilder = "/sys/bus/vmbus/drivers/%s/unbind"
	PathSysVmbusDriversNewID  stringBuilder = "/sys/bus/vmbus/drivers/%s/new_id"
)

var (
	PathSysClassNetDeviceDriver stringBuilder = "/sys/class/net/%s/device/driver"
	PathSysClassNetDevice       stringBuilder = "/sys/class/net/%s/device"
)

var (
	VmbusDeviceStringer stringBuilder = "ID: %s\nClass:\t%s\nDriver:\t%s"
	PciDeviceStringer   stringBuilder = "ID: %s\nClass:\t%s\nVendor:\t%s\nDevice:\t%s\nDriver:\t%s"
)

var (
	DefaultDpdkDriver = DriverUioPciGeneric
	DpdkDrivers       = [...]string{DriverUioPciGeneric, DriverIgUio, DriverVfioPci, DriverUioHvGeneric}
	DpdkPciDrivers    = [...]string{DriverUioPciGeneric, DriverIgUio, DriverVfioPci}
	DpdkVmbusDrivers  = [...]string{DriverUioHvGeneric}
)

var (
	// NOTE: this is for ethtool output
	rPciIDForEthtool *regexp.Regexp

	// NOTE: these is for lspci output
	rPciClass  *regexp.Regexp
	rPciVendor *regexp.Regexp
	rPciDevice *regexp.Regexp
	rPciDriver *regexp.Regexp

	rVmbusDriver *regexp.Regexp
)

var (
	IsPciID *regexp.Regexp
	IsUUID  *regexp.Regexp
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
