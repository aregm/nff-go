package devices

import (
	"fmt"
	"regexp"
)

const (
	DriverUioPciGeneric = "uio_pci_generic"
	DriverIgUio         = "ig_uio"
	DriverVfioPci       = "vfio-pci"
	DriverVfioPciKoName = "vfio_pci"
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

type StringBuilder string

func (s StringBuilder) With(args ...interface{}) string {
	return fmt.Sprintf(string(s), args...)
}

var (
	PathSysPciDevicesBind           StringBuilder = "/sys/bus/pci/devices/%s/driver/bind"
	PathSysPciDevicesUnbind         StringBuilder = "/sys/bus/pci/devices/%s/driver/unbind"
	PathSysPciDevicesOverrideDriver StringBuilder = "/sys/bus/pci/devices/%s/driver_override"

	PathSysPciDriversBind   StringBuilder = "/sys/bus/pci/drivers/%s/bind"
	PathSysPciDriversUnbind StringBuilder = "/sys/bus/pci/drivers/%s/unbind"
	PathSysPciDriversNewID  StringBuilder = "/sys/bus/pci/drivers/%s/new_id"
)

var (
	PathSysVmbusDriversBind   StringBuilder = "/sys/bus/vmbus/drivers/%s/bind"
	PathSysVmbusDriversUnbind StringBuilder = "/sys/bus/vmbus/drivers/%s/unbind"
	PathSysVmbusDriversNewID  StringBuilder = "/sys/bus/vmbus/drivers/%s/new_id"
)

var (
	PathSysClassNetDeviceDriver StringBuilder = "/sys/class/net/%s/device/driver"
	PathSysClassNetDevice       StringBuilder = "/sys/class/net/%s/device"
)

var (
	VmbusDeviceStringer StringBuilder = "ID: %s\nClass:\t%s\nDriver:\t%s"
	PciDeviceStringer   StringBuilder = "ID: %s\nClass:\t%s\nVendor:\t%s\nDevice:\t%s\nDriver:\t%s"
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
