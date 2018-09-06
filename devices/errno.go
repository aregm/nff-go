package devices

import (
	"errors"
)

// Errors of devices package
var (
	ErrNoBoundDriver         = errors.New("no driver is bound to the device")
	ErrAlreadyBoundDriver    = errors.New("device has already bound the selected driver")
	ErrBind                  = errors.New("fail to bind the driver")
	ErrUnbind                = errors.New("fail to unbind the driver")
	ErrUnsupportedDriver     = errors.New("unsupported DPDK driver")
	ErrNotProbe              = errors.New("device doesn't support 'drive_probe'")
	ErrKernelModuleNotLoaded = errors.New("kernel module is not loaded")
)
