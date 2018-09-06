package devices

import (
	"errors"
)

var (
	ErrNoBoundDriver         = errors.New("No driver is bound to the device.")
	ErrAlreadyBoundDriver    = errors.New("Device is already bound to selected driver.")
	ErrBind                  = errors.New("Fail to bind driver.")
	ErrUnbind                = errors.New("Fail to unbind driver.")
	ErrUnsupportedDriver     = errors.New("Unsupported DPDK driver.")
	ErrNotProbe              = errors.New("Devices didn't support drive_probe.")
	ErrKernelModuleNotLoaded = errors.New("Kernel module not loaded.")
)
