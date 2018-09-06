package devices

type Device interface {
	Bind(driver string) error
	Unbind() error
	CurrentDriver() (string, error)
	Probe() error
	Id() string
}

func NewDevices(devID string) (Device, error) {
	if IsPciID.Match([]byte(devID)) {
		return GetPciDeviceByPciID(devID)
	} else {
		return GetVmbusDeviceByUUID(devID)
	}
}

func NewDeviceWithPciID(pciID string) (Device, error) {
	device, err := GetPciDeviceByPciID(pciID)
	if err != nil {
		return nil, err
	}

	return device, nil
}

func NewDeviceWithUUID(uuid string) (Device, error) {
	device, err := GetVmbusDeviceByUUID(uuid)
	if err != nil {
		return nil, err
	}

	return device, nil
}

func NewDeviceByNicName(nicName string) (Device, error) {
	devID, err := GetDevID(nicName)
	if err != nil {
		return nil, err
	}

	device, err := NewDevices(devID)
	if err != nil {
		return nil, err
	}

	// setup devices by nicName
	return device, nil
}

func New(input string) (Device, error) {
	switch {
	case IsPciID.Match([]byte(input)):
		return NewDeviceWithPciID(input)
	case IsUUID.Match([]byte(input)):
		return NewDeviceWithUUID(input)
	default:
		return NewDeviceByNicName(input)
	}
}
