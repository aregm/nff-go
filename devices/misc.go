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

func GetDeviceID(nicName string) (string, error) {
	// DEV_ID=$(basename $(readlink /sys/class/net/<nicName>/device))
	return readlinkBaseCmd(pathSysClassNetDevice.With(nicName))
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

func readlinkBaseCmd(path string) (string, error) {
	output, err := cmdOutputWithTimeout(defaultTimeoutLimitation, "readlink", path)
	if err != nil {
		return "", fmt.Errorf("Cmd Execute readlink failed: %s", err.Error())
	}
	outputStr := strings.Trim(string(output), "\n")
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
