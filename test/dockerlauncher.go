// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

const (
	PKTGEN_GET_PORTS_NUMBER_COMMAND = "printf(\"%d\\n\", pktgen.portStats(\"all\", \"port\").n);"
	PKTGEN_GET_PORT_STARTS_COMMAND  = "stat = pktgen.portStats(\"all\", \"rate\");"
	PKTGEN_PRINT_PORT_STATS_COMMAND = "printf(\"%%d %%d %%d %%d\\n\", stat[%d].pkts_tx, stat[%d].mbits_tx, stat[%d].pkts_rx, stat[%d].mbits_rx);"
	PKTGEN_EXIT_COMMAND             = "os.exit(0);"

	PKTGET_GET_PORTS_NUMBER_FORMAT = "%d"
	PKTGEN_GET_PORT_STARTS_FORMAT  = "%d %d %d %d"
)

var (
	TEST_PASSED_REGEXP = regexp.MustCompile(`^TEST PASSED$`)
	TEST_FAILED_REGEXP = regexp.MustCompile(`^TEST FAILED$`)
	TEST_CORES_REGEXP  = regexp.MustCompile(`^DEBUG: System is using (\d+) cores now\. (\d+) cores are left available\.$`)

	DeleteContainersOnExit = true
)

type Measurement struct {
	Pkts_TX, Mbits_TX, Pkts_RX, Mbits_RX int64
}

type CoresInfo struct {
	CoresUsed, CoresFree int
}

type TestReport struct {
	AppIndex  int
	AppStatus TestStatus
	msg       string
}

type RunningApp struct {
	index          int
	config         *AppConfig
	test           *TestConfig
	Status         TestStatus
	cl             *client.Client
	containerID    string
	dockerConfig   *DockerConfig
	Benchmarks     [][]Measurement
	CoresStats     []CoresInfo
	Logger         *Logger
	benchStartTime time.Time
	benchEndTime   time.Time
}

func (app *RunningApp) String() string {
	return fmt.Sprintf("%v:%v:%s", app.test, app.config, app.containerID)
}

func (app *RunningApp) sendMessageOrFinish(str string, status TestStatus, report chan<- TestReport, done <-chan struct{}) (finish bool) {
	r := TestReport{
		AppIndex:  app.index,
		AppStatus: status,
		msg:       str,
	}

	select {
	case <-done:
		app.Logger.LogInfo("Cancelled test app", app)
		return true
	case report <- r:
		return false
	}
}

func (app *RunningApp) sendErrorOrFinish(err error, report chan<- TestReport, done <-chan struct{}) {
	r := TestReport{
		AppIndex:  app.index,
		AppStatus: TEST_REPORTED_FAILED,
		msg:       err.Error(),
	}

	select {
	case <-done:
		app.Logger.LogError("Cancelled test app while sending error", app, err)
	case report <- r:
	}
}

func (app *RunningApp) testRoutine(report chan<- TestReport, done <-chan struct{}) {
	logOptions := types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Timestamps: false,
		Details:    false,
		Follow:     true,
	}

	logs, err := app.cl.ContainerLogs(context.Background(), app.containerID, logOptions)
	defer logs.Close()
	if err != nil {
		app.Logger.LogError("Failed to get logs from ", app, ":", err)
		app.Status = TEST_INVALID
		return
	} else {
		app.Status = TEST_RUNNING
	}

	scanner := bufio.NewScanner(logs)

	app.Logger.LogDebug("Trying to read logs from container", app.containerID)

	for scanner.Scan() {
		str := scanner.Text()
		status := app.Status

		if TEST_PASSED_REGEXP.FindStringIndex(str) != nil {
			status = TEST_REPORTED_PASSED
		} else if TEST_FAILED_REGEXP.FindStringIndex(str) != nil {
			status = TEST_REPORTED_FAILED
		} else {
			t := time.Now()
			if t.After(app.benchStartTime) && t.Before(app.benchEndTime) {
				matches := TEST_CORES_REGEXP.FindStringSubmatch(str)
				if len(matches) == 3 {
					var c CoresInfo
					c.CoresUsed, err = strconv.Atoi(matches[1])
					if err == nil {
						c.CoresFree, err = strconv.Atoi(matches[2])
						if err == nil {
							app.CoresStats = append(app.CoresStats, c)
						}
					}
				}
			}
		}

		finish := app.sendMessageOrFinish(str, status, report, done)

		if app.Status != TEST_RUNNING || finish {
			return
		}
	}

	if err = scanner.Err(); err != nil {
		app.sendErrorOrFinish(err, report, done)
	}
}

func (app *RunningApp) testPktgenRoutine(report chan<- TestReport, done <-chan struct{}) {
	var connection net.Conn
	var err error
	var scanner *bufio.Scanner
	var str string

	writeData := func(command string) bool {
		if app.sendMessageOrFinish(command, app.Status, report, done) {
			return true
		}

		_, err := connection.Write([]byte(command + "\n"))
		if err != nil {
			app.sendErrorOrFinish(err, report, done)
			return true
		}
		return false
	}

	sendExitCommand := func() {
		// We don't care whether writeData returns to finish or not
		// because after this call this goroutine is exiting anyway
		writeData(PKTGEN_EXIT_COMMAND)
	}

	readString := func() bool {
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				app.sendErrorOrFinish(err, report, done)
				sendExitCommand()
				return true
			}
		}

		str = scanner.Text()
		app.Logger.LogDebug("Read from socket '", str, "'")
		if app.sendMessageOrFinish(str, app.Status, report, done) {
			sendExitCommand()
			return true
		}

		return false
	}

	// First try to connect to pktgen
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	connectSpec := app.config.HostName + ":" + strconv.Itoa(app.dockerConfig.PktgenPort)
	for {
		connection, err = net.Dial("tcp", connectSpec)

		if err == nil {
			break
		}

		select {
		case <-ticker.C:
		case <-done:
			app.Logger.LogInfo("Cancelled test app before connection to pktgen could be established", app)
			return
		}
	}
	defer connection.Close()

	scanner = bufio.NewScanner(connection)

	// Get number of ports seen by pktgen
	var numberOfPorts int
	if writeData(PKTGEN_GET_PORTS_NUMBER_COMMAND) {
		return
	}

	if readString() {
		return
	}

	_, err = fmt.Sscanf(str, PKTGET_GET_PORTS_NUMBER_FORMAT, &numberOfPorts)
	if err != nil {
		app.Logger.LogError("Failed to scan number of ports from pktgen", err)
		app.sendErrorOrFinish(err, report, done)
		sendExitCommand()
		return
	}
	app.Logger.LogDebug("Got number of ports", numberOfPorts)

	// Start generating packets on ports
	app.Logger.LogDebug("Executing startup commands")
	for _, cmd := range app.test.BenchConf.StartCommands {
		if writeData(cmd) {
			return
		}
	}

	// Gather statistics
	for {
		// Assign stat variable to an array of rates
		if writeData(PKTGEN_GET_PORT_STARTS_COMMAND) {
			return
		}

		bench := make([]Measurement, numberOfPorts)
		for iii := 0; iii < numberOfPorts; iii++ {
			// Print rate for every port from the stat array
			str = fmt.Sprintf(PKTGEN_PRINT_PORT_STATS_COMMAND, iii, iii, iii, iii)
			if writeData(str) {
				return
			}

			if readString() {
				return
			}

			_, err = fmt.Sscanf(str, PKTGEN_GET_PORT_STARTS_FORMAT,
				&bench[iii].Pkts_TX, &bench[iii].Mbits_TX, &bench[iii].Pkts_RX, &bench[iii].Mbits_RX)
			if err != nil {
				app.Logger.LogError("Failed to scan port", iii, "stats from pktgen", err)
				app.sendErrorOrFinish(err, report, done)
				sendExitCommand()
				return
			}
		}

		t := time.Now()
		if t.After(app.benchStartTime) && t.Before(app.benchEndTime) {
			// Put a new measurement into measurement array
			app.Benchmarks = append(app.Benchmarks, bench)
		}

		select {
		case <-ticker.C:
		case <-done:
			app.Logger.LogInfo("Cancelled test app", app)
			sendExitCommand()
			return
		}
	}
}

func (app *RunningApp) InitTest(logger *Logger, index int, config *AppConfig, dc *DockerConfig, test *TestConfig) {
	app.index = index
	app.config = config
	app.dockerConfig = dc
	app.test = test
	app.Status = TEST_CREATED
	app.Logger = logger
}

func (app *RunningApp) startTest() error {
	defaultHeaders := map[string]string{"User-Agent": "engine-api-cli-1.0"}

	cl, err := client.NewClient("tcp://"+app.config.HostName+":"+strconv.Itoa(app.dockerConfig.DockerPort),
		app.dockerConfig.DockerVersion, nil, defaultHeaders)
	app.Logger.LogDebug("Created client for", app, ", client =", cl, ", err =", err)

	if err != nil {
		app.Status = TEST_INVALID
		return err
	}
	app.cl = cl

	ctx, cancel := context.WithTimeout(context.Background(), app.dockerConfig.RequestTimeout)

	strport := strconv.Itoa(app.dockerConfig.PktgenPort)
	config := container.Config{
		// Same as --interactive switch
		AttachStdin: true,
		// Same as -p 0.0.0.0:22022:22022/tcp switch
		ExposedPorts: map[nat.Port]struct{}{
			nat.Port(strport + "/tcp"): {},
		},
		Tty: true,
		// Same as --interactive switch
		OpenStdin: true,
		Cmd:       app.config.CommandLine,
		Image:     app.config.ImageName,
	}

	hostConfig := container.HostConfig{
		// Same as
		// -v /sys/bus/pci/drivers:/sys/bus/pci/drivers
		// -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages
		// -v /sys/devices/system/node:/sys/devices/system/node
		// -v /dev:/dev switches
		Binds: app.dockerConfig.Volumes,
		// Same as -p 0.0.0.0:22022:22022/tcp switch
		PortBindings: nat.PortMap{
			nat.Port(strport + "/tcp"): []nat.PortBinding{
				{
					HostIP:   "0.0.0.0",
					HostPort: strport,
				},
			},
		},
		// Same as to --privileged switch
		Privileged: app.dockerConfig.Privileged,
		// Same as to -P switch
		PublishAllPorts: true,
	}
	response, err := app.cl.ContainerCreate(ctx, &config, &hostConfig, nil, "")
	cancel()
	app.containerID = response.ID
	app.Status = TEST_INITIALIZED
	app.Logger.LogDebug("Created container for", app, ", response =", response, ", err =", err)

	if err != nil {
		app.Status = TEST_INVALID
		return err
	}

	for _, w := range response.Warnings {
		app.Logger.LogWarning("Warning for test app", app, ":", w)
	}

	ctx, cancel = context.WithTimeout(context.Background(), app.dockerConfig.RequestTimeout)
	options := types.ContainerStartOptions{CheckpointID: ""}
	err = app.cl.ContainerStart(ctx, app.containerID, options)
	cancel()
	app.Logger.LogDebug("Started container for", app, "err =", err)

	if err != nil {
		app.Status = TEST_INVALID
		return err
	} else {
		app.Status = TEST_RUNNING
	}

	t := time.Now()
	app.benchStartTime = t.Add(app.test.BenchConf.MeasureAfter)
	if app.test.BenchConf.MeasureFor > 0 {
		app.benchEndTime = app.benchStartTime.Add(app.test.BenchConf.MeasureFor)
	} else {
		app.benchEndTime = app.benchStartTime.Add(app.test.TestTime)
	}

	return nil
}

func killAllRunningAndRemoveData(apps []RunningApp) {
	for iii := range apps {
		killRunningAppAndRemoveData(&apps[iii])
	}
}

func killRunningAppAndRemoveData(app *RunningApp) {
	var err error

	if app.Status == TEST_RUNNING {
		app.Logger.LogDebug("Trying to kill container for app", app)

		ctx, cancel := context.WithTimeout(context.Background(), app.dockerConfig.RequestTimeout)
		err = app.cl.ContainerKill(ctx, app.containerID, "INT")
		cancel()

		app.Logger.LogErrorsIfNotNil(err, "Error while killing container", &app)
	}

	if DeleteContainersOnExit && (app.Status == TEST_INITIALIZED || app.Status == TEST_RUNNING) {
		app.Logger.LogDebug("Trying to remove container for app", app)

		ctx, cancel := context.WithTimeout(context.Background(), app.dockerConfig.RequestTimeout)
		options := types.ContainerRemoveOptions{
			RemoveVolumes: false,
			RemoveLinks:   false,
			Force:         true,
		}
		err = app.cl.ContainerRemove(ctx, app.containerID, options)
		cancel()

		app.Logger.LogErrorsIfNotNil(err, "Error while removing container", &app)
	}
}
