// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

// Pktgen commands constants
const (
	PktgenGetPortsNumberCommand = "io.write(string.format(\"%d\\n\", pktgen.portStats(\"all\", \"port\").n)); io.flush();"
	PktgenGetPortStatsCommand   = "stat = pktgen.portStats(\"all\", \"rate\");"
	PktgenPrintPortStatsCommand = "io.write(string.format(\"%%d %%d %%d %%d\\n\", stat[%d].pkts_tx, stat[%d].mbits_tx, stat[%d].pkts_rx, stat[%d].mbits_rx)); io.flush();"
	PktgenExitCommand           = "os.exit(0);"

	PktgenGetPortsNumberFormat = "%d"
	PktgenGetPortStatsFormat   = "%d %d %d %d"
)

// Test statuses regular expressions.
var (
	TestPassedRegexp = regexp.MustCompile(`^TEST PASSED$`)
	TestFailedRegexp = regexp.MustCompile(`^TEST FAILED$`)
	TestCoresRegexp  = regexp.MustCompile(`^DEBUG: System is using (\d+) cores now\. (\d+) cores are left available\.$`)
	TestPerfRegexp   = regexp.MustCompile(`^Output: Packets/sec\: (\d+) Mbits/sec\: (\d+)$`)
	ABStatsRegexps   = [4]*regexp.Regexp{
		regexp.MustCompile(`^Requests per second: *(\d+\.\d+) \[#/sec\] \(mean\)$`),
		regexp.MustCompile(`^Time per request: *(\d+\.\d+) \[ms\] \(mean\)$`),
		regexp.MustCompile(`^Time per request: *(\d+\.\d+) \[ms\] \(mean, across all concurrent requests\)$`),
		regexp.MustCompile(`^Transfer rate: *(\d+\.\d+) \[Kbytes/sec\] received$`),
	}
	LatStatsRegexps = [5]*regexp.Regexp{
		regexp.MustCompile(`received\/sent= *(\d+\.?\d*) %$`),
		regexp.MustCompile(`speed= *(\d+\.?\d*)$`),
		regexp.MustCompile(`median= *(\d+\.?\d*) μs$`),
		regexp.MustCompile(`average= *(\d+\.?\d*) μs$`),
		regexp.MustCompile(`stddev= *(\d+\.?\d*) μs$`),
	}
	WrkStatsRegexps = [2]*regexp.Regexp{
		regexp.MustCompile(`Requests/sec: *(\d+\.?\d*)$`),
		regexp.MustCompile(`Transfer/sec: *(\d+\.?\d*)([K|M|G|T|P])B$`),
	}
	unitScale = map[string]float64{
		"K": 1.0,
		"M": 1024.0,
		"G": 1024.0 * 1024.0,
		"T": 1024.0 * 1024.0 * 1024.0,
		"P": 1024.0 * 1024.0 * 1024.0 * 1024.0,
	}

	NoDeleteContainersOnExit = false
	username                 string
)

func init() {
	u, _ := user.Current()
	username = u.Username
	prefix, exists := os.LookupEnv("NFF_GO_IMAGE_PREFIX")
	if exists {
		username = prefix + "/" + username
	}
}

// RunningApp structure represents the app being run.
type RunningApp struct {
	index           int
	config          *AppConfig
	test            *TestConfig
	Status          TestStatus
	cl              *client.Client
	containerID     string
	dockerConfig    *DockerConfig
	PktgenBenchdata [][]PktgenMeasurement
	CoresStats      []CoresInfo
	abs             *ApacheBenchmarkStats
	lats            *LatencyStats
	wrks            *WrkBenchmarkStats
	Logger          *Logger
	benchStartTime  time.Time
	benchEndTime    time.Time
}

func (app *RunningApp) String() string {
	if app != nil {
		return fmt.Sprintf("%v:%v:%s", app.test, app.config, app.containerID)
	}
	return "nil"
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
		AppStatus: TestReportedFailed,
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
		app.Status = TestInvalid
		return
	}
	app.Status = TestRunning
	if app.config.Type == TestAppApacheBenchmark {
		app.abs = &ApacheBenchmarkStats{}
	} else if app.config.Type == TestAppLatency {
		app.lats = &LatencyStats{}
	} else if app.config.Type == TestAppWrkBenchmark {
		app.wrks = &WrkBenchmarkStats{}
	}

	scanner := bufio.NewScanner(logs)

	app.Logger.LogDebug("Trying to read logs from container", app.containerID)

	for scanner.Scan() {
		str := scanner.Text()
		status := app.Status

		if TestPassedRegexp.FindStringIndex(str) != nil {
			status = TestReportedPassed
		} else if TestFailedRegexp.FindStringIndex(str) != nil {
			status = TestReportedFailed
		} else {
			fillstats := func(stats []float64, rexps []*regexp.Regexp) {
				for iii := range rexps {
					matches := rexps[iii].FindStringSubmatch(str)
					if len(matches) >= 2 {
						var value float64
						n, err := fmt.Sscanf(matches[1], "%f", &value)
						if err == nil && n == 1 {
							stats[iii] = value
							if len(matches) == 3 {
								// Next match is unit letter
								stats[iii] *= unitScale[matches[2]]
							}
						}
					}
				}
			}
			fillstats2 := func(first *int64, second *int64, rexps *regexp.Regexp) bool {
				t := time.Now()
				if t.After(app.benchStartTime) && t.Before(app.benchEndTime) {
					matches := rexps.FindStringSubmatch(str)
					if len(matches) == 3 {
						n0, err0 := fmt.Sscanf(matches[1], "%d", first)
						n1, err1 := fmt.Sscanf(matches[2], "%d", second)
						if err0 == nil && err1 == nil && n0 == 1 && n1 == 1 {
							return true
						}
					}
				}
				return false
			}

			// Scan for strings specific to test application type
			if app.config.Type == TestAppGo {
				// Get cores number information for NFF-Go application
				var first, second int64
				if fillstats2(&first, &second, TestCoresRegexp) == true {
					app.CoresStats = append(app.CoresStats, CoresInfo{int(first), int(second)})
				}
			} else if app.config.Type == TestAppPerf {
				// Get cores number information for NFF-Go application
				var first, second int64
				if fillstats2(&first, &second, TestPerfRegexp) == true {
					app.PktgenBenchdata = append(app.PktgenBenchdata, []PktgenMeasurement{{0, 0, first, second}})
				}
			} else if app.config.Type == TestAppApacheBenchmark {
				// Get Apache Benchmark output
				fillstats(app.abs.Stats[:], ABStatsRegexps[:])
			} else if app.config.Type == TestAppLatency {
				// Get Latency perf test output
				fillstats(app.lats.Stats[:], LatStatsRegexps[:])
			} else if app.config.Type == TestAppWrkBenchmark {
				// Get Wrk Benchmark output
				fillstats(app.wrks.Stats[:], WrkStatsRegexps[:])
			}
		}

		finish := app.sendMessageOrFinish(str, status, report, done)

		if app.Status != TestRunning || finish {
			return
		}
	}

	if err = scanner.Err(); err != nil {
		app.sendErrorOrFinish(err, report, done)
	}
}

func (app *RunningApp) testPktgenRoutine(report chan<- TestReport, done <-chan struct{}, start bool) {
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
		writeData(PktgenExitCommand)
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

	// We need to wait a little bit, because connection will be active
	// even if pktgen hasn't launch yet (Docker opens port in advance).
	// This will lead to "connection reset by peer" error at read stage.
	time.Sleep(app.dockerConfig.PktgenDelay * time.Second)

	// First try to connect to pktgen
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	connectSpec := app.config.hp.host + ":" + strconv.Itoa(app.dockerConfig.PktgenPort)
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
	if writeData(PktgenGetPortsNumberCommand) {
		return
	}

	if readString() {
		return
	}

	_, err = fmt.Sscanf(str, PktgenGetPortsNumberFormat, &numberOfPorts)
	if err != nil {
		app.Logger.LogError("Failed to scan number of ports from pktgen", err)
		app.sendErrorOrFinish(err, report, done)
		sendExitCommand()
		return
	}
	app.Logger.LogDebug("Got number of ports", numberOfPorts)

	// Start generating packets on ports
	// If we don't start generating - this pktgen will be used for receiving and counting
	if start {
		app.Logger.LogDebug("Executing startup commands")
		for _, cmd := range app.test.BenchConf.StartCommands {
			if writeData(cmd) {
				return
			}
		}
	}

	// Gather statistics
	for {
		// Assign stat variable to an array of rates
		if writeData(PktgenGetPortStatsCommand) {
			return
		}

		bench := make([]PktgenMeasurement, numberOfPorts)
		for iii := 0; iii < numberOfPorts; iii++ {
			// Print rate for every port from the stat array
			str = fmt.Sprintf(PktgenPrintPortStatsCommand, iii, iii, iii, iii)
			if writeData(str) {
				return
			}

			if readString() {
				return
			}

			_, err = fmt.Sscanf(str, PktgenGetPortStatsFormat,
				&bench[iii].PktsTX, &bench[iii].MbitsTX, &bench[iii].PktsRX, &bench[iii].MbitsRX)
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
			app.PktgenBenchdata = append(app.PktgenBenchdata, bench)
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

// InitTest makes test initialization.
func (app *RunningApp) InitTest(logger *Logger, index int, config *AppConfig, dc *DockerConfig, test *TestConfig) {
	app.index = index
	app.config = config
	app.dockerConfig = dc
	app.test = test
	app.Status = TestCreated
	app.Logger = logger
}

func (app *RunningApp) startTest() error {
	defaultHeaders := map[string]string{"User-Agent": "engine-api-cli-1.0"}

	cl, err := client.NewClient("tcp://"+app.config.hp.host+":"+strconv.Itoa(app.config.hp.port),
		app.dockerConfig.DockerVersion, nil, defaultHeaders)
	app.Logger.LogDebug("Created client for", app, ", client =", cl, ", err =", err)

	if err != nil {
		app.Status = TestInvalid
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
		Image:     username + "/" + app.config.ImageName,
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
	app.Status = TestInitialized
	app.Logger.LogDebug("Created container for", app, ", response =", response, ", err =", err)

	if err != nil {
		app.Status = TestInvalid
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
		app.Status = TestInvalid
		return err
	}

	app.Status = TestRunning
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

	if app.Status == TestRunning {
		app.Logger.LogDebug("Trying to kill container for app", app)

		ctx, cancel := context.WithTimeout(context.Background(), app.dockerConfig.RequestTimeout)
		err = app.cl.ContainerKill(ctx, app.containerID, "INT")
		cancel()

		app.Logger.LogErrorsIfNotNil(err, "Error while killing container", &app)
	}

	if !NoDeleteContainersOnExit && (app.Status == TestInitialized || app.Status == TestRunning) {
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
