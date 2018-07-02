package utils

import (
	"fmt"
	"log"
	"os"
)

var LOG_FILE_PATH = "log/dp.log"

type LogType uint8

const (
	// No - no output even after fatal errors
	No LogType = 1 << iota
	// Initialization - output during system initialization
	Info
	// Debug - output during execution one time per time period (scheduler ticks)
	Debug
	// Verbose - output during execution as soon as something happens. Can influence performance
	Warning
)

var currentLogType = No | Info | Debug

var (
	logger *log.Logger
)

func init() {
	
	if _, err := os.Stat("log"); os.IsNotExist(err) {
	          os.Mkdir("log", 0666)
	}

	file, err := os.OpenFile(LOG_FILE_PATH, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("Failed to open log file file.log : ", err)
		os.Exit(1)
	}

	logger = log.New(file, "", log.Ldate|log.Ltime)
}

func SetLogType(logType LogType) {
	currentLogType = logType
}

// LogFatal internal, used in all packages
func LogFatal(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		logger.Fatal("ERROR: ", t)
	}
	os.Exit(1)
}

// LogError internal, used in all packages
func LogError(logType LogType, v ...interface{}) string {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		logger.Print("ERROR: ", t)
		return t
	}
	return ""
}

// LogWarning internal, used in all packages
func LogWarning(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		logger.Print("WARNING: ", t)
	}
}

// LogDebug internal, used in all packages
func LogDebug(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		logger.Print("DEBUG: ", t)
	}
}
func LogInfo(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		logger.Print("INFO: ", t)
	}
}

// LogDrop internal, used in all packages
func LogDrop(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		t := fmt.Sprintln(v...)
		logger.Print("DROP: ", t)
	}
}

// LogTitle internal, used in all packages
func LogTitle(logType LogType, v ...interface{}) {
	if logType&currentLogType != 0 {
		logger.Print(v...)
	}
}
