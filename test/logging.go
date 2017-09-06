// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// LogLevel is a type indicating the level of logging.
type LogLevel int

// Constants for different log levels.
const (
	LogOffLvl   LogLevel = iota
	LogPanicLvl          = LogOffLvl
	LogErrorsLvl
	LogWarningsLvl
	LogInfoLvl
	LogDebugLvl
)

var loglevel = LogWarningsLvl

// Logger type contains a logging object that generates lines of
// output to an io.Writer and file for logging.
type Logger struct {
	logger *log.Logger
	file   *os.File
}

// LogPanic prints error and calls panic.
func LogPanic(v ...interface{}) {
	log.Panic(v...)
}

// LogErrorsIfNotNil logs if level is equal to or higher than
// LogErrorsLvl if error is not nil.
func LogErrorsIfNotNil(err error, v ...interface{}) {
	if loglevel >= LogErrorsLvl && err != nil {
		t := fmt.Sprintln(v...)
		log.Println("EE:", strings.TrimSpace(t), err)
	}
}

// LogError logs if level is is equal to or higher than LogErrorsLvl.
func LogError(v ...interface{}) {
	if loglevel >= LogErrorsLvl {
		t := fmt.Sprintln(v...)
		log.Println("EE:", t)
	}
}

// LogWarning logs if level is is equal to or higher than LogWarningsLvl.
func LogWarning(v ...interface{}) {
	if loglevel >= LogWarningsLvl {
		t := fmt.Sprintln(v...)
		log.Println("WW:", t)
	}
}

// LogInfo logs if level is is equal to or higher than LogInfoLvl.
func LogInfo(v ...interface{}) {
	if loglevel >= LogInfoLvl {
		log.Println(v...)
	}
}

// LogDebug logs if level is is equal to or higher than LogDebugLvl.
func LogDebug(v ...interface{}) {
	if loglevel >= LogDebugLvl {
		t := fmt.Sprintln(v...)
		log.Print("DD: ", t)
	}
}

// SetLogLevel sets a log level to given value.
func SetLogLevel(ll LogLevel) {
	loglevel = ll
}

// NewLogger creates and returns a new Logger object
// initialized with file for output.
func NewLogger(output *os.File) *Logger {
	return &Logger{
		logger: log.New(output, "", log.LstdFlags),
		file:   output,
	}
}

// LogPanic prints error and calls panic.
func (l *Logger) LogPanic(v ...interface{}) {
	log.Panic(v...)
	l.logger.Panic(v...)
}

// LogErrorsIfNotNil logs if level is equal to or higher than
// LogErrorsLvl if error is not nil.
func (l *Logger) LogErrorsIfNotNil(err error, v ...interface{}) {
	if loglevel >= LogErrorsLvl && err != nil {
		t := fmt.Sprintln(v...)
		log.Println("EE:", strings.TrimSpace(t), err)
		l.logger.Println("EE:", strings.TrimSpace(t), err)
	}
}

// LogError logs if level is is equal to or higher than LogErrorsLvl.
// Logs to standard output and to file in l.
func (l *Logger) LogError(v ...interface{}) {
	if loglevel >= LogErrorsLvl {
		t := fmt.Sprintln(v...)
		log.Println("EE:", t)
		l.logger.Println("EE:", t)
	}
}

// LogWarning logs if level is is equal to or higher than LogWarningsLvl.
// Logs to standard output and to file in l.
func (l *Logger) LogWarning(v ...interface{}) {
	if loglevel >= LogWarningsLvl {
		t := fmt.Sprintln(v...)
		log.Println("WW:", t)
		l.logger.Println("WW:", t)
	}
}

// LogInfo logs if level is is equal to or higher than LogInfoLvl.
// Logs to standard output and to file in l.
func (l *Logger) LogInfo(v ...interface{}) {
	if loglevel >= LogInfoLvl {
		log.Println(v...)
		l.logger.Println(v...)
	}
}

// LogDebug logs if level is is equal to or higher than LogDebugLvl.
// Logs to standard output and to file in l.
func (l *Logger) LogDebug(v ...interface{}) {
	if loglevel >= LogDebugLvl {
		t := fmt.Sprintln(v...)
		log.Print("DD: ", t)
		l.logger.Print("DD: ", t)
	}
}

// Returns the name of the file set for logging or empty string if it exists.
func (l *Logger) String() string {
	fi, err := os.Lstat(l.file.Name())
	if err != nil {
		return ""
	}
	return fi.Name()
}
