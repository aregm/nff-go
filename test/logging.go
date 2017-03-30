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

type LogLevel int

const (
	LOG_OFF   LogLevel = iota
	LOG_PANIC          = LOG_OFF
	LOG_ERRORS
	LOG_WARNINGS
	LOG_INFO
	LOG_DEBUG
)

var loglevel LogLevel = LOG_WARNINGS

type Logger struct {
	logger *log.Logger
	file   *os.File
}

func LogPanic(v ...interface{}) {
	log.Panic(v...)
}

func LogErrorsIfNotNil(err error, v ...interface{}) {
	if loglevel >= LOG_ERRORS && err != nil {
		t := fmt.Sprintln(v...)
		log.Println("EE:", strings.TrimSpace(t), err)
	}
}

func LogError(v ...interface{}) {
	if loglevel >= LOG_ERRORS {
		t := fmt.Sprintln(v...)
		log.Println("EE:", t)
	}
}

func LogWarning(v ...interface{}) {
	if loglevel >= LOG_WARNINGS {
		t := fmt.Sprintln(v...)
		log.Println("WW:", t)
	}
}

func LogInfo(v ...interface{}) {
	if loglevel >= LOG_INFO {
		log.Println(v...)
	}
}

func LogDebug(v ...interface{}) {
	if loglevel >= LOG_DEBUG {
		t := fmt.Sprintln(v...)
		log.Print("DD: ", t)
	}
}

func SetLogLevel(ll LogLevel) {
	loglevel = ll
}

func NewLogger(output *os.File) *Logger {
	return &Logger{
		logger: log.New(output, "", log.LstdFlags),
		file:   output,
	}
}

func (l *Logger) LogPanic(v ...interface{}) {
	log.Panic(v...)
	l.logger.Panic(v...)
}

func (l *Logger) LogErrorsIfNotNil(err error, v ...interface{}) {
	if loglevel >= LOG_ERRORS && err != nil {
		t := fmt.Sprintln(v...)
		log.Println("EE:", strings.TrimSpace(t), err)
		l.logger.Println("EE:", strings.TrimSpace(t), err)
	}
}

func (l *Logger) LogError(v ...interface{}) {
	if loglevel >= LOG_ERRORS {
		t := fmt.Sprintln(v...)
		log.Println("EE:", t)
		l.logger.Println("EE:", t)
	}
}

func (l *Logger) LogWarning(v ...interface{}) {
	if loglevel >= LOG_WARNINGS {
		t := fmt.Sprintln(v...)
		log.Println("WW:", t)
		l.logger.Println("WW:", t)
	}
}

func (l *Logger) LogInfo(v ...interface{}) {
	if loglevel >= LOG_INFO {
		log.Println(v...)
		l.logger.Println(v...)
	}
}

func (l *Logger) LogDebug(v ...interface{}) {
	if loglevel >= LOG_DEBUG {
		t := fmt.Sprintln(v...)
		log.Print("DD: ", t)
		l.logger.Print("DD: ", t)
	}
}

func (l *Logger) String() string {
	fi, err := os.Lstat(l.file.Name())
	if err != nil {
		return ""
	} else {
		return fi.Name()
	}
}
