// Copyright 2021 Workrise Technologies Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package csplugin

import (
	"fmt"
	"io"
	"log"
	"os"
	"reflect"

	"github.com/hashicorp/go-hclog"
	"github.com/sirupsen/logrus"
)

// NewHCLogAdapter takes an instance of a Logrus logger and returns an hclog
// logger in the form of an HCLogAdapter.
func NewHCLogAdapter(l *logrus.Logger, name string) hclog.Logger {
	return &HCLogAdapter{l, name, nil}
}

// HCLogAdapter implements the hclog interface.  Plugins use hclog to send
// log entries back to ephemeral-iam and this adapter allows for those logs
// to be handled by ephemeral-iam's Logrus logger.
type HCLogAdapter struct {
	log  *logrus.Logger
	name string

	impliedArgs []interface{}
}

func (h HCLogAdapter) Log(level hclog.Level, msg string, args ...interface{}) {
	switch level {
	case hclog.NoLevel:
		return
	case hclog.Trace:
		h.Trace(msg, args...)
	case hclog.Debug:
		h.Debug(msg, args...)
	case hclog.Info:
		h.Info(msg, args...)
	case hclog.Warn:
		h.Warn(msg, args...)
	case hclog.Error:
		h.Error(msg, args...)
	}
}

func (h HCLogAdapter) Trace(msg string, args ...interface{}) {
	h.log.WithFields(toLogrusFields(args)).Trace(msg)
}

func (h HCLogAdapter) Debug(msg string, args ...interface{}) {
	h.log.WithFields(toLogrusFields(args)).Debug(msg)
}

func (h HCLogAdapter) Info(msg string, args ...interface{}) {
	h.log.WithFields(toLogrusFields(args)).Info(msg)
}

func (h HCLogAdapter) Warn(msg string, args ...interface{}) {
	h.log.WithFields(toLogrusFields(args)).Warn(msg)
}

func (h HCLogAdapter) Error(msg string, args ...interface{}) {
	h.log.WithFields(toLogrusFields(args)).Error(msg)
}

func (h HCLogAdapter) IsTrace() bool {
	return h.log.GetLevel() >= logrus.TraceLevel
}

func (h HCLogAdapter) IsDebug() bool {
	return h.log.GetLevel() >= logrus.DebugLevel
}

func (h HCLogAdapter) IsInfo() bool {
	return h.log.GetLevel() >= logrus.InfoLevel
}

func (h HCLogAdapter) IsWarn() bool {
	return h.log.GetLevel() >= logrus.WarnLevel
}

func (h HCLogAdapter) IsError() bool {
	return h.log.GetLevel() >= logrus.ErrorLevel
}

func (h HCLogAdapter) ImpliedArgs() []interface{} {
	// Not supported.
	return nil
}

func (h HCLogAdapter) With(args ...interface{}) hclog.Logger {
	return &h
}

func (h HCLogAdapter) Name() string {
	return h.name
}

func (h HCLogAdapter) Named(name string) hclog.Logger {
	return NewHCLogAdapter(h.log, name)
}

func (h HCLogAdapter) ResetNamed(name string) hclog.Logger {
	return &h
}

func (h *HCLogAdapter) SetLevel(level hclog.Level) {
	h.log.SetLevel(convertLevel(level))
}

func (h HCLogAdapter) StandardLogger(opts *hclog.StandardLoggerOptions) *log.Logger {
	if opts == nil {
		opts = &hclog.StandardLoggerOptions{}
	}
	return log.New(h.StandardWriter(opts), "", 0)
}

func (h HCLogAdapter) StandardWriter(opts *hclog.StandardLoggerOptions) io.Writer {
	return os.Stderr
}

// convertLevel maps hclog levels to Logrus levels.
func convertLevel(level hclog.Level) logrus.Level {
	switch level {
	case hclog.NoLevel:
		// Logrus does not have NoLevel, so use Info instead.
		return logrus.InfoLevel
	case hclog.Trace:
		return logrus.TraceLevel
	case hclog.Debug:
		return logrus.DebugLevel
	case hclog.Info:
		return logrus.InfoLevel
	case hclog.Warn:
		return logrus.WarnLevel
	case hclog.Error:
		return logrus.ErrorLevel
	default:
		return logrus.InfoLevel
	}
}

// toLogrusFields takes a list of key/value pairs passed to the hclog logger
// and converts them to a map to be used as Logrus fields.
func toLogrusFields(kvPairs []interface{}) map[string]interface{} {
	m := map[string]interface{}{}
	if len(kvPairs) == 0 {
		return m
	}

	if len(kvPairs)%2 == 1 {
		// There are an odd number of key/value pairs so append nil as the final value.
		kvPairs = append(kvPairs, nil)
	}

	for i := 0; i < len(kvPairs); i += 2 {
		// hclog automatically adds the timestamp field, ignore it.
		if kvPairs[i] != "timestamp" {
			merge(m, kvPairs[i], kvPairs[i+1])
		}
	}
	return m
}

// merge takes a key/value pair and converts them to strings then adds them to
// the dst map.
func merge(dst map[string]interface{}, k, v interface{}) {
	var key string

	switch x := k.(type) {
	case string:
		key = x
	case fmt.Stringer:
		key = safeString(x)
	default:
		key = fmt.Sprint(x)
	}

	dst[key] = v
}

// safeString takes an interface that implements the String() function and calls it
// to attempt to convert it to a string.  If a panic occurs, and it's caused by a
// nil pointer, the value will be set to "NULL".
func safeString(str fmt.Stringer) (s string) {
	defer func() {
		if panicVal := recover(); panicVal != nil {
			if v := reflect.ValueOf(str); v.Kind() == reflect.Ptr && v.IsNil() {
				s = "NULL"
			} else {
				panic(panicVal)
			}
		}
	}()

	s = str.String()
	return
}
