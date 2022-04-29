// Package gocron : A Golang Job Scheduling Package.
//
// An in-process scheduler for periodic jobs that uses the builder pattern
// for configuration. gocron lets you run Golang functions periodically
// at pre-determined intervals using a simple, human-friendly syntax.
//
package gocron

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"runtime"
	"time"
)

// Error declarations for gocron related errors
var (
	ErrNotAFunction                  = errors.New("only functions can be scheduled into the job queue")
	ErrNotScheduledWeekday           = errors.New("job not scheduled weekly on a weekday")
	ErrJobNotFoundWithTag            = errors.New("no jobs found with given tag")
	ErrUnsupportedTimeFormat         = errors.New("the given time format is not supported")
	ErrInvalidInterval               = errors.New(".Every() interval must be greater than 0")
	ErrInvalidIntervalType           = errors.New(".Every() interval must be int, time.Duration, or string")
	ErrInvalidIntervalUnitsSelection = errors.New(".Every(time.Duration) and .Cron() cannot be used with units (e.g. .Seconds())")

	ErrAtTimeNotSupported               = errors.New("the At() method is not supported for this time unit")
	ErrWeekdayNotSupported              = errors.New("weekday is not supported for time unit")
	ErrInvalidDayOfMonthEntry           = errors.New("only days 1 through 28 are allowed for monthly schedules")
	ErrTagsUnique                       = func(tag string) error { return fmt.Errorf("a non-unique tag was set on the job: %s", tag) }
	ErrWrongParams                      = errors.New("wrong list of params")
	ErrUpdateCalledWithoutJob           = errors.New("a call to Scheduler.Update() requires a call to Scheduler.Job() first")
	ErrCronParseFailure                 = errors.New("cron expression failed to be parsed")
	ErrInvalidDaysOfMonthDuplicateValue = errors.New("duplicate days of month is not allowed in Month() and Months() methods")
)

func wrapOrError(toWrap error, err error) error {
	var returnErr error
	if toWrap != nil {
		returnErr = fmt.Errorf("%s: %w", err, toWrap)
	} else {
		returnErr = err
	}
	return returnErr
}

// regex patterns for supported time formats
var (
	timeWithSeconds    = regexp.MustCompile(`(?m)^\d{1,2}:\d\d:\d\d$`)
	timeWithoutSeconds = regexp.MustCompile(`(?m)^\d{1,2}:\d\d$`)
)

type schedulingUnit int

const (
	// default unit is seconds
	milliseconds schedulingUnit = iota
	seconds
	minutes
	hours
	days
	weeks
	months
	duration
	crontab
)

func callJobFuncWithParams(jobFunc interface{}, params []interface{}) {
	f := reflect.ValueOf(jobFunc)
	if len(params) != f.Type().NumIn() {
		return
	}
	in := make([]reflect.Value, len(params))
	for k, param := range params {
		in[k] = reflect.ValueOf(param)
	}
	f.Call(in)
}

func getFunctionName(fn interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
}

func parseTime(t string) (hour, min, sec int, err error) {
	var timeLayout string
	switch {
	case timeWithSeconds.Match([]byte(t)):
		timeLayout = "15:04:05"
	case timeWithoutSeconds.Match([]byte(t)):
		timeLayout = "15:04"
	default:
		return 0, 0, 0, ErrUnsupportedTimeFormat
	}

	parsedTime, err := time.Parse(timeLayout, t)
	if err != nil {
		return 0, 0, 0, ErrUnsupportedTimeFormat
	}
	return parsedTime.Hour(), parsedTime.Minute(), parsedTime.Second(), nil
}
