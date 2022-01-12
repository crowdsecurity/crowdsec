package gocron

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"golang.org/x/sync/singleflight"
)

// Job struct stores the information necessary to run a Job
type Job struct {
	mu sync.RWMutex
	jobFunction
	interval          int            // pause interval * unit between runs
	duration          time.Duration  // time duration between runs
	unit              schedulingUnit // time units, e.g. 'minutes', 'hours'...
	startsImmediately bool           // if the Job should run upon scheduler start
	atTime            time.Duration  // optional time at which this Job runs when interval is day
	startAtTime       time.Time      // optional time at which the Job starts
	error             error          // error related to Job
	lastRun           time.Time      // datetime of last run
	nextRun           time.Time      // datetime of next run
	scheduledWeekdays []time.Weekday // Specific days of the week to start on
	daysOfTheMonth    []int          // Specific days of the month to run the job
	tags              []string       // allow the user to tag Jobs with certain labels
	runCount          int            // number of times the job ran
	timer             *time.Timer    // handles running tasks at specific time
	cronSchedule      cron.Schedule  // stores the schedule when a task uses cron
}

type jobFunction struct {
	function   interface{}         // task's function
	parameters []interface{}       // task's function parameters
	name       string              //nolint the function name to run
	runConfig  runConfig           // configuration for how many times to run the job
	limiter    *singleflight.Group // limits inflight runs of job to one
	ctx        context.Context     // for cancellation
	cancel     context.CancelFunc  // for cancellation
}

type runConfig struct {
	finiteRuns bool
	maxRuns    int
	mode       mode
}

// mode is the Job's running mode
type mode int8

const (
	// defaultMode disable any mode
	defaultMode mode = iota

	// singletonMode switch to single job mode
	singletonMode
)

// newJob creates a new Job with the provided interval
func newJob(interval int, startImmediately bool) *Job {
	ctx, cancel := context.WithCancel(context.Background())
	return &Job{
		interval: interval,
		unit:     seconds,
		lastRun:  time.Time{},
		nextRun:  time.Time{},
		jobFunction: jobFunction{
			ctx:    ctx,
			cancel: cancel,
		},
		tags:              []string{},
		startsImmediately: startImmediately,
	}
}

func (j *Job) neverRan() bool {
	return j.lastRun.IsZero()
}

func (j *Job) getStartsImmediately() bool {
	return j.startsImmediately
}

func (j *Job) setStartsImmediately(b bool) {
	j.startsImmediately = b
}

func (j *Job) setTimer(t *time.Timer) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.timer = t
}

func (j *Job) getAtTime() time.Duration {
	return j.atTime
}

func (j *Job) setAtTime(t time.Duration) {
	j.atTime = t
}

func (j *Job) getStartAtTime() time.Time {
	return j.startAtTime
}

func (j *Job) setStartAtTime(t time.Time) {
	j.startAtTime = t
}

func (j *Job) getUnit() schedulingUnit {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.unit
}

func (j *Job) setUnit(t schedulingUnit) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.unit = t
}

func (j *Job) getDuration() time.Duration {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.duration
}

func (j *Job) setDuration(t time.Duration) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.duration = t
}

// Error returns an error if one occurred while creating the Job.
// If multiple errors occurred, they will be wrapped and can be
// checked using the standard unwrap options.
func (j *Job) Error() error {
	return j.error
}

// Tag allows you to add arbitrary labels to a Job that do not
// impact the functionality of the Job
func (j *Job) Tag(tags ...string) {
	j.tags = append(j.tags, tags...)
}

// Untag removes a tag from a Job
func (j *Job) Untag(t string) {
	var newTags []string
	for _, tag := range j.tags {
		if t != tag {
			newTags = append(newTags, tag)
		}
	}

	j.tags = newTags
}

// Tags returns the tags attached to the Job
func (j *Job) Tags() []string {
	return j.tags
}

// ScheduledTime returns the time of the Job's next scheduled run
func (j *Job) ScheduledTime() time.Time {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.nextRun
}

// ScheduledAtTime returns the specific time of day the Job will run at
func (j *Job) ScheduledAtTime() string {
	return fmt.Sprintf("%d:%d", j.atTime/time.Hour, (j.atTime%time.Hour)/time.Minute)
}

// Weekday returns which day of the week the Job will run on and
// will return an error if the Job is not scheduled weekly
func (j *Job) Weekday() (time.Weekday, error) {
	if len(j.scheduledWeekdays) == 0 {
		return time.Sunday, ErrNotScheduledWeekday
	}
	return j.scheduledWeekdays[0], nil
}

// Weekdays returns a slice of time.Weekday that the Job will run in a week and
// will return an error if the Job is not scheduled weekly
func (j *Job) Weekdays() []time.Weekday {
	// appending on j.scheduledWeekdays may cause a side effect
	if len(j.scheduledWeekdays) == 0 {
		return []time.Weekday{time.Sunday}
	}

	return j.scheduledWeekdays
}

// LimitRunsTo limits the number of executions of this job to n.
// Upon reaching the limit, the job is removed from the scheduler.
//
// Note: If a job is added to a running scheduler and this method is then used
// you may see the job run more than the set limit as job is scheduled immediately
// by default upon being added to the scheduler. It is recommended to use the
// LimitRunsTo() func on the scheduler chain when scheduling the job.
// For example: scheduler.LimitRunsTo(1).Do()
func (j *Job) LimitRunsTo(n int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.runConfig.finiteRuns = true
	j.runConfig.maxRuns = n
}

// SingletonMode prevents a new job from starting if the prior job has not yet
// completed it's run
// Note: If a job is added to a running scheduler and this method is then used
// you may see the job run overrun itself as job is scheduled immediately
// by default upon being added to the scheduler. It is recommended to use the
// SingletonMode() func on the scheduler chain when scheduling the job.
func (j *Job) SingletonMode() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.runConfig.mode = singletonMode
	j.jobFunction.limiter = &singleflight.Group{}

}

// shouldRun evaluates if this job should run again
// based on the runConfig
func (j *Job) shouldRun() bool {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return !j.runConfig.finiteRuns || j.runCount < j.runConfig.maxRuns
}

// LastRun returns the time the job was run last
func (j *Job) LastRun() time.Time {
	return j.lastRun
}

func (j *Job) setLastRun(t time.Time) {
	j.lastRun = t
}

// NextRun returns the time the job will run next
func (j *Job) NextRun() time.Time {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.nextRun
}

func (j *Job) setNextRun(t time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.nextRun = t
}

// RunCount returns the number of time the job ran so far
func (j *Job) RunCount() int {
	return j.runCount
}

func (j *Job) stop() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.timer != nil {
		j.timer.Stop()
	}
	j.cancel()
}
