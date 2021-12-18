package gocron

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"golang.org/x/sync/semaphore"
)

type limitMode int8

// Scheduler struct stores a list of Jobs and the location of time used by the Scheduler,
// and implements the sort.Interface{} for sorting Jobs, by the time of nextRun
type Scheduler struct {
	jobsMutex sync.RWMutex
	jobs      []*Job

	locationMutex sync.RWMutex
	location      *time.Location
	runningMutex  sync.RWMutex
	running       bool // represents if the scheduler is running at the moment or not

	time     timeWrapper // wrapper around time.Time
	executor *executor   // executes jobs passed via chan

	tags sync.Map // for storing tags when unique tags is set

	tagsUnique      bool // defines whether tags should be unique
	updateJob       bool // so the scheduler knows to create a new job or update the current
	waitForInterval bool // defaults jobs to waiting for first interval to start
	jobCreated      bool // so the scheduler knows a job was created prior to calling Every or Cron
}

// days in a week
const allWeekDays = 7

// NewScheduler creates a new Scheduler
func NewScheduler(loc *time.Location) *Scheduler {
	executor := newExecutor()

	return &Scheduler{
		jobs:       make([]*Job, 0),
		location:   loc,
		running:    false,
		time:       &trueTime{},
		executor:   &executor,
		tagsUnique: false,
	}
}

// SetMaxConcurrentJobs limits how many jobs can be running at the same time.
// This is useful when running resource intensive jobs and a precise start time is not critical.
func (s *Scheduler) SetMaxConcurrentJobs(n int, mode limitMode) {
	s.executor.maxRunningJobs = semaphore.NewWeighted(int64(n))
	s.executor.limitMode = mode
}

// StartBlocking starts all jobs and blocks the current thread
func (s *Scheduler) StartBlocking() {
	s.StartAsync()
	<-make(chan bool)
}

// StartAsync starts all jobs without blocking the current thread
func (s *Scheduler) StartAsync() {
	if !s.IsRunning() {
		s.start()
	}
}

//start starts the scheduler, scheduling and running jobs
func (s *Scheduler) start() {
	go s.executor.start()
	s.setRunning(true)
	s.runJobs(s.Jobs())
}

func (s *Scheduler) runJobs(jobs []*Job) {
	for _, job := range jobs {
		s.scheduleNextRun(job)
	}
}

func (s *Scheduler) setRunning(b bool) {
	s.runningMutex.Lock()
	defer s.runningMutex.Unlock()
	s.running = b
}

// IsRunning returns true if the scheduler is running
func (s *Scheduler) IsRunning() bool {
	s.runningMutex.RLock()
	defer s.runningMutex.RUnlock()
	return s.running
}

// Jobs returns the list of Jobs from the Scheduler
func (s *Scheduler) Jobs() []*Job {
	s.jobsMutex.RLock()
	defer s.jobsMutex.RUnlock()
	return s.jobs
}

func (s *Scheduler) setJobs(jobs []*Job) {
	s.jobsMutex.Lock()
	defer s.jobsMutex.Unlock()
	s.jobs = jobs
}

// Len returns the number of Jobs in the Scheduler - implemented for sort
func (s *Scheduler) Len() int {
	s.jobsMutex.RLock()
	defer s.jobsMutex.RUnlock()
	return len(s.jobs)
}

// Swap places each job into the other job's position given
// the provided job indexes.
func (s *Scheduler) Swap(i, j int) {
	s.jobsMutex.Lock()
	defer s.jobsMutex.Unlock()
	s.jobs[i], s.jobs[j] = s.jobs[j], s.jobs[i]
}

// Less compares the next run of jobs based on their index.
// Returns true if the second job is after the first.
func (s *Scheduler) Less(first, second int) bool {
	return s.Jobs()[second].NextRun().Unix() >= s.Jobs()[first].NextRun().Unix()
}

// ChangeLocation changes the default time location
func (s *Scheduler) ChangeLocation(newLocation *time.Location) {
	s.locationMutex.Lock()
	defer s.locationMutex.Unlock()
	s.location = newLocation
}

// Location provides the current location set on the scheduler
func (s *Scheduler) Location() *time.Location {
	s.locationMutex.RLock()
	defer s.locationMutex.RUnlock()
	return s.location
}

type nextRun struct {
	duration time.Duration
	dateTime time.Time
}

// scheduleNextRun Compute the instant when this Job should run next
func (s *Scheduler) scheduleNextRun(job *Job) {
	now := s.now()
	lastRun := job.LastRun()
	if !s.jobPresent(job) {
		return
	}

	if job.getStartsImmediately() {
		s.run(job)
		lastRun = now
		job.setStartsImmediately(false)
	}

	if job.neverRan() {
		// Increment startAtTime to the future
		if !job.startAtTime.IsZero() && job.startAtTime.Before(now) {
			duration := s.durationToNextRun(job.startAtTime, job).duration
			job.startAtTime = job.startAtTime.Add(duration)
			if job.startAtTime.Before(now) {
				diff := now.Sub(job.startAtTime)
				duration := s.durationToNextRun(job.startAtTime, job).duration
				count := diff / duration
				if diff%duration != 0 {
					count++
				}
				job.startAtTime = job.startAtTime.Add(duration * count)
			}
		}
		lastRun = now
	}

	if !job.shouldRun() {
		s.RemoveByReference(job)
		return
	}

	next := s.durationToNextRun(lastRun, job)

	if next.dateTime.IsZero() {
		job.setNextRun(lastRun.Add(next.duration))
	} else {
		job.setNextRun(next.dateTime)
	}
	job.setTimer(time.AfterFunc(next.duration, func() {
		if !next.dateTime.IsZero() {
			for {
				if time.Now().Unix() >= next.dateTime.Unix() {
					break
				}
			}
		}
		s.run(job)
		s.scheduleNextRun(job)
	}))
}

// durationToNextRun calculate how much time to the next run, depending on unit
func (s *Scheduler) durationToNextRun(lastRun time.Time, job *Job) nextRun {
	// job can be scheduled with .StartAt()
	if job.getStartAtTime().After(lastRun) {
		return nextRun{duration: job.getStartAtTime().Sub(s.now()), dateTime: job.getStartAtTime()}
	}

	var next nextRun
	switch job.getUnit() {
	case milliseconds, seconds, minutes, hours:
		next.duration = s.calculateDuration(job)
	case days:
		next = s.calculateDays(job, lastRun)
	case weeks:
		if len(job.scheduledWeekdays) != 0 { // weekday selected, Every().Monday(), for example
			next = s.calculateWeekday(job, lastRun)
		} else {
			next = s.calculateWeeks(job, lastRun)
		}
	case months:
		next = s.calculateMonths(job, lastRun)
	case duration:
		next.duration = job.getDuration()
	case crontab:
		next.dateTime = job.cronSchedule.Next(lastRun)
		next.duration = next.dateTime.Sub(lastRun)
	}
	return next
}

func (s *Scheduler) calculateMonths(job *Job, lastRun time.Time) nextRun {
	lastRunRoundedMidnight := s.roundToMidnight(lastRun)

	if len(job.daysOfTheMonth) != 0 { // calculate days to job.daysOfTheMonth

		nextRunDateMap := make(map[int]nextRun)
		for _, day := range job.daysOfTheMonth {
			nextRunDateMap[day] = calculateNextRunForMonth(s, job, lastRun, day)
		}

		nextRunResult := nextRun{}
		for _, val := range nextRunDateMap {
			if nextRunResult.dateTime.IsZero() {
				nextRunResult = val
			} else if nextRunResult.dateTime.Sub(val.dateTime).Milliseconds() > 0 {
				nextRunResult = val
			}
		}

		return nextRunResult
	}
	next := lastRunRoundedMidnight.Add(job.getAtTime()).AddDate(0, job.interval, 0)
	return nextRun{duration: until(lastRunRoundedMidnight, next), dateTime: next}
}

func calculateNextRunForMonth(s *Scheduler, job *Job, lastRun time.Time, dayOfMonth int) nextRun {

	jobDay := time.Date(lastRun.Year(), lastRun.Month(), dayOfMonth, 0, 0, 0, 0, s.Location()).Add(job.getAtTime())
	difference := absDuration(lastRun.Sub(jobDay))
	next := lastRun
	if jobDay.Before(lastRun) { // shouldn't run this month; schedule for next interval minus day difference
		next = next.AddDate(0, job.interval, -0)
		next = next.Add(-difference)
	} else {
		if job.interval == 1 { // every month counts current month
			next = next.AddDate(0, job.interval-1, 0)
		} else { // should run next month interval
			next = next.AddDate(0, job.interval, 0)
		}
		next = next.Add(difference)
	}
	return nextRun{duration: until(lastRun, next), dateTime: next}
}

func (s *Scheduler) calculateWeekday(job *Job, lastRun time.Time) nextRun {
	daysToWeekday := remainingDaysToWeekday(lastRun.Weekday(), job.Weekdays())
	totalDaysDifference := s.calculateTotalDaysDifference(lastRun, daysToWeekday, job)
	next := s.roundToMidnight(lastRun).Add(job.getAtTime()).AddDate(0, 0, totalDaysDifference)
	return nextRun{duration: until(lastRun, next), dateTime: next}
}

func (s *Scheduler) calculateWeeks(job *Job, lastRun time.Time) nextRun {
	totalDaysDifference := int(job.interval) * 7
	next := s.roundToMidnight(lastRun).Add(job.getAtTime()).AddDate(0, 0, totalDaysDifference)
	return nextRun{duration: until(lastRun, next), dateTime: next}
}

func (s *Scheduler) calculateTotalDaysDifference(lastRun time.Time, daysToWeekday int, job *Job) int {
	if job.interval > 1 && job.RunCount() < len(job.Weekdays()) { // just count weeks after the first jobs were done
		return daysToWeekday
	} else if job.interval > 1 && job.RunCount() >= len(job.Weekdays()) {
		if daysToWeekday > 0 {
			return int(job.interval)*7 - (allWeekDays - daysToWeekday)
		}
		return int(job.interval) * 7
	}

	if daysToWeekday == 0 { // today, at future time or already passed
		lastRunAtTime := time.Date(lastRun.Year(), lastRun.Month(), lastRun.Day(), 0, 0, 0, 0, s.Location()).Add(job.getAtTime())
		if lastRun.Before(lastRunAtTime) || lastRun.Equal(lastRunAtTime) {
			return 0
		}
		return 7
	}
	return daysToWeekday
}

func (s *Scheduler) calculateDays(job *Job, lastRun time.Time) nextRun {

	if job.interval == 1 {
		lastRunDayPlusJobAtTime := time.Date(lastRun.Year(), lastRun.Month(), lastRun.Day(), 0, 0, 0, 0, s.Location()).Add(job.getAtTime())

		// handle occasional occurrence of job running to quickly / too early such that last run was within a second of now
		lastRunUnix, nowUnix := job.LastRun().Unix(), s.now().Unix()
		if lastRunUnix == nowUnix || lastRunUnix == nowUnix-1 || lastRunUnix == nowUnix+1 {
			lastRun = lastRunDayPlusJobAtTime
		}

		if shouldRunToday(lastRun, lastRunDayPlusJobAtTime) {
			return nextRun{duration: until(lastRun, s.roundToMidnight(lastRun).Add(job.getAtTime())), dateTime: s.roundToMidnight(lastRun).Add(job.getAtTime())}
		}
	}

	nextRunAtTime := s.roundToMidnight(lastRun).Add(job.getAtTime()).AddDate(0, 0, job.interval).In(s.Location())
	return nextRun{duration: until(lastRun, nextRunAtTime), dateTime: nextRunAtTime}
}

func until(from time.Time, until time.Time) time.Duration {
	return until.Sub(from)
}

func shouldRunToday(lastRun time.Time, atTime time.Time) bool {
	return lastRun.Before(atTime)
}

func in(scheduleWeekdays []time.Weekday, weekday time.Weekday) bool {
	in := false

	for _, weekdayInSchedule := range scheduleWeekdays {
		if int(weekdayInSchedule) == int(weekday) {
			in = true
			break
		}
	}
	return in
}

func (s *Scheduler) calculateDuration(job *Job) time.Duration {
	lastRun := job.LastRun()
	if job.neverRan() && shouldRunAtSpecificTime(job) { // ugly. in order to avoid this we could prohibit setting .At() and allowing only .StartAt() when dealing with Duration types
		atTime := time.Date(lastRun.Year(), lastRun.Month(), lastRun.Day(), 0, 0, 0, 0, s.Location()).Add(job.getAtTime())
		if lastRun.Before(atTime) || lastRun.Equal(atTime) {
			return time.Until(s.roundToMidnight(lastRun).Add(job.getAtTime()))
		}
	}

	interval := job.interval
	switch job.getUnit() {
	case milliseconds:
		return time.Duration(interval) * time.Millisecond
	case seconds:
		return time.Duration(interval) * time.Second
	case minutes:
		return time.Duration(interval) * time.Minute
	default:
		return time.Duration(interval) * time.Hour
	}
}

func shouldRunAtSpecificTime(job *Job) bool {
	return job.getAtTime() != 0
}

func remainingDaysToWeekday(from time.Weekday, weekDays []time.Weekday) int {
	var (
		daysUntilScheduledDay         int
		daysUntilScheduledDayPositive = allWeekDays
		daysUntilScheduledDayNegative = 0
	)

	for _, day := range weekDays {
		differenceBetweenDays := int(day) - int(from)
		// checking only if is smaller than max cause there is no way to be equals
		if differenceBetweenDays > 0 && differenceBetweenDays < daysUntilScheduledDayPositive {
			daysUntilScheduledDayPositive = differenceBetweenDays
		}

		// mapping negative days to repeat jobs
		if differenceBetweenDays < 0 && differenceBetweenDays < daysUntilScheduledDayNegative {
			daysUntilScheduledDayNegative = differenceBetweenDays
		}
	}

	if daysUntilScheduledDayPositive > 0 && daysUntilScheduledDayPositive != allWeekDays {
		daysUntilScheduledDay = daysUntilScheduledDayPositive
	} else if daysUntilScheduledDayNegative < 0 {
		daysUntilScheduledDay = allWeekDays + daysUntilScheduledDayNegative
	}
	return daysUntilScheduledDay
}

// absDuration returns the abs time difference
func absDuration(a time.Duration) time.Duration {
	if a >= 0 {
		return a
	}
	return -a
}

// roundToMidnight truncates time to midnight
func (s *Scheduler) roundToMidnight(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, s.Location())
}

// NextRun datetime when the next Job should run.
func (s *Scheduler) NextRun() (*Job, time.Time) {
	if len(s.Jobs()) <= 0 {
		return nil, s.now()
	}

	sort.Sort(s)

	return s.Jobs()[0], s.Jobs()[0].NextRun()
}

// Every schedules a new periodic Job with an interval.
// Interval can be an int, time.Duration or a string that
// parses with time.ParseDuration().
// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
func (s *Scheduler) Every(interval interface{}) *Scheduler {
	job := &Job{}
	if s.updateJob || s.jobCreated {
		job = s.getCurrentJob()
	}

	switch interval := interval.(type) {
	case int:
		if !(s.updateJob || s.jobCreated) {
			job = s.newJob(interval)
		} else {
			job = s.newJob(interval)
		}
		if interval <= 0 {
			job.error = wrapOrError(job.error, ErrInvalidInterval)
		}
	case time.Duration:
		if !(s.updateJob || s.jobCreated) {
			job = s.newJob(0)
		} else {
			job.interval = 0
		}
		job.setDuration(interval)
		job.setUnit(duration)
	case string:
		if !(s.updateJob || s.jobCreated) {
			job = s.newJob(0)
		} else {
			job.interval = 0
		}
		d, err := time.ParseDuration(interval)
		if err != nil {
			job.error = wrapOrError(job.error, err)
		}
		job.setDuration(d)
		job.setUnit(duration)
	default:
		if !(s.updateJob || s.jobCreated) {
			job = s.newJob(0)
		} else {
			job.interval = 0
		}
		job.error = wrapOrError(job.error, ErrInvalidIntervalType)
	}

	if s.updateJob || s.jobCreated {
		s.setJobs(append(s.Jobs()[:len(s.Jobs())-1], job))
		if s.jobCreated {
			s.jobCreated = false
		}
	} else {
		s.setJobs(append(s.Jobs(), job))
	}

	return s
}

func (s *Scheduler) run(job *Job) {
	if !s.IsRunning() {
		return
	}

	job.mu.Lock()
	defer job.mu.Unlock()
	job.setLastRun(s.now())
	job.runCount++
	s.executor.jobFunctions <- job.jobFunction
}

// RunAll run all Jobs regardless if they are scheduled to run or not
func (s *Scheduler) RunAll() {
	s.RunAllWithDelay(0)
}

// RunAllWithDelay runs all jobs with the provided delay in between each job
func (s *Scheduler) RunAllWithDelay(d time.Duration) {
	for _, job := range s.Jobs() {
		s.run(job)
		s.time.Sleep(d)
	}
}

// RunByTag runs all the jobs containing a specific tag
// regardless of whether they are scheduled to run or not
func (s *Scheduler) RunByTag(tag string) error {
	return s.RunByTagWithDelay(tag, 0)
}

// RunByTagWithDelay is same as RunByTag but introduces a delay between
// each job execution
func (s *Scheduler) RunByTagWithDelay(tag string, d time.Duration) error {
	jobs, err := s.findJobsByTag(tag)
	if err != nil {
		return err
	}
	for _, job := range jobs {
		s.run(job)
		s.time.Sleep(d)
	}
	return nil
}

// Remove specific Job by function
//
// Removing a job stops that job's timer. However, if a job has already
// been started by by the job's timer before being removed, there is no way to stop
// it through gocron as https://pkg.go.dev/time#Timer.Stop explains.
// The job function would need to have implemented a means of
// stopping, e.g. using a context.WithCancel().
func (s *Scheduler) Remove(job interface{}) {
	fName := getFunctionName(job)
	j := s.findJobByTaskName(fName)
	s.removeJobsUniqueTags(j)
	s.removeByCondition(func(someJob *Job) bool {
		return someJob.name == fName
	})
}

// RemoveByReference removes specific Job by reference
func (s *Scheduler) RemoveByReference(job *Job) {
	s.removeJobsUniqueTags(job)
	s.removeByCondition(func(someJob *Job) bool {
		job.mu.RLock()
		defer job.mu.RUnlock()
		return someJob == job
	})
}

func (s *Scheduler) findJobByTaskName(name string) *Job {
	for _, job := range s.Jobs() {
		if job.name == name {
			return job
		}
	}
	return nil
}

func (s *Scheduler) removeJobsUniqueTags(job *Job) {
	if job == nil {
		return
	}
	if s.tagsUnique && len(job.tags) > 0 {
		for _, tag := range job.tags {
			s.tags.Delete(tag)
		}
	}
}

func (s *Scheduler) removeByCondition(shouldRemove func(*Job) bool) {
	retainedJobs := make([]*Job, 0)
	for _, job := range s.Jobs() {
		if !shouldRemove(job) {
			retainedJobs = append(retainedJobs, job)
		} else {
			job.stop()
		}
	}
	s.setJobs(retainedJobs)
}

// RemoveByTag will remove a job by a given tag.
func (s *Scheduler) RemoveByTag(tag string) error {
	jobs, err := s.findJobsByTag(tag)
	if err != nil {
		return err
	}

	for _, job := range jobs {
		s.RemoveByReference(job)
	}
	return nil
}

func (s *Scheduler) findJobsByTag(tag string) ([]*Job, error) {
	var jobs []*Job

Jobs:
	for _, job := range s.Jobs() {
		tags := job.Tags()
		for _, t := range tags {
			if t == tag {
				jobs = append(jobs, job)
				continue Jobs
			}
		}
	}

	if len(jobs) > 0 {
		return jobs, nil
	}
	return nil, ErrJobNotFoundWithTag
}

// LimitRunsTo limits the number of executions of this job to n.
// Upon reaching the limit, the job is removed from the scheduler.
func (s *Scheduler) LimitRunsTo(i int) *Scheduler {
	job := s.getCurrentJob()
	job.LimitRunsTo(i)
	return s
}

// SingletonMode prevents a new job from starting if the prior job has not yet
// completed it's run
func (s *Scheduler) SingletonMode() *Scheduler {
	job := s.getCurrentJob()
	job.SingletonMode()
	return s
}

// TaskPresent checks if specific job's function was added to the scheduler.
func (s *Scheduler) TaskPresent(j interface{}) bool {
	for _, job := range s.Jobs() {
		if job.name == getFunctionName(j) {
			return true
		}
	}
	return false
}

// To avoid the recursive read lock on s.Jobs() and this function,
// creating this new function and distributing the lock between jobPresent, _jobPresent
func (s *Scheduler) _jobPresent(j *Job, jobs []*Job) bool {
	s.jobsMutex.RLock()
	defer s.jobsMutex.RUnlock()
	for _, job := range jobs {
		if job == j {
			return true
		}
	}
	return false
}

func (s *Scheduler) jobPresent(j *Job) bool {
	return s._jobPresent(j, s.Jobs())
}

// Clear clears all Jobs from this scheduler
func (s *Scheduler) Clear() {
	for _, job := range s.Jobs() {
		job.stop()
	}
	s.setJobs(make([]*Job, 0))
	// If unique tags was enabled, delete all the tags loaded in the tags sync.Map
	if s.tagsUnique {
		s.tags.Range(func(key interface{}, value interface{}) bool {
			s.tags.Delete(key)
			return true
		})
	}
}

// Stop stops the scheduler. This is a no-op if the scheduler is already stopped.
// It waits for all running jobs to finish before returning, so it is safe to assume that running jobs will finish when calling this.
func (s *Scheduler) Stop() {
	if s.IsRunning() {
		s.stop()
	}
}

func (s *Scheduler) stop() {
	s.setRunning(false)
	s.executor.stop()
}

// Do specifies the jobFunc that should be called every time the Job runs
func (s *Scheduler) Do(jobFun interface{}, params ...interface{}) (*Job, error) {
	job := s.getCurrentJob()

	jobUnit := job.getUnit()
	if job.atTime != 0 && (jobUnit <= hours || jobUnit >= duration) {
		job.error = wrapOrError(job.error, ErrAtTimeNotSupported)
	}

	if len(job.scheduledWeekdays) != 0 && jobUnit != weeks {
		job.error = wrapOrError(job.error, ErrWeekdayNotSupported)
	}

	if job.error != nil {
		// delete the job from the scheduler as this job
		// cannot be executed
		s.RemoveByReference(job)
		return nil, job.error
	}

	typ := reflect.TypeOf(jobFun)
	if typ.Kind() != reflect.Func {
		// delete the job for the same reason as above
		s.RemoveByReference(job)
		return nil, ErrNotAFunction
	}

	f := reflect.ValueOf(jobFun)
	if len(params) != f.Type().NumIn() {
		s.RemoveByReference(job)
		job.error = wrapOrError(job.error, ErrWrongParams)
		return nil, job.error
	}

	fname := getFunctionName(jobFun)
	if job.name != fname {
		job.function = jobFun
		job.parameters = params
		job.name = fname
	}

	// we should not schedule if not running since we can't foresee how long it will take for the scheduler to start
	if s.IsRunning() {
		s.scheduleNextRun(job)
	}

	return job, nil
}

// At schedules the Job at a specific time of day in the form "HH:MM:SS" or "HH:MM"
// or time.Time (note that only the hours, minutes, seconds and nanos are used).
func (s *Scheduler) At(i interface{}) *Scheduler {
	job := s.getCurrentJob()

	switch t := i.(type) {
	case string:
		hour, min, sec, err := parseTime(t)
		if err != nil {
			job.error = wrapOrError(job.error, err)
			return s
		}
		// save atTime start as duration from midnight
		job.setAtTime(time.Duration(hour)*time.Hour + time.Duration(min)*time.Minute + time.Duration(sec)*time.Second)
	case time.Time:
		job.setAtTime(time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute + time.Duration(t.Second())*time.Second + time.Duration(t.Nanosecond())*time.Nanosecond)
	default:
		job.error = wrapOrError(job.error, ErrUnsupportedTimeFormat)
	}
	job.startsImmediately = false
	return s
}

// Tag will add a tag when creating a job.
func (s *Scheduler) Tag(t ...string) *Scheduler {
	job := s.getCurrentJob()

	if s.tagsUnique {
		for _, tag := range t {
			if _, ok := s.tags.Load(tag); ok {
				job.error = wrapOrError(job.error, ErrTagsUnique(tag))
				return s
			}
			s.tags.Store(tag, struct{}{})
		}
	}

	job.tags = t
	return s
}

// StartAt schedules the next run of the Job. If this time is in the past, the configured interval will be used
// to calculate the next future time
func (s *Scheduler) StartAt(t time.Time) *Scheduler {
	job := s.getCurrentJob()
	job.setStartAtTime(t)
	job.startsImmediately = false
	return s
}

// setUnit sets the unit type
func (s *Scheduler) setUnit(unit schedulingUnit) {
	job := s.getCurrentJob()
	currentUnit := job.getUnit()
	if currentUnit == duration || currentUnit == crontab {
		job.error = wrapOrError(job.error, ErrInvalidIntervalUnitsSelection)
		return
	}
	job.setUnit(unit)
}

// Millisecond sets the unit with seconds
func (s *Scheduler) Millisecond() *Scheduler {
	return s.Milliseconds()
}

// Milliseconds sets the unit with seconds
func (s *Scheduler) Milliseconds() *Scheduler {
	s.setUnit(milliseconds)
	return s
}

// Second sets the unit with seconds
func (s *Scheduler) Second() *Scheduler {
	return s.Seconds()
}

// Seconds sets the unit with seconds
func (s *Scheduler) Seconds() *Scheduler {
	s.setUnit(seconds)
	return s
}

// Minute sets the unit with minutes
func (s *Scheduler) Minute() *Scheduler {
	return s.Minutes()
}

// Minutes sets the unit with minutes
func (s *Scheduler) Minutes() *Scheduler {
	s.setUnit(minutes)
	return s
}

// Hour sets the unit with hours
func (s *Scheduler) Hour() *Scheduler {
	return s.Hours()
}

// Hours sets the unit with hours
func (s *Scheduler) Hours() *Scheduler {
	s.setUnit(hours)
	return s
}

// Day sets the unit with days
func (s *Scheduler) Day() *Scheduler {
	s.setUnit(days)
	return s
}

// Days set the unit with days
func (s *Scheduler) Days() *Scheduler {
	s.setUnit(days)
	return s
}

// Week sets the unit with weeks
func (s *Scheduler) Week() *Scheduler {
	s.setUnit(weeks)
	return s
}

// Weeks sets the unit with weeks
func (s *Scheduler) Weeks() *Scheduler {
	s.setUnit(weeks)
	return s
}

// Month sets the unit with months
func (s *Scheduler) Month(daysOfMonth ...int) *Scheduler {
	return s.Months(daysOfMonth...)
}

// Months sets the unit with months
// Note: Only days 1 through 28 are allowed for monthly schedules
// Note: Multiple add same days of month cannot be allowed
func (s *Scheduler) Months(daysOfTheMonth ...int) *Scheduler {
	job := s.getCurrentJob()

	if len(daysOfTheMonth) == 0 {
		job.error = wrapOrError(job.error, ErrInvalidDayOfMonthEntry)
	} else {

		if job.daysOfTheMonth == nil {
			job.daysOfTheMonth = make([]int, 0)
		}

		repeatMap := make(map[int]int)
		for _, dayOfMonth := range daysOfTheMonth {

			if dayOfMonth < 1 || dayOfMonth > 28 {
				job.error = wrapOrError(job.error, ErrInvalidDayOfMonthEntry)
				break
			}

			for _, dayOfMonthInJob := range job.daysOfTheMonth {
				if dayOfMonthInJob == dayOfMonth {
					job.error = wrapOrError(job.error, ErrInvalidDaysOfMonthDuplicateValue)
					break
				}
			}

			if _, ok := repeatMap[dayOfMonth]; ok {
				job.error = wrapOrError(job.error, ErrInvalidDaysOfMonthDuplicateValue)
				break
			} else {
				repeatMap[dayOfMonth]++
			}
		}
	}
	job.daysOfTheMonth = append(job.daysOfTheMonth, daysOfTheMonth...)
	job.startsImmediately = false
	s.setUnit(months)
	return s
}

// NOTE: If the dayOfTheMonth for the above two functions is
// more than the number of days in that month, the extra day(s)
// spill over to the next month. Similarly, if it's less than 0,
// it will go back to the month before

// Weekday sets the scheduledWeekdays with a specifics weekdays
func (s *Scheduler) Weekday(weekDay time.Weekday) *Scheduler {
	job := s.getCurrentJob()

	if in := in(job.scheduledWeekdays, weekDay); !in {
		job.scheduledWeekdays = append(job.scheduledWeekdays, weekDay)
	}

	job.startsImmediately = false
	s.setUnit(weeks)
	return s
}

// Monday sets the start day as Monday
func (s *Scheduler) Monday() *Scheduler {
	return s.Weekday(time.Monday)
}

// Tuesday sets the start day as Tuesday
func (s *Scheduler) Tuesday() *Scheduler {
	return s.Weekday(time.Tuesday)
}

// Wednesday sets the start day as Wednesday
func (s *Scheduler) Wednesday() *Scheduler {
	return s.Weekday(time.Wednesday)
}

// Thursday sets the start day as Thursday
func (s *Scheduler) Thursday() *Scheduler {
	return s.Weekday(time.Thursday)
}

// Friday sets the start day as Friday
func (s *Scheduler) Friday() *Scheduler {
	return s.Weekday(time.Friday)
}

// Saturday sets the start day as Saturday
func (s *Scheduler) Saturday() *Scheduler {
	return s.Weekday(time.Saturday)
}

// Sunday sets the start day as Sunday
func (s *Scheduler) Sunday() *Scheduler {
	return s.Weekday(time.Sunday)
}

func (s *Scheduler) getCurrentJob() *Job {
	if len(s.Jobs()) == 0 {
		s.setJobs([]*Job{{}})
		s.jobCreated = true
	}
	return s.Jobs()[len(s.Jobs())-1]
}

func (s *Scheduler) now() time.Time {
	return s.time.Now(s.Location())
}

// TagsUnique forces job tags to be unique across the scheduler
// when adding tags with (s *Scheduler) Tag().
// This does not enforce uniqueness on tags added via
// (j *Job) Tag()
func (s *Scheduler) TagsUnique() {
	s.tagsUnique = true
}

// Job puts the provided job in focus for the purpose
// of making changes to the job with the scheduler chain
// and finalized by calling Update()
func (s *Scheduler) Job(j *Job) *Scheduler {
	jobs := s.Jobs()
	for index, job := range jobs {
		if job == j {
			// the current job is always last, so put this job there
			s.Swap(len(jobs)-1, index)
		}
	}
	s.updateJob = true
	return s
}

// Update stops the job (if running) and starts it with any updates
// that were made to the job in the scheduler chain. Job() must be
// called first to put the given job in focus.
func (s *Scheduler) Update() (*Job, error) {
	job := s.getCurrentJob()

	if !s.updateJob {
		return job, wrapOrError(job.error, ErrUpdateCalledWithoutJob)
	}
	s.updateJob = false
	job.stop()
	job.ctx, job.cancel = context.WithCancel(context.Background())
	return s.Do(job.function, job.parameters...)
}

func (s *Scheduler) Cron(cronExpression string) *Scheduler {
	return s.cron(cronExpression, false)
}

func (s *Scheduler) CronWithSeconds(cronExpression string) *Scheduler {
	return s.cron(cronExpression, true)
}

func (s *Scheduler) cron(cronExpression string, withSeconds bool) *Scheduler {
	job := s.newJob(0)
	if s.updateJob || s.jobCreated {
		job = s.getCurrentJob()
	}

	withLocation := fmt.Sprintf("CRON_TZ=%s %s", s.location.String(), cronExpression)

	var (
		cronSchedule cron.Schedule
		err          error
	)

	if withSeconds {
		p := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
		cronSchedule, err = p.Parse(withLocation)
	} else {
		cronSchedule, err = cron.ParseStandard(withLocation)
	}

	if err != nil {
		job.error = wrapOrError(err, ErrCronParseFailure)
	}

	job.cronSchedule = cronSchedule
	job.setUnit(crontab)
	job.startsImmediately = false

	if s.updateJob || s.jobCreated {
		s.setJobs(append(s.Jobs()[:len(s.Jobs())-1], job))
		s.jobCreated = false
	} else {
		s.setJobs(append(s.Jobs(), job))
	}
	return s
}

func (s *Scheduler) newJob(interval int) *Job {
	return newJob(interval, !s.waitForInterval)
}

// WaitForScheduleAll defaults the scheduler to create all
// new jobs with the WaitForSchedule option as true.
// The jobs will not start immediately but rather will
// wait until their first scheduled interval.
func (s *Scheduler) WaitForScheduleAll() {
	s.waitForInterval = true
}

// WaitForSchedule sets the job to not start immediately
// but rather wait until the first scheduled interval.
func (s *Scheduler) WaitForSchedule() *Scheduler {
	job := s.getCurrentJob()
	job.startsImmediately = false
	return s
}

// StartImmediately sets the job to run immediately upon
// starting the scheduler or adding the job to a running
// scheduler. This overrides the jobs start status of any
// previously called methods in the chain.
//
// Note: This is the default behavior of the scheduler
// for most jobs, but is useful for overriding the default
// behavior of Cron scheduled jobs which default to
// WaitForSchedule.
func (s *Scheduler) StartImmediately() *Scheduler {
	job := s.getCurrentJob()
	job.startsImmediately = true
	return s
}
