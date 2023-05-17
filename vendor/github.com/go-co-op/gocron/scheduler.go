package gocron

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
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

	time     TimeWrapper // wrapper around time.Time
	timer    func(d time.Duration, f func()) *time.Timer
	executor *executor // executes jobs passed via chan

	tags sync.Map // for storing tags when unique tags is set

	tagsUnique      bool // defines whether tags should be unique
	updateJob       bool // so the scheduler knows to create a new job or update the current
	waitForInterval bool // defaults jobs to waiting for first interval to start
	singletonMode   bool // defaults all jobs to use SingletonMode()
	jobCreated      bool // so the scheduler knows a job was created prior to calling Every or Cron

	startBlockingStopChanMutex sync.Mutex
	startBlockingStopChan      chan struct{} // stops the scheduler
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
		timer:      afterFunc,
	}
}

// SetMaxConcurrentJobs limits how many jobs can be running at the same time.
// This is useful when running resource intensive jobs and a precise start time is not critical.
func (s *Scheduler) SetMaxConcurrentJobs(n int, mode limitMode) {
	s.executor.maxRunningJobs = semaphore.NewWeighted(int64(n))
	s.executor.limitMode = mode
}

// StartBlocking starts all jobs and blocks the current thread.
// This blocking method can be stopped with Stop() from a separate goroutine.
func (s *Scheduler) StartBlocking() {
	s.StartAsync()
	s.startBlockingStopChanMutex.Lock()
	s.startBlockingStopChan = make(chan struct{}, 1)
	s.startBlockingStopChanMutex.Unlock()
	<-s.startBlockingStopChan
}

// StartAsync starts all jobs without blocking the current thread
func (s *Scheduler) StartAsync() {
	if !s.IsRunning() {
		s.start()
	}
}

// start starts the scheduler, scheduling and running jobs
func (s *Scheduler) start() {
	go s.executor.start()
	s.setRunning(true)
	s.runJobs(s.Jobs())
}

func (s *Scheduler) runJobs(jobs []*Job) {
	for _, job := range jobs {
		s.runContinuous(job)
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
func (s *Scheduler) scheduleNextRun(job *Job) (bool, nextRun) {
	now := s.now()
	if !s.jobPresent(job) {
		return false, nextRun{}
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
	}

	if !job.shouldRun() {
		s.RemoveByReference(job)
		return false, nextRun{}
	}

	next := s.durationToNextRun(now, job)

	if next.dateTime.IsZero() {
		job.setNextRun(now.Add(next.duration))
	} else {
		job.setNextRun(next.dateTime)
	}
	return true, next
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

	// Special case: the last day of the month
	if len(job.daysOfTheMonth) == 1 && job.daysOfTheMonth[0] == -1 {
		return calculateNextRunForLastDayOfMonth(s, job, lastRun)
	}

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
	next := lastRunRoundedMidnight.Add(job.getFirstAtTime()).AddDate(0, job.getInterval(), 0)
	return nextRun{duration: until(lastRun, next), dateTime: next}
}

func calculateNextRunForLastDayOfMonth(s *Scheduler, job *Job, lastRun time.Time) nextRun {
	// Calculate the last day of the next month, by adding job.interval+1 months (i.e. the
	// first day of the month after the next month), and subtracting one day, unless the
	// last run occurred before the end of the month.
	addMonth := job.getInterval()
	atTime := job.getAtTime(lastRun)
	if testDate := lastRun.AddDate(0, 0, 1); testDate.Month() != lastRun.Month() &&
		!s.roundToMidnight(lastRun).Add(atTime).After(lastRun) {
		// Our last run was on the last day of this month.
		addMonth++
		atTime = job.getFirstAtTime()
	}

	next := time.Date(lastRun.Year(), lastRun.Month(), 1, 0, 0, 0, 0, s.Location()).
		Add(atTime).
		AddDate(0, addMonth, 0).
		AddDate(0, 0, -1)
	return nextRun{duration: until(lastRun, next), dateTime: next}
}

func calculateNextRunForMonth(s *Scheduler, job *Job, lastRun time.Time, dayOfMonth int) nextRun {
	atTime := job.getAtTime(lastRun)
	natTime := atTime
	jobDay := time.Date(lastRun.Year(), lastRun.Month(), dayOfMonth, 0, 0, 0, 0, s.Location()).Add(atTime)
	difference := absDuration(lastRun.Sub(jobDay))
	next := lastRun
	if jobDay.Before(lastRun) { // shouldn't run this month; schedule for next interval minus day difference
		next = next.AddDate(0, job.getInterval(), -0)
		next = next.Add(-difference)
		natTime = job.getFirstAtTime()
	} else {
		if job.getInterval() == 1 && !jobDay.Equal(lastRun) { // every month counts current month
			next = next.AddDate(0, job.getInterval()-1, 0)
		} else { // should run next month interval
			next = next.AddDate(0, job.getInterval(), 0)
			natTime = job.getFirstAtTime()
		}
		next = next.Add(difference)
	}
	if atTime != natTime {
		next = next.Add(-atTime).Add(natTime)
	}
	return nextRun{duration: until(lastRun, next), dateTime: next}
}

func (s *Scheduler) calculateWeekday(job *Job, lastRun time.Time) nextRun {
	daysToWeekday := s.remainingDaysToWeekday(lastRun, job)
	totalDaysDifference := s.calculateTotalDaysDifference(lastRun, daysToWeekday, job)
	acTime := job.getAtTime(lastRun)
	if totalDaysDifference > 0 {
		acTime = job.getFirstAtTime()
	}
	next := s.roundToMidnight(lastRun).Add(acTime).AddDate(0, 0, totalDaysDifference)
	return nextRun{duration: until(lastRun, next), dateTime: next}
}

func (s *Scheduler) calculateWeeks(job *Job, lastRun time.Time) nextRun {
	totalDaysDifference := int(job.getInterval()) * 7
	next := s.roundToMidnight(lastRun).Add(job.getFirstAtTime()).AddDate(0, 0, totalDaysDifference)
	return nextRun{duration: until(lastRun, next), dateTime: next}
}

func (s *Scheduler) calculateTotalDaysDifference(lastRun time.Time, daysToWeekday int, job *Job) int {
	if job.getInterval() > 1 {
		// just count weeks after the first jobs were done
		if job.RunCount() < len(job.Weekdays()) {
			return daysToWeekday
		}
		if daysToWeekday > 0 {
			return int(job.getInterval())*7 - (allWeekDays - daysToWeekday)
		}
		return int(job.getInterval()) * 7
	}

	if daysToWeekday == 0 { // today, at future time or already passed
		lastRunAtTime := time.Date(lastRun.Year(), lastRun.Month(), lastRun.Day(), 0, 0, 0, 0, s.Location()).Add(job.getAtTime(lastRun))
		if lastRun.Before(lastRunAtTime) {
			return 0
		}
		return 7
	}
	return daysToWeekday
}

func (s *Scheduler) calculateDays(job *Job, lastRun time.Time) nextRun {
	if job.getInterval() == 1 {
		lastRunDayPlusJobAtTime := s.roundToMidnight(lastRun).Add(job.getAtTime(lastRun))

		// handle occasional occurrence of job running to quickly / too early such that last run was within a second of now
		lastRunUnix, nowUnix := job.LastRun().Unix(), s.now().Unix()
		if lastRunUnix == nowUnix || lastRunUnix == nowUnix-1 || lastRunUnix == nowUnix+1 {
			lastRun = lastRunDayPlusJobAtTime
		}

		if shouldRunToday(lastRun, lastRunDayPlusJobAtTime) {
			return nextRun{duration: until(lastRun, lastRunDayPlusJobAtTime), dateTime: lastRunDayPlusJobAtTime}
		}
	}

	nextRunAtTime := s.roundToMidnight(lastRun).Add(job.getFirstAtTime()).AddDate(0, 0, job.getInterval()).In(s.Location())
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
	if job.neverRan() && shouldRunAtSpecificTime(job) { // ugly. in order to avoid this we could prohibit setting .At() and allowing only .StartAt() when dealing with Duration types
		now := s.time.Now(s.location)
		next := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, s.Location()).Add(job.getFirstAtTime())
		if now.Before(next) || now.Equal(next) {
			return next.Sub(now)
		}
	}

	interval := job.getInterval()
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
	jobLastRun := job.LastRun()
	return job.getAtTime(jobLastRun) != 0
}

func (s *Scheduler) remainingDaysToWeekday(lastRun time.Time, job *Job) int {
	weekDays := job.Weekdays()
	sort.Slice(weekDays, func(i, j int) bool {
		return weekDays[i] < weekDays[j]
	})

	equals := false
	lastRunWeekday := lastRun.Weekday()
	index := sort.Search(len(weekDays), func(i int) bool {
		b := weekDays[i] >= lastRunWeekday
		if b {
			equals = weekDays[i] == lastRunWeekday
		}
		return b
	})
	// check atTime
	if equals {
		if s.roundToMidnight(lastRun).Add(job.getAtTime(lastRun)).After(lastRun) {
			return 0
		}
		index++
	}

	if index < len(weekDays) {
		return int(weekDays[index] - lastRunWeekday)
	}

	return int(weekDays[0]) + allWeekDays - int(lastRunWeekday)
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

// EveryRandom schedules a new period Job that runs at random intervals
// between the provided lower (inclusive) and upper (inclusive) bounds.
// The default unit is Seconds(). Call a different unit in the chain
// if you would like to change that. For example, Minutes(), Hours(), etc.
func (s *Scheduler) EveryRandom(lower, upper int) *Scheduler {
	job := s.newJob(0)
	if s.updateJob || s.jobCreated {
		job = s.getCurrentJob()
	}

	job.setRandomInterval(lower, upper)

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

// Every schedules a new periodic Job with an interval.
// Interval can be an int, time.Duration or a string that
// parses with time.ParseDuration().
// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
func (s *Scheduler) Every(interval interface{}) *Scheduler {
	job := s.newJob(0)
	if s.updateJob || s.jobCreated {
		job = s.getCurrentJob()
	}

	switch interval := interval.(type) {
	case int:
		job.interval = interval
		if interval <= 0 {
			job.error = wrapOrError(job.error, ErrInvalidInterval)
		}
	case time.Duration:
		job.interval = 0
		job.setDuration(interval)
		job.setUnit(duration)
	case string:
		d, err := time.ParseDuration(interval)
		if err != nil {
			job.error = wrapOrError(job.error, err)
		}
		job.setDuration(d)
		job.setUnit(duration)
	default:
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

	if job.runWithDetails {
		switch len(job.parameters) {
		case job.parametersLen:
			job.parameters = append(job.parameters, job.copy())
		case job.parametersLen + 1:
			job.parameters[job.parametersLen] = job.copy()
		default:
			// something is really wrong and we should never get here
			job.error = wrapOrError(job.error, ErrInvalidFunctionParameters)
			return
		}
	}

	s.executor.jobFunctions <- job.jobFunction.copy()
	job.setLastRun(s.now())
	job.runCount++
}

func (s *Scheduler) runContinuous(job *Job) {
	shouldRun, next := s.scheduleNextRun(job)
	if !shouldRun {
		return
	}

	if !job.getStartsImmediately() {
		job.setStartsImmediately(true)
	} else {
		s.run(job)
	}

	job.setTimer(s.timer(next.duration, func() {
		if !next.dateTime.IsZero() {
			for {
				n := s.now().UnixNano() - next.dateTime.UnixNano()
				if n >= 0 {
					break
				}
				s.time.Sleep(time.Duration(n))
			}
		}
		s.runContinuous(job)
	}))
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
	jobs, err := s.FindJobsByTag(tag)
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

// RemoveByTag will remove Jobs that match the given tag.
func (s *Scheduler) RemoveByTag(tag string) error {
	return s.RemoveByTags(tag)
}

// RemoveByTags will remove Jobs that match all given tags.
func (s *Scheduler) RemoveByTags(tags ...string) error {
	jobs, err := s.FindJobsByTag(tags...)
	if err != nil {
		return err
	}

	for _, job := range jobs {
		s.RemoveByReference(job)
	}
	return nil
}

// RemoveByTagsAny will remove Jobs that match any one of the given tags.
func (s *Scheduler) RemoveByTagsAny(tags ...string) error {
	var errs error
	mJob := make(map[*Job]struct{})
	for _, tag := range tags {
		jobs, err := s.FindJobsByTag(tag)
		if err != nil {
			errs = wrapOrError(errs, fmt.Errorf("%s: %s", err.Error(), tag))
		}
		for _, job := range jobs {
			mJob[job] = struct{}{}
		}
	}

	for job := range mJob {
		s.RemoveByReference(job)
	}

	return errs
}

// FindJobsByTag will return a slice of Jobs that match all given tags
func (s *Scheduler) FindJobsByTag(tags ...string) ([]*Job, error) {
	var jobs []*Job

Jobs:
	for _, job := range s.Jobs() {
		if job.hasTags(tags...) {
			jobs = append(jobs, job)
			continue Jobs
		}
	}

	if len(jobs) > 0 {
		return jobs, nil
	}
	return nil, ErrJobNotFoundWithTag
}

// MonthFirstWeekday sets the job to run the first specified weekday of the month
func (s *Scheduler) MonthFirstWeekday(weekday time.Weekday) *Scheduler {
	_, month, day := s.time.Now(time.UTC).Date()

	if day < 7 {
		return s.Cron(fmt.Sprintf("0 0 %d %d %d", day, month, weekday))
	}

	return s.Cron(fmt.Sprintf("0 0 %d %d %d", day, month+1, weekday))
}

// LimitRunsTo limits the number of executions of this job to n.
// Upon reaching the limit, the job is removed from the scheduler.
func (s *Scheduler) LimitRunsTo(i int) *Scheduler {
	job := s.getCurrentJob()
	job.LimitRunsTo(i)
	return s
}

// SingletonMode prevents a new job from starting if the prior job has not yet
// completed its run
func (s *Scheduler) SingletonMode() *Scheduler {
	job := s.getCurrentJob()
	job.SingletonMode()
	return s
}

// SingletonModeAll prevents new jobs from starting if the prior instance of the
// particular job has not yet completed its run
func (s *Scheduler) SingletonModeAll() {
	s.singletonMode = true
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
	s.stopJobs(s.jobs)
	s.executor.stop()
	s.StopBlockingChan()
}

func (s *Scheduler) stopJobs(jobs []*Job) {
	for _, job := range jobs {
		job.stop()
	}
}

func (s *Scheduler) doCommon(jobFun interface{}, params ...interface{}) (*Job, error) {
	job := s.getCurrentJob()

	jobUnit := job.getUnit()
	jobLastRun := job.LastRun()
	if job.getAtTime(jobLastRun) != 0 && (jobUnit <= hours || jobUnit >= duration) {
		job.error = wrapOrError(job.error, ErrAtTimeNotSupported)
	}

	if len(job.scheduledWeekdays) != 0 && jobUnit != weeks {
		job.error = wrapOrError(job.error, ErrWeekdayNotSupported)
	}

	if job.unit != crontab && job.getInterval() == 0 {
		if job.unit != duration {
			job.error = wrapOrError(job.error, ErrInvalidInterval)
		}
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

	fname := getFunctionName(jobFun)
	if job.name != fname {
		job.function = jobFun
		job.parameters = params
		job.name = fname
	}

	f := reflect.ValueOf(jobFun)
	expectedParamLength := f.Type().NumIn()
	if job.runWithDetails {
		expectedParamLength--
	}

	if len(params) != expectedParamLength {
		s.RemoveByReference(job)
		job.error = wrapOrError(job.error, ErrWrongParams)
		return nil, job.error
	}

	if job.runWithDetails && f.Type().In(len(params)).Kind() != reflect.ValueOf(*job).Kind() {
		s.RemoveByReference(job)
		job.error = wrapOrError(job.error, ErrDoWithJobDetails)
		return nil, job.error
	}

	// we should not schedule if not running since we can't foresee how long it will take for the scheduler to start
	if s.IsRunning() {
		s.runContinuous(job)
	}

	return job, nil
}

// Do specifies the jobFunc that should be called every time the Job runs
func (s *Scheduler) Do(jobFun interface{}, params ...interface{}) (*Job, error) {
	return s.doCommon(jobFun, params...)
}

// DoWithJobDetails specifies the jobFunc that should be called every time the Job runs
// and additionally passes the details of the current job to the jobFunc.
// The last argument of the function must be a gocron.Job that will be passed by
// the scheduler when the function is called.
func (s *Scheduler) DoWithJobDetails(jobFun interface{}, params ...interface{}) (*Job, error) {
	job := s.getCurrentJob()
	job.runWithDetails = true
	job.parametersLen = len(params)
	return s.doCommon(jobFun, params...)
}

// At schedules the Job at a specific time of day in the form "HH:MM:SS" or "HH:MM"
// or time.Time (note that only the hours, minutes, seconds and nanos are used).
func (s *Scheduler) At(i interface{}) *Scheduler {
	job := s.getCurrentJob()

	switch t := i.(type) {
	case string:
		for _, tt := range strings.Split(t, ";") {
			hour, min, sec, err := parseTime(tt)
			if err != nil {
				job.error = wrapOrError(job.error, err)
				return s
			}
			// save atTime start as duration from midnight
			job.addAtTime(time.Duration(hour)*time.Hour + time.Duration(min)*time.Minute + time.Duration(sec)*time.Second)
		}
	case time.Time:
		job.addAtTime(time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute + time.Duration(t.Second())*time.Second + time.Duration(t.Nanosecond())*time.Nanosecond)
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

	job.tags = append(job.tags, t...)
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

// MonthLastDay sets the unit with months at every last day of the month
func (s *Scheduler) MonthLastDay() *Scheduler {
	return s.Months(-1)
}

// Months sets the unit with months
// Note: Only days 1 through 28 are allowed for monthly schedules
// Note: Multiple add same days of month cannot be allowed
// Note: -1 is a special value and can only occur as single argument
func (s *Scheduler) Months(daysOfTheMonth ...int) *Scheduler {
	job := s.getCurrentJob()

	if len(daysOfTheMonth) == 0 {
		job.error = wrapOrError(job.error, ErrInvalidDayOfMonthEntry)
	} else if len(daysOfTheMonth) == 1 {
		dayOfMonth := daysOfTheMonth[0]
		if dayOfMonth != -1 && (dayOfMonth < 1 || dayOfMonth > 28) {
			job.error = wrapOrError(job.error, ErrInvalidDayOfMonthEntry)
		}
	} else {

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
	if job.daysOfTheMonth == nil {
		job.daysOfTheMonth = make([]int, 0)
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

func (s *Scheduler) Midday() *Scheduler {
	return s.At("12:00")
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
		s.setJobs([]*Job{s.newJob(0)})
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
	job.setStartsImmediately(false)

	if job.runWithDetails {
		return s.DoWithJobDetails(job.function, job.parameters...)
	}

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

	var withLocation string
	if strings.HasPrefix(cronExpression, "TZ=") || strings.HasPrefix(cronExpression, "CRON_TZ=") {
		withLocation = cronExpression
	} else {
		withLocation = fmt.Sprintf("CRON_TZ=%s %s", s.location.String(), cronExpression)
	}

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
	return newJob(interval, !s.waitForInterval, s.singletonMode)
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

// CustomTime takes an in a struct that implements the TimeWrapper interface
// allowing the caller to mock the time used by the scheduler. This is useful
// for tests relying on gocron.
func (s *Scheduler) CustomTime(customTimeWrapper TimeWrapper) {
	s.time = customTimeWrapper
}

// CustomTimer takes in a function that mirrors the time.AfterFunc
// This is used to mock the time.AfterFunc function used by the scheduler
// for testing long intervals in a short amount of time.
func (s *Scheduler) CustomTimer(customTimer func(d time.Duration, f func()) *time.Timer) {
	s.timer = customTimer
}

func (s *Scheduler) StopBlockingChan() {
	s.startBlockingStopChanMutex.Lock()
	if s.startBlockingStopChan != nil {
		s.startBlockingStopChan <- struct{}{}
	}
	s.startBlockingStopChanMutex.Unlock()
}
