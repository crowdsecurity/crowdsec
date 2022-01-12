package health

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type (
	checkerConfig struct {
		timeout              time.Duration
		checks               map[string]*Check
		maxErrMsgLen         uint
		cacheTTL             time.Duration
		statusChangeListener func(context.Context, CheckerState)
		interceptors         []Interceptor
		detailsDisabled      bool
		autostartDisabled    bool
	}

	defaultChecker struct {
		started  bool
		mtx      sync.Mutex
		cfg      checkerConfig
		state    CheckerState
		endChans []chan *sync.WaitGroup
	}

	checkResult struct {
		checkName string
		newState  CheckState
	}

	// Checker is the main checker interface. It provides all health checking logic.
	Checker interface {
		// Start will start all necessary background workers and prepare
		// the checker for further usage.
		Start()
		// Stop stops will stop the checker.
		Stop()
		// Check runs all synchronous (i.e., non-periodic) check functions.
		// It returns the aggregated health status (combined from the results
		// of this executions synchronous checks and the previously reported
		// results of asynchronous/periodic checks. This function expects a
		// context, that may contain deadlines to which will be adhered to.
		// The context will be passed to all downstream calls
		// (such as listeners, component check functions, and interceptors).
		Check(ctx context.Context) CheckerResult
		// GetRunningPeriodicCheckCount returns the number of currently
		// running periodic checks.
		GetRunningPeriodicCheckCount() int
		// IsStarted returns true, if the Checker was started (see Checker.Start)
		// and is currently still running. Returns false otherwise.
		IsStarted() bool
	}

	// CheckerState represents the current state of the Checker.
	CheckerState struct {
		// Status is the aggregated system health status.
		Status AvailabilityStatus
		// CheckState contains the state of all checks.
		CheckState map[string]CheckState
	}

	// CheckState represents the current state of a component check.
	CheckState struct {
		// LastCheckedAt holds the time of when the check was last executed.
		LastCheckedAt *time.Time
		// LastCheckedAt holds the last time of when the check did not return an error.
		LastSuccessAt *time.Time
		// LastFailureAt holds the last time of when the check did return an error.
		LastFailureAt *time.Time
		// FirstCheckStartedAt holds the time of when the first check was started.
		FirstCheckStartedAt time.Time
		// ContiguousFails holds the number of how often the check failed in a row.
		ContiguousFails uint
		// Result holds the error of the last check (nil if successful).
		Result error
		// The current availability status of the check.
		Status AvailabilityStatus
	}

	// CheckerResult holds the aggregated system availability status and
	// detailed information about the individual checks.
	CheckerResult struct {
		// Status is the aggregated system availability status.
		Status AvailabilityStatus `json:"status"`
		// Details contains health information for all checked components.
		Details *map[string]CheckResult `json:"details,omitempty"`
	}

	// CheckResult holds a components health information.
	CheckResult struct {
		// Status is the availability status of a component.
		Status AvailabilityStatus `json:"status"`
		// Timestamp holds the time when the check was executed.
		Timestamp *time.Time `json:"timestamp,omitempty"`
		// Error contains the check error message, if the check failed.
		Error *string `json:"error,omitempty"`
	}

	// Interceptor is factory function that allows creating new instances of
	// a InterceptorFunc. The concept behind Interceptor is similar to the
	// middleware pattern. A InterceptorFunc that is created by calling a
	// Interceptor is expected to forward the function call to the next
	// InterceptorFunc (passed to the Interceptor in parameter 'next').
	// This way, a chain of interceptors is constructed that will eventually
	// invoke of the components health check function. Each interceptor must therefore
	// invoke the 'next' interceptor. If the 'next' InterceptorFunc is not called,
	// the components check health function will never be executed.
	Interceptor func(next InterceptorFunc) InterceptorFunc

	// InterceptorFunc is an interceptor function that intercepts any call to
	// a components health check function.
	InterceptorFunc func(ctx context.Context, name string, state CheckState) CheckState

	// AvailabilityStatus expresses the availability of either
	// a component or the whole system.
	AvailabilityStatus string
)

const (
	// StatusUnknown holds the information that the availability
	// status is not known, because not all checks were executed yet.
	StatusUnknown AvailabilityStatus = "unknown"
	// StatusUp holds the information that the system or a component
	// is up and running.
	StatusUp AvailabilityStatus = "up"
	// StatusDown holds the information that the system or a component
	// down and not available.
	StatusDown AvailabilityStatus = "down"
)

func (s AvailabilityStatus) criticality() int {
	switch s {
	case StatusDown:
		return 2
	case StatusUnknown:
		return 1
	default:
		return 0
	}
}

func newDefaultChecker(cfg checkerConfig) *defaultChecker {
	checkState := map[string]CheckState{}
	for _, check := range cfg.checks {
		checkState[check.Name] = CheckState{Status: StatusUnknown}
	}

	checker := defaultChecker{
		cfg:      cfg,
		state:    CheckerState{Status: StatusUnknown, CheckState: checkState},
		endChans: []chan *sync.WaitGroup{},
	}

	if !cfg.autostartDisabled {
		checker.Start()
	}

	return &checker
}

// Start implements Checker.Start. Please refer to Checker.Start for more information.
func (ck *defaultChecker) Start() {
	ck.mtx.Lock()

	if !ck.started {
		ck.started = true
		defer ck.startPeriodicChecks()
		defer ck.Check(context.Background())
	}

	ck.mtx.Unlock()
}

// Stop implements Checker.Stop. Please refer to Checker.Stop for more information.
func (ck *defaultChecker) Stop() {
	ck.mtx.Lock()

	var wg sync.WaitGroup
	for _, endChan := range ck.endChans {
		wg.Add(1)
		endChan <- &wg
	}

	ck.endChans = []chan *sync.WaitGroup{}
	ck.started = false

	ck.mtx.Unlock()
	wg.Wait()
}

// GetRunningPeriodicCheckCount implements Checker.GetRunningPeriodicCheckCount.
// Please refer to Checker.GetRunningPeriodicCheckCount for more information.
func (ck *defaultChecker) GetRunningPeriodicCheckCount() int {
	ck.mtx.Lock()
	defer ck.mtx.Unlock()
	return len(ck.endChans)
}

// IsStarted implements Checker.IsStarted. Please refer to Checker.IsStarted for more information.
func (ck *defaultChecker) IsStarted() bool {
	ck.mtx.Lock()
	defer ck.mtx.Unlock()
	return ck.started
}

// Check implements Checker.Check. Please refer to Checker.Check for more information.
func (ck *defaultChecker) Check(ctx context.Context) CheckerResult {
	ck.mtx.Lock()
	defer ck.mtx.Unlock()

	ctx, cancel := context.WithTimeout(ctx, ck.cfg.timeout)
	defer cancel()

	ck.runSynchronousChecks(ctx)

	return ck.mapStateToCheckerResult()
}

func (ck *defaultChecker) runSynchronousChecks(ctx context.Context) {
	var (
		cfg                = ck.cfg
		numChecks          = len(cfg.checks)
		resChan            = make(chan checkResult, numChecks)
		numInitiatedChecks = 0
	)

	for _, c := range cfg.checks {
		checkState := ck.state.CheckState[c.Name]
		if !isPeriodicCheck(c) && isCacheExpired(cfg.cacheTTL, &checkState) {
			numInitiatedChecks++
			go func(ctx context.Context, check Check, state CheckState) {
				withCheckContext(ctx, &check, func(ctx context.Context) {
					_, state = executeCheck(ctx, &cfg, &check, state)
					resChan <- checkResult{check.Name, state}
				})
			}(ctx, *c, checkState)
		}
	}

	var results []checkResult
	for len(results) < numInitiatedChecks {
		results = append(results, <-resChan)
	}

	ck.updateState(ctx, results...)
}

func (ck *defaultChecker) startPeriodicChecks() {
	ck.mtx.Lock()
	defer ck.mtx.Unlock()

	// Start periodic checks
	for _, check := range ck.cfg.checks {
		if isPeriodicCheck(check) {
			var wg *sync.WaitGroup
			endChan := make(chan *sync.WaitGroup, 1)
			checkState := ck.state.CheckState[check.Name]
			ck.endChans = append(ck.endChans, endChan)
			go func(check Check, cfg checkerConfig, state CheckState) {
				if check.initialDelay > 0 {
					time.Sleep(check.initialDelay)
				}
			loop:
				for {
					withCheckContext(context.Background(), &check, func(ctx context.Context) {
						ctx, state = executeCheck(ctx, &cfg, &check, state)
						ck.mtx.Lock()
						ck.updateState(ctx, checkResult{check.Name, state})
						ck.mtx.Unlock()
					})
					select {
					case <-time.After(check.updateInterval):
					case wg = <-endChan:
						break loop
					}
				}
				close(endChan)
				wg.Done()
			}(*check, ck.cfg, checkState)
		}
	}
}

func (ck *defaultChecker) updateState(ctx context.Context, updates ...checkResult) {
	for _, update := range updates {
		ck.state.CheckState[update.checkName] = update.newState
	}

	oldStatus := ck.state.Status
	ck.state.Status = aggregateStatus(ck.state.CheckState)

	if oldStatus != ck.state.Status && ck.cfg.statusChangeListener != nil {
		ck.cfg.statusChangeListener(ctx, ck.state)
	}
}

func (ck *defaultChecker) mapStateToCheckerResult() CheckerResult {
	var status = ck.state.Status
	var checkResults *map[string]CheckResult

	if !ck.cfg.detailsDisabled {
		checkResults = &map[string]CheckResult{}
		for _, c := range ck.cfg.checks {
			checkState := ck.state.CheckState[c.Name]
			(*checkResults)[c.Name] = CheckResult{
				Status:    checkState.Status,
				Error:     toErrorDesc(checkState.Result, ck.cfg.maxErrMsgLen),
				Timestamp: checkState.LastCheckedAt,
			}
		}
	}

	return CheckerResult{Status: status, Details: checkResults}
}

func isCacheExpired(cacheDuration time.Duration, state *CheckState) bool {
	return state.LastCheckedAt == nil || state.LastCheckedAt.Before(time.Now().Add(-cacheDuration))
}

func isPeriodicCheck(check *Check) bool {
	return check.updateInterval > 0
}

func withCheckContext(ctx context.Context, check *Check, f func(checkCtx context.Context)) {
	cancel := func() {}
	if check.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, check.Timeout)
	}
	defer cancel()
	f(ctx)
}

func executeCheck(
	ctx context.Context,
	cfg *checkerConfig,
	check *Check,
	oldState CheckState,
) (context.Context, CheckState) {
	state := oldState

	if state.FirstCheckStartedAt.IsZero() {
		state.FirstCheckStartedAt = time.Now().UTC()
	}

	interceptors := append(cfg.interceptors, check.Interceptors...)
	state = withInterceptors(interceptors, func(ctx context.Context, _ string, state CheckState) CheckState {
		now := time.Now().UTC()
		checkFuncResult := executeCheckFunc(ctx, check)
		return createNextCheckState(now, checkFuncResult, check, state)
	})(ctx, check.Name, state)

	if check.StatusListener != nil && oldState.Status != state.Status {
		check.StatusListener(ctx, check.Name, state)
	}

	return ctx, state
}

func executeCheckFunc(ctx context.Context, check *Check) error {
	res := make(chan error)
	go func() {
		res <- check.Check(ctx)
	}()

	select {
	case r := <-res:
		return r
	case <-ctx.Done():
		return fmt.Errorf("check timed out")
	}
}

func createNextCheckState(checkedAt time.Time, result error, check *Check, state CheckState) CheckState {
	state.Result = result
	state.LastCheckedAt = &checkedAt

	if state.Result == nil {
		state.ContiguousFails = 0
		state.LastSuccessAt = &checkedAt
	} else {
		state.ContiguousFails++
		state.LastFailureAt = &checkedAt
	}

	state.Status = evaluateCheckStatus(&state, check.MaxTimeInError, check.MaxContiguousFails)

	return state
}

func toErrorDesc(err error, maxLen uint) *string {
	if err != nil {
		errDesc := err.Error()
		if uint(len(errDesc)) > maxLen {
			errDesc = errDesc[:maxLen]
		}
		return &errDesc
	}
	return nil
}

func evaluateCheckStatus(state *CheckState, maxTimeInError time.Duration, maxFails uint) AvailabilityStatus {
	if state.LastCheckedAt.IsZero() {
		return StatusUnknown
	} else if state.Result != nil {
		maxTimeInErrorSinceStartPassed := !state.FirstCheckStartedAt.Add(maxTimeInError).After(time.Now())
		maxTimeInErrorSinceLastSuccessPassed := state.LastSuccessAt == nil ||
			!state.LastSuccessAt.Add(maxTimeInError).After(time.Now())

		timeInErrorThresholdCrossed := maxTimeInErrorSinceStartPassed && maxTimeInErrorSinceLastSuccessPassed
		failCountThresholdCrossed := state.ContiguousFails >= maxFails

		if failCountThresholdCrossed && timeInErrorThresholdCrossed {
			return StatusDown
		}
	}
	return StatusUp
}

func aggregateStatus(results map[string]CheckState) AvailabilityStatus {
	status := StatusUp
	for _, result := range results {
		if result.Status.criticality() > status.criticality() {
			status = result.Status
		}
	}
	return status
}

func withInterceptors(interceptors []Interceptor, target InterceptorFunc) InterceptorFunc {
	chain := target
	for idx := len(interceptors) - 1; idx >= 0; idx-- {
		chain = interceptors[idx](chain)
	}
	return chain
}
