package appsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/expr-lang/expr"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/time/rate"

	"github.com/crowdsecurity/crowdsec/pkg/alertcontext"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	rateLimitHelper   = "RateLimit"
	rateLimitScenario = "rate limit exceeded"

	rateLimitKeyField  = "rate_limit_key"
	rateLimitExprField = "rate_limit"

	// One /64 is one end site: keying on the full address would hand every
	// IPv6 client 2^64 budgets.
	rateLimitIPv6PrefixLen = 64
)

type rateLimitSpec struct {
	key    string
	expr   string
	count  int
	period time.Duration
}

// parseRateLimitSpec reads "N/s", "N/m" or "N/h": N requests per period, all
// usable at once.
func parseRateLimitSpec(key, limit string) (rateLimitSpec, error) {
	if key == "" {
		return rateLimitSpec{}, fmt.Errorf("%s: key must not be empty", rateLimitHelper)
	}

	n, unit, ok := strings.Cut(limit, "/")
	if !ok {
		return rateLimitSpec{}, fmt.Errorf("%s(%q): invalid limit %q, expected <count>/<s|m|h>", rateLimitHelper, key, limit)
	}

	count, err := strconv.Atoi(n)
	if err != nil || count <= 0 {
		return rateLimitSpec{}, fmt.Errorf("%s(%q): invalid limit %q, count must be a positive integer", rateLimitHelper, key, limit)
	}

	var period time.Duration

	switch unit {
	case "s":
		period = time.Second
	case "m":
		period = time.Minute
	case "h":
		period = time.Hour
	default:
		return rateLimitSpec{}, fmt.Errorf("%s(%q): invalid limit %q, unit must be s, m or h", rateLimitHelper, key, limit)
	}

	return rateLimitSpec{key: key, expr: limit, count: count, period: period}, nil
}

// Namespaced so a caller-supplied value can never land on an IP's budget: a
// client sending cookie=5.6.7.8 must not drain what 5.6.7.8 is allowed.
type rateLimitIdentity string

func rateLimitIdentityFor(clientIP, sourceValue string) rateLimitIdentity {
	if sourceValue != "" {
		return rateLimitIdentity("value:" + sourceValue)
	}

	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return rateLimitIdentity("ip:" + clientIP)
	}

	addr = addr.Unmap()
	if addr.Is6() {
		prefix, _ := addr.Prefix(rateLimitIPv6PrefixLen)
		return rateLimitIdentity("ip:" + prefix.String())
	}

	return rateLimitIdentity("ip:" + addr.String())
}

type rateLimitEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
	alerted  bool
}

// rateLimiter holds every source's budget for one RateLimit() key.
type rateLimiter struct {
	spec   rateLimitSpec
	engine string

	mu      sync.Mutex
	entries map[rateLimitIdentity]*rateLimitEntry
	// Out-of-band calls are a no-op, and a common pre_eval hook makes one on
	// every request: warning each time would drown the log.
	warnedOutOfBand bool
}

func (l *rateLimiter) gauge() prometheus.Gauge {
	return metrics.AppsecRateLimiters.With(prometheus.Labels{"appsec_engine": l.engine, "key": l.spec.key})
}

// take spends one token. Denied requests still count as activity: a source
// that keeps hammering must not be swept and handed a fresh budget.
func (l *rateLimiter) take(id rateLimitIdentity, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := l.entries[id]
	if e == nil {
		e = &rateLimitEntry{
			limiter: rate.NewLimiter(rate.Limit(float64(l.spec.count)/l.spec.period.Seconds()), l.spec.count),
		}
		l.entries[id] = e
		l.gauge().Set(float64(len(l.entries)))
	}

	e.lastSeen = now

	return e.limiter.AllowN(now, 1)
}

// claimAlert reports whether this is the first denial since the source was
// first seen, so a source flip-flopping around its limit yields one alert.
func (l *rateLimiter) claimAlert(id rateLimitIdentity) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := l.entries[id]
	if e == nil || e.alerted {
		return false
	}

	e.alerted = true

	return true
}

// sweep drops sources idle for a full period. Their bucket has refilled by
// then, so a fresh limiter is indistinguishable from the one dropped.
func (l *rateLimiter) sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for id, e := range l.entries {
		if now.Sub(e.lastSeen) >= l.spec.period {
			delete(l.entries, id)
		}
	}

	l.gauge().Set(float64(len(l.entries)))
}

func (l *rateLimiter) runSweeper(done <-chan struct{}) {
	ticker := time.NewTicker(l.spec.period)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			metrics.AppsecRateLimiters.DeleteLabelValues(l.engine, l.spec.key)
			return
		case now := <-ticker.C:
			l.sweep(now)
		}
	}
}

// RateLimits is shared by every runner of an appsec engine: the budget of a
// source can't depend on which runner picked its request up.
type RateLimits struct {
	limiters map[string]*rateLimiter
}

func newRateLimits(engine string, specs map[string]rateLimitSpec) *RateLimits {
	r := &RateLimits{limiters: make(map[string]*rateLimiter, len(specs))}

	for key, spec := range specs {
		r.limiters[key] = &rateLimiter{
			spec:    spec,
			engine:  engine,
			entries: make(map[rateLimitIdentity]*rateLimitEntry),
		}
	}

	return r
}

// RunSweepers blocks until done is closed, sweeping each key at its own period.
func (r *RateLimits) RunSweepers(done <-chan struct{}) {
	if r == nil {
		return
	}

	var wg sync.WaitGroup

	for _, l := range r.limiters {
		wg.Go(func() { l.runSweeper(done) })
	}

	wg.Wait()
}

func (r *RateLimits) get(key string) *rateLimiter {
	if r == nil {
		return nil
	}

	return r.limiters[key]
}

// RateLimit spends one token of key's budget for the request's source and, if
// none is left, blocks the request with a ban/429. It reports whether the
// source is over its limit.
func (w *AppsecRuntimeConfig) RateLimit(state *AppsecRequestState, request *ParsedRequest, key string, sourceValue string) (bool, error) {
	limiter := w.RateLimits.get(key)
	if limiter == nil {
		// Keys are literals collected at load time, so this is a wiring bug.
		return false, fmt.Errorf("%s(%q): unknown key", rateLimitHelper, key)
	}

	if !request.IsInBand {
		limiter.mu.Lock()
		warn := !limiter.warnedOutOfBand
		limiter.warnedOutOfBand = true
		limiter.mu.Unlock()

		if warn {
			w.Logger.Warnf("%s(%q) called out-of-band, ignoring: rate limiting only applies in-band, guard the hook with IsInBand", rateLimitHelper, key)
		}

		return false, nil
	}

	id := rateLimitIdentityFor(request.ClientIP, strings.TrimSpace(sourceValue))
	if limiter.take(id, time.Now()) {
		return false, nil
	}

	recorded, err := w.setOutcome(state, request, &HookOutcome{
		Action: BanRemediation,
		Reason: rateLimitScenario,
	})
	if err != nil || !recorded {
		return true, err
	}

	state.Response.InBandInterrupt = true
	state.Response.Action = BanRemediation
	state.Response.BouncerHTTPResponseCode = w.Config.BouncerBlockedHTTPCode
	state.Response.UserHTTPResponseCode = http.StatusTooManyRequests

	metrics.AppsecRateLimited.With(prometheus.Labels{
		"source":        request.RemoteAddrNormalized,
		"appsec_engine": request.AppsecEngine,
		"key":           key,
	}).Inc()

	w.Logger.Debugf("%s(%q, %q) exceeded by %s", rateLimitHelper, key, limiter.spec.expr, request.ClientIP)

	evt := rateLimitEventFromRequest(request, w.Labels, request.UUID, limiter.spec)
	StampHookVars(&evt, state)

	var overflow *pipeline.Event

	if limiter.claimAlert(id) {
		o := NewAppsecOverflow(w.buildRateLimitAlert(request, evt, limiter.spec), evt.Appsec.HookVars)
		overflow = &o
	}

	w.EmitAlertAndEvent(overflow, &evt)

	return true, nil
}

func rateLimitEventMeta(request *ParsedRequest, spec rateLimitSpec) map[string]string {
	meta := map[string]string{
		"service":          "appsec",
		"log_type":         "appsec-rate-limit",
		"source_ip":        request.ClientIP,
		"target_host":      request.Host,
		"target_uri":       request.URI,
		"method":           request.Method,
		"request_uuid":     request.UUID,
		rateLimitKeyField:  spec.key,
		rateLimitExprField: spec.expr,
	}
	if request.HTTPRequest != nil {
		meta["http_user_agent"] = request.HTTPRequest.UserAgent()
	}

	for k, v := range meta {
		if v == "" {
			delete(meta, k)
		}
	}

	return meta
}

func (w *AppsecRuntimeConfig) buildRateLimitAlert(request *ParsedRequest, evt pipeline.Event, spec rateLimitSpec) *models.Alert {
	now := time.Now().UTC().Format(time.RFC3339)

	sourceIP := request.ClientIP
	source := models.Source{
		Value: &sourceIP,
		IP:    sourceIP,
		Scope: new(types.Ip),
	}
	if err := GeoIPEnrichSource(&source); err != nil {
		w.Logger.Debugf("unable to enrich rate limit alert source with GeoIP data: %s", err)
	}

	evt.Meta = rateLimitEventMeta(request, spec)

	contextMeta, errs := alertcontext.EventToContext([]pipeline.Event{evt})
	for _, err := range errs {
		w.Logger.Debugf("while generating rate limit alert context: %s", err)
	}

	// Carried whatever the operator's context file says, so the console can
	// always tell which limit fired.
	contextMeta = withContextValue(contextMeta, rateLimitKeyField, spec.key)
	contextMeta = withContextValue(contextMeta, rateLimitExprField, spec.expr)

	scenario := rateLimitScenario
	msg := fmt.Sprintf("WAF rate limit: %s exceeded %s on %s", source.IP, spec.expr, spec.key)

	return &models.Alert{
		Capacity:        new(int32(spec.count)),
		Events:          []*models.Event{{Timestamp: &now, Meta: sortedMeta(evt.Meta)}},
		EventsCount:     new(int32(1)),
		Leakspeed:       new((spec.period / time.Duration(spec.count)).String()),
		Message:         &msg,
		Meta:            contextMeta,
		Scenario:        &scenario,
		ScenarioHash:    new(""),
		ScenarioVersion: new(""),
		Simulated:       new(false),
		Source:          &source,
		StartAt:         new(now),
		StopAt:          new(now),
		Kind:            types.WAFAlertKind.String(),
	}
}

// withContextValue adds key unless the context already has it, encoded the
// way alertcontext encodes values.
func withContextValue(meta models.Meta, key, value string) models.Meta {
	for _, m := range meta {
		if m.Key == key {
			return meta
		}
	}

	encoded, err := json.Marshal([]string{value})
	if err != nil {
		return meta
	}

	return append(meta, &models.MetaItems0{Key: key, Value: string(encoded)})
}

type requestBindingKey struct{}

type requestBinding struct {
	w       *AppsecRuntimeConfig
	state   *AppsecRequestState
	request *ParsedRequest
}

func withRequestBinding(ctx context.Context, w *AppsecRuntimeConfig, state *AppsecRequestState, request *ParsedRequest) context.Context {
	return context.WithValue(ctx, requestBindingKey{}, &requestBinding{w: w, state: state, request: request})
}

func requestBindingFrom(params []any) (*requestBinding, error) {
	if len(params) == 0 {
		return nil, errors.New("helper called without a context")
	}

	ctx, ok := params[0].(context.Context)
	if !ok {
		return nil, fmt.Errorf("helper got %T where a context was expected", params[0])
	}

	b, _ := ctx.Value(requestBindingKey{}).(*requestBinding)
	if b == nil || b.w == nil || b.state == nil || b.request == nil {
		return nil, errors.New("helper is not available in this hook")
	}

	return b, nil
}

func exprRateLimit(params ...any) (any, error) {
	b, err := requestBindingFrom(params)
	if err != nil {
		return nil, err
	}

	// The prototypes below have expr enforce types and arity at load time.
	key, _ := params[1].(string)

	var sourceValue string
	if len(params) > 3 {
		sourceValue, _ = params[3].(string)
	}

	return b.w.RateLimit(b.state, b.request, key, sourceValue)
}

// rateLimitExprOptions is only given to pre_eval: RateLimit anywhere else
// fails to compile.
var rateLimitExprOptions = []expr.Option{
	expr.Function(rateLimitHelper, exprRateLimit,
		new(func(context.Context, string, string) bool),
		new(func(context.Context, string, string, string) bool),
	),
}
