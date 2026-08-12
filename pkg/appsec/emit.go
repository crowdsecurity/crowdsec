package appsec

import (
	"maps"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// Every emitted event gets its own map: the request state keeps mutating (the
// out-of-band phase runs after the in-band event is sent) and the parsers mutate
// events downstream, so sharing one map would be a concurrent read/write.
func copyHookVars(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}

	dst := make(map[string]string, len(src))
	maps.Copy(dst, src)

	return dst
}

// StampHookVars writes to both the event and every matched rule because the two
// alert-context entry points are mirrors: WAF alerts (AppsecEventToContext) are
// evaluated against a real `match` and an empty `evt`, so they can only read
// match.hook_vars.<key>; challenge alerts (EventToContext) against a real `evt`
// and an empty `match`, so they can only read evt.Appsec.HookVars.<key>.
// Challenge events have no matched rules, so the loop is a no-op there.
func StampHookVars(evt *pipeline.Event, state *AppsecRequestState) {
	if evt == nil || state == nil {
		return
	}

	snapshot := copyHookVars(state.HookVars)
	if snapshot == nil {
		return
	}

	evt.Appsec.HookVars = snapshot
	// Matches share the one snapshot: same request, per-rule copies would only allocate.
	for i := range evt.Appsec.MatchedRules {
		evt.Appsec.MatchedRules[i]["hook_vars"] = snapshot
	}
}

// NewAppsecOverflow wraps an alert into the APPSEC event the pipeline routes
// straight to LAPI. hookVars is copied so callers can pass the source event's
// map without the two aliasing.
func NewAppsecOverflow(alert *models.Alert, hookVars map[string]string) pipeline.Event {
	evt := pipeline.Event{}
	evt.Type = pipeline.APPSEC
	evt.Process = true

	if snapshot := copyHookVars(hookVars); snapshot != nil {
		evt.Appsec.HookVars = snapshot
	}

	if alert == nil {
		return evt
	}

	if alert.Source != nil {
		evt.Overflow.Sources = map[string]models.Source{alert.Source.IP: *alert.Source}
	}

	evt.Overflow.APIAlerts = []models.Alert{*alert}
	evt.Overflow.Alert = alert

	return evt
}

// EmitEvent is the single point through which every appsec event reaches the
// pipeline. No-op when no channel is wired (unit tests).
func (w *AppsecRuntimeConfig) EmitEvent(evt pipeline.Event) {
	if w.OutChan == nil {
		return
	}

	w.OutChan <- evt
}

// EmitAlertAndEvent is the only place emission order is decided: the alert goes
// first because the two can share internal maps (matched rules, hook vars) and
// the parsers mutate the log event once it enters the pipeline. Either may be nil.
func (w *AppsecRuntimeConfig) EmitAlertAndEvent(overflow *pipeline.Event, evt *pipeline.Event) {
	if overflow != nil {
		w.EmitEvent(*overflow)
	}

	if evt != nil {
		w.EmitEvent(*evt)
	}
}
