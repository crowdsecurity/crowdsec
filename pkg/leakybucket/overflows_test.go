package leakybucket

import (
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func scopeTestFactory(t *testing.T) *BucketFactory {
	t.Helper()

	return &BucketFactory{
		Spec:   BucketSpec{Name: "test/ssh-bf", ScopeType: ScopeType{Scope: types.Ip}},
		logger: log.NewEntry(log.StandardLogger()),
	}
}

func scopeTestEvent(ip, srcRange string) pipeline.Event {
	return pipeline.Event{
		Meta:     map[string]string{"source_ip": ip, "SourceRange": srcRange},
		Enriched: map[string]string{},
	}
}

// setSourceScope does what the statics of crowdsecurity/ipv6_to_range do:
//
//   - target: evt.Overflow.Alert.Source.Scope
//     value: Range
func setSourceScope(t *testing.T, src *models.Source, scope string) {
	t.Helper()

	evt := pipeline.Event{
		Type:     pipeline.OVFLW,
		Overflow: pipeline.RuntimeAlert{Alert: &models.Alert{Source: src}},
	}
	require.True(t, parser.SetTargetByName("evt.Overflow.Alert.Source.Scope", scope, &evt))
}

// A postoverflow rewriting the scope of one alert must not rescope the scenario:
// SetTargetByName writes through the *string, so handing out a pointer into the
// factory turns every later alert of that scenario into a Range one.
func TestSourceScopeIsNotSharedWithFactory(t *testing.T) {
	f := scopeTestFactory(t)

	srcs, err := SourceFromEvent(scopeTestEvent("2001:db8:1:2::5", ""), &Leaky{Factory: f, logger: f.logger})
	require.NoError(t, err)
	require.Len(t, srcs, 1)

	for _, src := range srcs {
		require.Equal(t, types.Ip, *src.Scope)
		setSourceScope(t, &src, types.Range)
		require.Equal(t, types.Range, *src.Scope)
	}

	require.Equal(t, types.Ip, f.Spec.ScopeType.Scope)

	// a later IPv4, in its own bucket, is still scoped on the ip
	srcs, err = SourceFromEvent(scopeTestEvent("1.2.3.4", "1.2.0.0/16"), &Leaky{Factory: f, logger: f.logger})
	require.NoError(t, err)
	require.Len(t, srcs, 1)
	require.Contains(t, srcs, "1.2.3.4")
	require.Equal(t, types.Ip, *srcs["1.2.3.4"].Scope)
}

// Same reason, within a single alert: a postoverflow only ever sees APIAlerts[0],
// so rewriting its scope must leave the other sources alone.
func TestSourceScopeIsNotSharedBetweenSources(t *testing.T) {
	f := scopeTestFactory(t)
	leaky := &Leaky{Factory: f, logger: f.logger, Queue: pipeline.NewQueue(10)}

	for _, ip := range []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"} {
		leaky.Queue.Add(scopeTestEvent(ip, ""))
	}

	sources, scope, err := alertFormatSource(leaky, leaky.Queue)
	require.NoError(t, err)
	require.Len(t, sources, 3)
	require.Equal(t, types.Ip, scope)

	first := sources["1.2.3.4"]
	setSourceScope(t, &first, types.Range)

	require.Equal(t, types.Ip, *sources["5.6.7.8"].Scope)
	require.Equal(t, types.Ip, *sources["9.10.11.12"].Scope)
}

// NewAlert must not hand the alert pointers into the factory either: the same
// statics mechanism can rewrite Scenario, ScenarioHash and ScenarioVersion.
func TestAlertDoesNotShareStringsWithFactory(t *testing.T) {
	f := scopeTestFactory(t)
	f.Spec.ScenarioVersion = "0.1"
	f.scenarioHash = "deadbeef"

	leaky := &Leaky{Factory: f, logger: f.logger, Queue: pipeline.NewQueue(10)}

	evt := scopeTestEvent("1.2.3.4", "")
	evt.Time = time.Now().UTC()
	leaky.Queue.Add(evt)

	runtimeAlert, err := NewAlert(leaky, leaky.Queue)
	require.NoError(t, err)

	ovflw := pipeline.Event{Type: pipeline.OVFLW, Overflow: runtimeAlert}

	for _, target := range []string{"Scenario", "ScenarioHash", "ScenarioVersion"} {
		require.True(t, parser.SetTargetByName("evt.Overflow.Alert."+target, "rewritten", &ovflw))
	}

	require.Equal(t, "test/ssh-bf", f.Spec.Name)
	require.Equal(t, "deadbeef", f.scenarioHash)
	require.Equal(t, "0.1", f.Spec.ScenarioVersion)
}

// gen-1 bucket overflows, reprocess re-injects the event, gen-2 bucket pours it.
// Does a postoverflow on the gen-2 alert reach back into the gen-1 alert?
func TestReprocessAliasesFirstGenerationAlert(t *testing.T) {
	gen1 := scopeTestFactory(t)
	gen1.Spec.Name = "gen1/scenario"
	gen1.Spec.Reprocess = true

	leaky1 := &Leaky{Factory: gen1, logger: gen1.logger, Queue: pipeline.NewQueue(10)}
	evt := scopeTestEvent("1.2.3.4", "")
	evt.Time = time.Now().UTC()
	leaky1.Queue.Add(evt)

	alert1, err := NewAlert(leaky1, leaky1.Queue)
	require.NoError(t, err)
	require.True(t, alert1.Reprocess)
	require.Equal(t, types.Ip, *alert1.Alert.Source.Scope)

	// this RuntimeAlert is what output.go hands to pendingAlerts for LAPI,
	// while the same event goes back through the parser chain
	ovflwEvent := pipeline.Event{Type: pipeline.OVFLW, Overflow: alert1}

	// gen-2 bucket, same scope, pours the reprocessed overflow
	gen2 := scopeTestFactory(t)
	gen2.Spec.Name = "gen2/scenario"
	leaky2 := &Leaky{Factory: gen2, logger: gen2.logger, Queue: pipeline.NewQueue(10)}

	srcs, err := SourceFromEvent(ovflwEvent, leaky2)
	require.NoError(t, err)
	require.Len(t, srcs, 1)

	src2 := srcs["1.2.3.4"]
	setSourceScope(t, &src2, types.Range)

	t.Logf("gen1 alert source scope after gen2 postoverflow: %s", *alert1.Alert.Source.Scope)
	require.Equal(t, types.Ip, *alert1.Alert.Source.Scope,
		"gen-2 postoverflow rewrote the gen-1 alert still queued for LAPI")
}
