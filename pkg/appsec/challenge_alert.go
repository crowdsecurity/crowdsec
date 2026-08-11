package appsec

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/oschwald/geoip2-golang"

	"github.com/crowdsecurity/crowdsec/pkg/alertcontext"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// challengeScenario is the fixed scenario name stamped on every bot-detection
// alert. It reads like a hub scenario so the console/central API can group and
// label these alerts consistently; the per-detection "why" (reason, score, bot
// signals) is carried in the alert context instead.
const challengeScenario = "crowdsecurity/rejected-browser-submission"

// appendContext adds a context entry to alert Meta. Empty values are dropped;
// a key with no values is omitted entirely. Encoding is delegated to
// alertcontext.TruncateContext so the value shape (a JSON string array, size
// capped) matches every other context entry cscli and the console decode.
func appendContext(meta *models.Meta, key string, values ...string) {
	kept := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			kept = append(kept, v)
		}
	}
	if len(kept) == 0 {
		return
	}
	encoded, err := alertcontext.TruncateContext(kept, alertcontext.MaxContextValueLen)
	if err != nil {
		return
	}
	*meta = append(*meta, &models.MetaItems0{Key: key, Value: encoded})
}

// GeoIPEnrichSource fills a models.Source (IP scope) with GeoIP data — ASN,
// country, coordinates, range — from the shared exprhelpers GeoIP databases.
// It lives here (rather than the acquisition module) so both the WAF alert path
// and the bot-detection challenge alert can share a single implementation.
func GeoIPEnrichSource(src *models.Source) error {
	if src == nil || src.Scope == nil || *src.Scope != types.Ip {
		return errors.New("source is nil or not an IP")
	}

	asndata, err := exprhelpers.GeoIPASNEnrich(src.IP)
	if err != nil {
		return err
	} else if asndata != nil {
		record := asndata.(*geoip2.ASN)
		src.AsName = record.AutonomousSystemOrganization
		src.AsNumber = fmt.Sprintf("%d", record.AutonomousSystemNumber)
	}

	cityData, err := exprhelpers.GeoIPEnrich(src.IP)
	if err != nil {
		return err
	} else if cityData != nil {
		record := cityData.(*geoip2.City)
		src.Cn = record.Country.IsoCode
		src.Latitude = float32(record.Location.Latitude)
		src.Longitude = float32(record.Location.Longitude)
	}

	rangeData, err := exprhelpers.GeoIPRangeEnrich(src.IP)
	if err != nil {
		return err
	} else if rangeData != nil {
		record := rangeData.(*net.IPNet)
		src.Range = record.String()
	}

	return nil
}

// buildChallengeAlert turns a challenge detection moment (a rejected submission
// or a failed validation) into a self-contained bot-detection alert, the same
// way the WAF's DropRequest builds a `waf` alert.
//
// The scenario is a fixed name so these alerts group consistently. The
// human-facing "why" — outcome, reason, score, bot signals — lives in the alert
// context (Meta) so it surfaces in cscli and the console; the request details
// live on the single event for `-d` output.
func (w *AppsecRuntimeConfig) buildChallengeAlert(request *ParsedRequest, info ChallengeEventInfo) *models.Alert {
	now := time.Now().UTC().Format(time.RFC3339)

	sourceIP := request.ClientIP
	source := models.Source{
		Value: &sourceIP,
		IP:    sourceIP,
		Scope: new(types.Ip),
	}
	if err := GeoIPEnrichSource(&source); err != nil {
		w.Logger.Debugf("unable to enrich challenge alert source with GeoIP data: %s", err)
	}

	scenario := challengeScenario

	// Alert context (Meta): the detection reasoning, as JSON string arrays.
	context := models.Meta{}
	appendContext(&context, "detection_outcome", string(info.Reason))
	appendContext(&context, "detection_reason", info.FailReason)
	// Score can net to zero even with contributions, so gate on the reasons
	// slice rather than the total (mirrors ChallengeEventFromRequest).
	if len(info.ScoreReasons) > 0 {
		appendContext(&context, "request_score", strconv.Itoa(info.Score))
		appendContext(&context, "request_score_reasons", info.ScoreReasons...)
	}
	if fp := info.Fingerprint; fp != nil {
		appendContext(&context, "bot_signals", fp.BotSignals()...)
		appendContext(&context, "fingerprint_bot", strconv.FormatBool(fp.IsBot()))
		appendContext(&context, "platform", fp.Platform())
		appendContext(&context, "fsid", fp.FSID)
		if fp.Allowlisted {
			appendContext(&context, "fingerprint_allowlisted", "true")
		}
	}

	// Event Meta: request details, as plain strings (shown by `cscli ... -d`).
	eventMeta := models.Meta{}
	addEvent := func(key, value string) {
		if value != "" {
			eventMeta = append(eventMeta, &models.MetaItems0{Key: key, Value: value})
		}
	}
	addEvent("challenge_event", string(info.Reason))
	addEvent("challenge_fail_reason", info.FailReason)
	addEvent("target_uri", request.URI)
	addEvent("target_host", request.Host)
	addEvent("method", request.Method)
	if request.HTTPRequest != nil {
		addEvent("user_agent", request.HTTPRequest.UserAgent())
	}

	event := &models.Event{
		Timestamp: &now,
		Meta:      eventMeta,
	}

	msg := fmt.Sprintf("AppSec bot-detection: %s %s by %s", source.IP, info.Reason, scenario)
	if info.FailReason != "" {
		msg += fmt.Sprintf(" (%s)", info.FailReason)
	}

	return &models.Alert{
		Capacity:        new(int32(1)),
		Events:          []*models.Event{event},
		EventsCount:     new(int32(1)),
		Leakspeed:       new(""),
		Message:         &msg,
		Meta:            context,
		Scenario:        &scenario,
		ScenarioHash:    new(""),
		ScenarioVersion: new(""),
		Simulated:       new(false),
		Source:          &source,
		StartAt:         new(now),
		StopAt:          new(now),
		Kind:            types.BotDetectionAlertKind.String(),
	}
}

// emitChallengeAlert sends the direct bot-detection alert on the pipeline
// output channel, wrapped as an APPSEC overflow event so it reaches LAPI the
// same way WAF alerts do. It is gated by state.Response.SendAlert so operators
// can suppress it with CancelAlert() (honored on the rejected path only; the
// failed path emits before on_challenge_submit hooks run). Metrics are left to
// emitChallengeEvent so the prometheus counters are not double-counted.
func (w *AppsecRuntimeConfig) emitChallengeAlert(state *AppsecRequestState, request *ParsedRequest, info ChallengeEventInfo) {
	if w.OutChan == nil || !request.IsInBand {
		return
	}
	if state != nil && !state.Response.SendAlert {
		return
	}

	alert := w.buildChallengeAlert(request, info)

	evt := pipeline.Event{}
	evt.Type = pipeline.APPSEC
	evt.Process = true
	evt.Overflow.Sources = map[string]models.Source{alert.Source.IP: *alert.Source}
	evt.Overflow.APIAlerts = []models.Alert{*alert}
	evt.Overflow.Alert = alert

	w.OutChan <- evt
}
