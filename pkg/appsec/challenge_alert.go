package appsec

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
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
// signals) is carried in the event meta, and the alert context is dictated by
// the operator's context file.
const challengeScenario = "crowdsecurity/rejected-browser-submission"

// challengeEventMeta builds the event Meta for a bot-detection alert. The keys
// mirror the crowdsecurity/appsec-bot-detection-logs parser (which enriches the
// LOG-event path) so the crowdsecurity/appsec-bot-detection context file
// resolves the same way for this direct alert, plus a few raw extras (score,
// signals) an operator can reference from their own context file.
func challengeEventMeta(request *ParsedRequest, info ChallengeEventInfo) map[string]string {
	meta := map[string]string{
		"service":               "appsec",
		"log_type":              "appsec-challenge",
		"source_ip":             request.ClientIP,
		"target_host":           request.Host,
		"target_uri":            request.URI,
		"method":                request.Method,
		"request_uuid":          request.UUID,
		"challenge_event":       string(info.Reason),
		"challenge_fail_reason": info.FailReason,
	}
	if request.HTTPRequest != nil {
		meta["http_user_agent"] = request.HTTPRequest.UserAgent()
	}
	// Score can net to zero even with contributions, so gate on the detail.
	if info.ScoreDetail != "" {
		meta["request_score"] = strconv.Itoa(info.Score)
		meta["request_score_reasons"] = info.ScoreDetail
	}
	if fp := info.Fingerprint; fp != nil {
		meta["fsid"] = fp.FSID
		meta["fingerprint_bot"] = strconv.FormatBool(fp.IsBot())
		meta["os"] = fp.Platform()
		meta["bot_signals"] = strings.Join(fp.BotSignals(), ",")
		if fp.Allowlisted {
			meta["fingerprint_allowlisted"] = "true"
		}
	}

	for k, v := range meta {
		if v == "" {
			delete(meta, k)
		}
	}

	return meta
}

// sortedMeta converts a Meta map into models.Meta with deterministic key order
func sortedMeta(m map[string]string) models.Meta {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	meta := make(models.Meta, 0, len(keys))
	for _, k := range keys {
		meta = append(meta, &models.MetaItems0{Key: k, Value: m[k]})
	}

	return meta
}

// GeoIPEnrichSource fills a models.Source (IP scope) with GeoIP data — ASN,
// country, coordinates, range — from the shared exprhelpers GeoIP databases.
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

// buildChallengeAlert creates an alert for rejected or failed challenge submission.
func (w *AppsecRuntimeConfig) buildChallengeAlert(state *AppsecRequestState, request *ParsedRequest, info ChallengeEventInfo) *models.Alert {
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

	// Build the challenge event the context engine consumes: raw fields in Meta
	// (parser-equivalent), fingerprint exposed via Unmarshaled
	cevt := ChallengeEventFromRequest(request, w.Labels, request.UUID, info)
	cevt.Meta = challengeEventMeta(request, info)
	StampHookVars(&cevt, state)

	contextMeta, errs := alertcontext.EventToContext([]pipeline.Event{cevt})
	for _, err := range errs {
		w.Logger.Debugf("while generating bot-detection alert context: %s", err)
	}

	event := &models.Event{
		Timestamp: &now,
		Meta:      sortedMeta(cevt.Meta),
	}

	msg := fmt.Sprintf("WAF bot-detection: %s %s by %s", source.IP, info.Reason, scenario)
	if info.FailReason != "" {
		msg += fmt.Sprintf(" (%s)", info.FailReason)
	}

	return &models.Alert{
		Capacity:        new(int32(1)),
		Events:          []*models.Event{event},
		EventsCount:     new(int32(1)),
		Leakspeed:       new(""),
		Message:         &msg,
		Meta:            contextMeta,
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

// buildChallengeOverflow doesn't send: emission is centralized in EmitAlertAndEvent.
func (w *AppsecRuntimeConfig) buildChallengeOverflow(state *AppsecRequestState, request *ParsedRequest, info ChallengeEventInfo, hookVars map[string]string) *pipeline.Event {
	// Operators suppress the alert with CancelAlert() in on_challenge_submit.
	if state != nil && !state.Response.SendAlert {
		return nil
	}

	overflow := NewAppsecOverflow(w.buildChallengeAlert(state, request, info), hookVars)

	return &overflow
}
