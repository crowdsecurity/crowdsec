package apiserver

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/metric"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

const (
	// what the CAPI refuses: "http code 415, response: HTTP content length exceeded 10485760 bytes"
	capiBodyLimit = 10 * 1024 * 1024

	// We budget on uncompressed bytes while the request body is gzipped, so this already
	// over-estimates what the CAPI measures. The slack covers the json structure and the lapi block.
	usageMetricsBatchBytes = capiBodyLimit - 1024*1024

	// Bounds the number of source envelopes in a batch, and keeps the id list we mark as sent
	// under the sqlite variable limit (cf. paginationSize in pkg/database/alerts.go).
	usageMetricsBatchRows = 256

	// rows read per query while filling a batch
	usageMetricsPageSize = 32

	// A snapshot describes a 30 minutes window. Once it is a day late the console has nothing
	// useful left to do with it, so we stop dragging it along.
	usageMetricsMaxAge = 24 * time.Hour
)

type dbPayload struct {
	Metrics []*models.DetailedMetrics `json:"metrics"`
}

// usageMetricsBatch is one CAPI request worth of the backlog.
type usageMetricsBatch struct {
	metrics *models.AllMetrics
	// rows settled by this batch, whether the CAPI takes them or refuses them
	ids []int
	// highest row id in the batch, to feed back as the cursor for the next one
	lastID int
}

func newUsageMetricsBatch(lps map[string]*models.LogProcessorsMetrics, rcs map[string]*models.RemediationComponentsMetrics, ids []int, lastID int) *usageMetricsBatch {
	metrics := &models.AllMetrics{
		// force actual slices to avoid non existing fields in the json
		LogProcessors:         make([]*models.LogProcessorsMetrics, 0, len(lps)),
		RemediationComponents: make([]*models.RemediationComponentsMetrics, 0, len(rcs)),
	}

	// sorted, to keep the payload stable
	for _, name := range slices.Sorted(maps.Keys(lps)) {
		metrics.LogProcessors = append(metrics.LogProcessors, lps[name])
	}

	for _, name := range slices.Sorted(maps.Keys(rcs)) {
		metrics.RemediationComponents = append(metrics.RemediationComponents, rcs[name])
	}

	return &usageMetricsBatch{metrics: metrics, ids: ids, lastID: lastID}
}

// envelopeSize is how much a source adds to a request on top of the payloads it carries. It is not
// negligible: hub_items alone is tens of kilobytes for a log processor with a large hub.
func envelopeSize(v any) int {
	serialized, err := json.Marshal(v)
	if err != nil {
		return 0
	}

	return len(serialized)
}

func lpBaseMetrics(lp *ent.Machine) *models.LogProcessorsMetrics {
	hubItems := models.HubItems{}

	if lp.Hubstate != nil {
		// must carry over the hub state even if nothing is installed
		for itemType, items := range lp.Hubstate {
			hubItems[itemType] = []models.HubItem{}
			for _, item := range items {
				hubItems[itemType] = append(hubItems[itemType], models.HubItem{
					Name:    item.Name,
					Status:  item.Status,
					Version: item.Version,
				})
			}
		}
	}

	ret := &models.LogProcessorsMetrics{
		Datasources: lp.Datasources,
		HubItems:    hubItems,
		LastUpdate:  lp.UpdatedAt.UTC().Unix(),
		Name:        lp.MachineId,
	}

	if lp.LastPush != nil {
		ret.LastPush = lp.LastPush.UTC().Unix()
	}

	ret.Os = &models.OSversion{
		Name:    &lp.Osname,
		Family:  lp.Osfamily,
		Version: &lp.Osversion,
	}
	ret.FeatureFlags = strings.Split(lp.Featureflags, ",")
	ret.Version = &lp.Version
	ret.Metrics = make([]*models.DetailedMetrics, 0)

	return ret
}

func rcBaseMetrics(rc *ent.Bouncer) *models.RemediationComponentsMetrics {
	ret := &models.RemediationComponentsMetrics{
		Name: rc.Name,
		Type: rc.Type,
	}

	if rc.LastPull != nil {
		ret.LastPull = rc.LastPull.UTC().Unix()
	}

	ret.Os = &models.OSversion{
		Name:    &rc.Osname,
		Family:  rc.Osfamily,
		Version: &rc.Osversion,
	}
	ret.FeatureFlags = strings.Split(rc.Featureflags, ",")
	ret.Version = &rc.Version
	ret.Metrics = make([]*models.DetailedMetrics, 0)

	return ret
}

func (a *apic) lapiMetrics() *models.LapiMetrics {
	osName, osFamily, osVersion := version.DetectOS()

	ret := &models.LapiMetrics{
		ConsoleOptions: models.ConsoleOptions{
			strings.Join(a.consoleConfig.EnabledOptions(), ","),
		},
	}

	ret.Os = &models.OSversion{
		Name:    &osName,
		Family:  osFamily,
		Version: &osVersion,
	}
	ret.Version = new(version.String())
	ret.FeatureFlags = fflag.Crowdsec.GetEnabledFeatures()
	ret.Metrics = []*models.DetailedMetrics{{
		Meta: &models.MetricsMeta{
			UtcNowTimestamp:   new(time.Now().UTC().Unix()),
			WindowSizeSeconds: new(int64(a.metricsInterval.Seconds())),
		},
		Items: make([]*models.MetricsDetailItem, 0),
	}}

	return ret
}

// nextUsageMetricsBatch folds the rows after afterID into a single request worth of metrics,
// bounded by usageMetricsBatchBytes so that neither the request nor our memory usage depends on
// how much of a backlog we have. It returns nil when nothing is pending.
func (a *apic) nextUsageMetricsBatch(ctx context.Context, afterID int, lps map[string]*ent.Machine, rcs map[string]*ent.Bouncer) (*usageMetricsBatch, error) {
	var (
		lpMetrics = make(map[string]*models.LogProcessorsMetrics)
		rcMetrics = make(map[string]*models.RemediationComponentsMetrics)
		ids       []int
		size      int
	)

	lastID := afterID

readLoop:
	for len(ids) < usageMetricsBatchRows && size < a.usageMetricsBatchBytes {
		limit := min(usageMetricsPageSize, usageMetricsBatchRows-len(ids))

		rows, err := a.dbClient.GetUnsentMetrics(ctx, lastID, limit)
		if err != nil {
			return nil, err
		}

		for _, row := range rows {
			// a row larger than the whole budget goes out on its own: leaving it behind would
			// block everything queued after it
			if len(ids) > 0 && size+len(row.Payload) > a.usageMetricsBatchBytes {
				break readLoop
			}

			// account for the row before anything can go wrong with it, or it stays pending forever
			lastID = row.ID
			ids = append(ids, row.ID)
			size += len(row.Payload)

			payload := &dbPayload{}
			if err := json.Unmarshal([]byte(row.Payload), payload); err != nil {
				log.Errorf("unable to parse %s usage metrics from %s: %s", row.GeneratedType, row.GeneratedBy, err)
				continue
			}

			switch row.GeneratedType {
			case metric.GeneratedTypeLP:
				lp, ok := lps[row.GeneratedBy]
				if !ok {
					// the log processor is gone, there is nothing left to attach these to
					continue
				}

				met, ok := lpMetrics[row.GeneratedBy]
				if !ok {
					met = lpBaseMetrics(lp)
					lpMetrics[row.GeneratedBy] = met
					size += envelopeSize(met)
				}

				met.Metrics = append(met.Metrics, payload.Metrics...)
			case metric.GeneratedTypeRC:
				rc, ok := rcs[row.GeneratedBy]
				if !ok {
					continue
				}

				met, ok := rcMetrics[row.GeneratedBy]
				if !ok {
					met = rcBaseMetrics(rc)
					rcMetrics[row.GeneratedBy] = met
					size += envelopeSize(met)
				}

				met.Metrics = append(met.Metrics, payload.Metrics...)
			}
		}

		if len(rows) < limit {
			break
		}
	}

	if len(ids) == 0 {
		return nil, nil
	}

	return newUsageMetricsBatch(lpMetrics, rcMetrics, ids, lastID), nil
}

// usageMetricsBatchRefused reports whether the CAPI turned down the request because of what we
// sent. It would refuse the same body again, so the batch has to be dropped or it blocks
// everything queued behind it. The listed statuses are about our credentials, our request rate or
// the route rather than the body, so retrying those later can work.
func usageMetricsBatchRefused(code int) bool {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}

	return code >= http.StatusBadRequest && code < http.StatusInternalServerError
}

type usageMetricsResult int

const (
	usageMetricsAccepted usageMetricsResult = iota
	usageMetricsDropped
	usageMetricsRetryLater
)

// sendUsageMetricsBatch pushes one batch and settles its rows.
func (a *apic) sendUsageMetricsBatch(ctx context.Context, batch *usageMetricsBatch) usageMetricsResult {
	result := usageMetricsAccepted

	_, resp, err := a.apiClient.UsageMetrics.Add(ctx, batch.metrics)
	if err != nil {
		log.Errorf("unable to send usage metrics: %s", err)

		if resp == nil || resp.Response == nil {
			// most likely a transient network error, it will be retried later
			return usageMetricsRetryLater
		}

		if !usageMetricsBatchRefused(resp.Response.StatusCode) {
			return usageMetricsRetryLater
		}

		// The CAPI will never accept this payload. Drop it, or we send it again on every run,
		// bigger every time, until the LAPI runs out of memory.
		log.Errorf("dropping %d usage metrics refused by the CAPI (http code %d)", len(batch.ids), resp.Response.StatusCode)

		result = usageMetricsDropped
	}

	if len(batch.ids) == 0 {
		return result
	}

	if err := a.dbClient.MarkUsageMetricsAsSent(ctx, batch.ids); err != nil {
		log.Errorf("unable to mark usage metrics as sent: %s", err)
		return usageMetricsRetryLater
	}

	return result
}

// pushUsageMetrics drains the pending usage metrics, one bounded batch per request.
func (a *apic) pushUsageMetrics(ctx context.Context) {
	dropped, err := a.dbClient.MarkStaleUsageMetricsAsSent(ctx, time.Now().UTC().Add(-usageMetricsMaxAge))
	if err != nil {
		log.Errorf("unable to drop stale usage metrics: %s", err)
	} else if dropped > 0 {
		log.Warnf("dropped %d usage metrics older than %s", dropped, usageMetricsMaxAge)
	}

	machines, err := a.dbClient.ListMachines(ctx)
	if err != nil {
		log.Errorf("unable to get log processors: %s", err)
		return
	}

	bouncers, err := a.dbClient.ListBouncers(ctx)
	if err != nil {
		log.Errorf("unable to get remediation components: %s", err)
		return
	}

	lps := make(map[string]*ent.Machine, len(machines))
	for _, machine := range machines {
		lps[machine.MachineId] = machine
	}

	rcs := make(map[string]*ent.Bouncer, len(bouncers))
	for _, bouncer := range bouncers {
		rcs[bouncer.Name] = bouncer
	}

	// The lapi block rides on the first request, which goes out even when nothing is pending:
	// it is how the console learns our version and console options.
	lapi := a.lapiMetrics()
	afterID := 0
	sent := 0

	// report what went out even when the drain stops halfway
	defer func() {
		log.Infof("Sent %d usage metrics", sent)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.metricsTomb.Dying():
			return
		default:
		}

		batch, err := a.nextUsageMetricsBatch(ctx, afterID, lps, rcs)
		if err != nil {
			log.Errorf("unable to get usage metrics: %s", err)
			return
		}

		if batch == nil {
			if lapi == nil {
				break
			}

			batch = newUsageMetricsBatch(nil, nil, nil, afterID)
		}

		if lapi != nil {
			batch.metrics.Lapi = lapi
			lapi = nil
		}

		switch a.sendUsageMetricsBatch(ctx, batch) {
		case usageMetricsRetryLater:
			return
		case usageMetricsAccepted:
			sent += len(batch.ids)
		case usageMetricsDropped:
		}

		afterID = batch.lastID
	}
}

func (a *apic) GetMetrics(ctx context.Context) (*models.Metrics, error) {
	machines, err := a.dbClient.ListMachines(ctx)
	if err != nil {
		return nil, err
	}

	machinesInfo := make([]*models.MetricsAgentInfo, len(machines))

	for i, machine := range machines {
		machinesInfo[i] = &models.MetricsAgentInfo{
			Version:    machine.Version,
			Name:       machine.MachineId,
			LastUpdate: machine.UpdatedAt.Format(time.RFC3339),
			LastPush:   ptr.OrEmpty(machine.LastPush).Format(time.RFC3339),
		}
	}

	bouncers, err := a.dbClient.ListBouncers(ctx)
	if err != nil {
		return nil, err
	}

	bouncersInfo := make([]*models.MetricsBouncerInfo, len(bouncers))

	for i, bouncer := range bouncers {
		lastPull := ""
		if bouncer.LastPull != nil {
			lastPull = bouncer.LastPull.Format(time.RFC3339)
		}

		bouncersInfo[i] = &models.MetricsBouncerInfo{
			Version:    bouncer.Version,
			CustomName: bouncer.Name,
			Name:       bouncer.Type,
			LastPull:   lastPull,
		}
	}

	return &models.Metrics{
		ApilVersion: new(version.String()),
		Machines:    machinesInfo,
		Bouncers:    bouncersInfo,
	}, nil
}

func (a *apic) fetchMachineIDs(ctx context.Context) ([]string, error) {
	machines, err := a.dbClient.ListMachines(ctx)
	if err != nil {
		return nil, err
	}

	ret := make([]string, len(machines))
	for i, machine := range machines {
		ret[i] = machine.MachineId
	}
	// sorted slices are required for the slices.Equal comparison
	slices.Sort(ret)

	return ret, nil
}

// SendMetrics sends metrics to the API server until it receives a stop signal.
//
// Metrics are sent at start, then at the randomized metricsIntervalFirst,
// then at regular metricsInterval. If a change is detected in the list
// of machines, the next metrics are sent immediately.
func (a *apic) SendMetrics(ctx context.Context, stop chan bool) {
	// verify the list of machines every <checkInt> interval
	const checkInt = 20 * time.Second

	// intervals must always be > 0
	metInts := []time.Duration{1 * time.Millisecond, a.metricsIntervalFirst, a.metricsInterval}

	log.Infof("Start sending metrics to CrowdSec Central API (interval: %s once, then %s)",
		metInts[1].Round(time.Second), metInts[2])

	count := -1
	nextMetInt := func() time.Duration {
		if count < len(metInts)-1 {
			count++
		}

		return metInts[count]
	}

	machineIDs := []string{}

	reloadMachineIDs := func() {
		ids, err := a.fetchMachineIDs(ctx)
		if err != nil {
			log.Debugf("unable to get machines (%s), will retry", err)

			return
		}

		machineIDs = ids
	}

	// store the list of machine IDs to compare
	// with the next list
	reloadMachineIDs()

	checkTicker := time.NewTicker(checkInt)
	metTicker := time.NewTicker(nextMetInt())

	for {
		select {
		case <-stop:
			checkTicker.Stop()
			metTicker.Stop()

			return
		case <-checkTicker.C:
			oldIDs := machineIDs

			reloadMachineIDs()

			if !slices.Equal(oldIDs, machineIDs) {
				log.Infof("capi metrics: machines changed, immediate send")
				metTicker.Reset(1 * time.Millisecond)
			}
		case <-metTicker.C:
			metTicker.Stop()

			metrics, err := a.GetMetrics(ctx)
			if err != nil {
				log.Errorf("unable to get metrics (%s)", err)
			}
			// metrics are nil if they could not be retrieved
			if metrics != nil {
				log.Info("capi metrics: sending")

				_, _, err = a.apiClient.Metrics.Add(ctx, metrics)
				if err != nil {
					log.Errorf("capi metrics: failed: %s", err)
				}
			}

			metTicker.Reset(nextMetInt())
		case <-a.metricsTomb.Dying(): // if one apic routine is dying, do we kill the others?
			checkTicker.Stop()
			metTicker.Stop()
			a.pullTomb.Kill(nil)
			a.pushTomb.Kill(nil)

			return
		}
	}
}

func (a *apic) SendUsageMetrics(ctx context.Context) {
	firstRun := true

	log.Debugf("Start sending usage metrics to CrowdSec Central API (interval: %s once, then %s)", a.usageMetricsIntervalFirst, a.usageMetricsInterval)
	ticker := time.NewTicker(a.usageMetricsIntervalFirst)

	for {
		select {
		case <-a.metricsTomb.Dying():
			// The normal metrics routine also kills push/pull tombs, does that make sense ?
			ticker.Stop()
			return
		case <-ticker.C:
			if firstRun {
				firstRun = false

				ticker.Reset(a.usageMetricsInterval)
			}

			a.pushUsageMetrics(ctx)
		}
	}
}
