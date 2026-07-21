package main

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

func TestUpdateMachinesHeartbeatMetric_SetsElapsedSecondsForActiveMachine(t *testing.T) {
	metrics.GlobalMachinesHeartbeat.Reset()

	fourMinutesAgo := time.Now().UTC().Add(-4 * time.Minute)
	machines := []*ent.Machine{
		{MachineId: "watcher1", LastHeartbeat: &fourMinutesAgo},
	}

	updateMachinesHeartbeatMetric(machines)

	got := testutil.ToFloat64(metrics.GlobalMachinesHeartbeat.With(prometheus.Labels{"machine": "watcher1"}))
	assert.InDelta(t, 240.0, got, 5.0)
}

func TestUpdateMachinesHeartbeatMetric_SkipsMachineWithNilLastHeartbeat(t *testing.T) {
	metrics.GlobalMachinesHeartbeat.Reset()

	machines := []*ent.Machine{
		{MachineId: "watcher-never-connected", LastHeartbeat: nil},
	}

	updateMachinesHeartbeatMetric(machines)

	assert.Equal(t, 0, testutil.CollectAndCount(metrics.GlobalMachinesHeartbeat))
}

func TestUpdateMachinesHeartbeatMetric_ResetDropsStaleMachines(t *testing.T) {
	metrics.GlobalMachinesHeartbeat.Reset()

	oneMinuteAgo := time.Now().UTC().Add(-1 * time.Minute)
	updateMachinesHeartbeatMetric([]*ent.Machine{
		{MachineId: "old-watcher", LastHeartbeat: &oneMinuteAgo},
	})
	assert.Equal(t, 1, testutil.CollectAndCount(metrics.GlobalMachinesHeartbeat))

	updateMachinesHeartbeatMetric([]*ent.Machine{
		{MachineId: "new-watcher", LastHeartbeat: &oneMinuteAgo},
	})

	assert.Equal(t, 1, testutil.CollectAndCount(metrics.GlobalMachinesHeartbeat))
	got := testutil.ToFloat64(metrics.GlobalMachinesHeartbeat.With(prometheus.Labels{"machine": "new-watcher"}))
	assert.InDelta(t, 60.0, got, 5.0)
}
