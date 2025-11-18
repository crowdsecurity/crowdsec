package dockeracquisition

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/moby/moby/client"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/docker/tracker"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Source struct {
	metricsLevel          metrics.AcquisitionMetricsLevel
	Config                Configuration
	runningContainerState *tracker.Tracker[*ContainerConfig]
	runningServiceState   *tracker.Tracker[*ContainerConfig]
	compiledContainerName []*regexp.Regexp
	compiledContainerID   []*regexp.Regexp
	compiledServiceName   []*regexp.Regexp
	compiledServiceID     []*regexp.Regexp
	logger                *log.Entry
	Client                client.APIClient
	t                     *tomb.Tomb
	containerLogsOptions  *client.ContainerLogsOptions
	isSwarmManager        bool
	backoffFactory        BackOffFactory
}

type ContainerConfig struct {
	Name       string
	ID         string
	t          tomb.Tomb
	logger     *log.Entry
	Labels     map[string]string
	Tty        bool
	logOptions *client.ContainerLogsOptions
}

func (d *Source) GetUuid() string {
	return d.Config.UniqueId
}

func (d *Source) GetMode() string {
	return d.Config.Mode
}

func (*Source) GetName() string {
	return "docker"
}

func (*Source) CanRun() error {
	return nil
}

func (d *Source) getContainerTTY(ctx context.Context, containerID string) bool {
	containerDetails, err := d.Client.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return false
	}

	return containerDetails.Container.Config.Tty
}

func (d *Source) getContainerLabels(ctx context.Context, containerID string) map[string]any {
	containerDetails, err := d.Client.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return map[string]any{}
	}

	return parseLabels(containerDetails.Container.Config.Labels)
}

func (d *Source) processCrowdsecLabels(parsedLabels map[string]any, entityID string, entityType string) (map[string]string, error) {
	if len(parsedLabels) == 0 {
		d.logger.Tracef("%s has no 'crowdsec' labels set, ignoring %s: %s", entityType, entityType, entityID)
		return nil, errors.New("no crowdsec labels")
	}

	if _, ok := parsedLabels["enable"]; !ok {
		d.logger.Errorf("%s has 'crowdsec' labels set but no 'crowdsec.enable' key found", entityType)
		return nil, errors.New("no crowdsec.enable key")
	}

	enable, ok := parsedLabels["enable"].(string)
	if !ok {
		d.logger.Errorf("%s has 'crowdsec.enable' label set but it's not a string", entityType)
		return nil, errors.New("crowdsec.enable not a string")
	}

	if strings.ToLower(enable) != "true" {
		d.logger.Debugf("%s has 'crowdsec.enable' label not set to true ignoring %s: %s", entityType, entityType, entityID)
		return nil, errors.New("crowdsec.enable not true")
	}

	if _, ok = parsedLabels["labels"]; !ok {
		d.logger.Errorf("%s has 'crowdsec.enable' label set to true but no 'labels' keys found", entityType)
		return nil, errors.New("no labels key")
	}

	labelsTypeCast, ok := parsedLabels["labels"].(map[string]any)
	if !ok {
		d.logger.Errorf("%s has 'crowdsec.enable' label set to true but 'labels' is not a map", entityType)
		return nil, errors.New("labels not a map")
	}

	d.logger.Debugf("%s labels %+v", entityType, labelsTypeCast)

	labels := make(map[string]string)

	for k, v := range labelsTypeCast {
		if v, ok := v.(string); ok {
			log.Debugf("label %s is a string with value %s", k, v)
			labels[k] = v
			continue
		}

		d.logger.Errorf("label %s is not a string", k)
	}

	return labels, nil
}

// NewContainerConfig creates per-container log options by copying the base options
func NewContainerConfig(baseOpts *client.ContainerLogsOptions, id string, name string, labels map[string]string, tty bool) *ContainerConfig {
	opts := &client.ContainerLogsOptions{
		ShowStdout: baseOpts.ShowStdout,
		ShowStderr: baseOpts.ShowStderr,
		Follow:     baseOpts.Follow,
		Since:      baseOpts.Since,
		Until:      baseOpts.Until,
	}

	return &ContainerConfig{
		ID:         id,
		Name:       name,
		Labels:     labels,
		Tty:        tty,
		logOptions: opts,
	}
}

func (d *Source) Dump() any {
	return d
}
