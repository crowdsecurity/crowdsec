package dockeracquisition

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"

	dockerTypesSwarm "github.com/moby/moby/api/types/swarm"
	"github.com/moby/moby/client"
	yaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/docker/tracker"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Configuration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`

	CheckInterval       string   `yaml:"check_interval"`
	FollowStdout        bool     `yaml:"follow_stdout"`
	FollowStdErr        bool     `yaml:"follow_stderr"`
	Until               string   `yaml:"until"`
	Since               string   `yaml:"since"`
	DockerHost          string   `yaml:"docker_host"`
	ContainerName       []string `yaml:"container_name"`
	ContainerID         []string `yaml:"container_id"`
	ContainerNameRegexp []string `yaml:"container_name_regexp"`
	ContainerIDRegexp   []string `yaml:"container_id_regexp"`
	ServiceName         []string `yaml:"service_name"`
	ServiceID           []string `yaml:"service_id"`
	ServiceNameRegexp   []string `yaml:"service_name_regexp"`
	ServiceIDRegexp     []string `yaml:"service_id_regexp"`
	UseServiceLabels    bool     `yaml:"use_service_labels"`
	UseContainerLabels  bool     `yaml:"use_container_labels"`
}

func (dc *Configuration) hasServiceConfig() bool {
	return len(dc.ServiceName) > 0 || len(dc.ServiceID) > 0 ||
		len(dc.ServiceIDRegexp) > 0 || len(dc.ServiceNameRegexp) > 0 || dc.UseServiceLabels
}

func (dc *Configuration) hasContainerConfig() bool {
	return len(dc.ContainerName) > 0 || len(dc.ContainerID) > 0 ||
		len(dc.ContainerIDRegexp) > 0 || len(dc.ContainerNameRegexp) > 0 || dc.UseContainerLabels
}

func (d *Source) UnmarshalConfig(yamlConfig []byte) error {
	d.Config = Configuration{
		FollowStdout: true, // default
		FollowStdErr: true, // default
	}

	if err := yaml.UnmarshalWithOptions(yamlConfig, &d.Config, yaml.Strict()); err != nil {
		return fmt.Errorf("while parsing DockerAcquisition configuration: %s", yaml.FormatError(err, false, false))
	}

	if d.logger != nil {
		d.logger.Tracef("DockerAcquisition configuration: %+v", d.Config)
	}

	// Check if we have any container or service configuration
	if !d.Config.hasContainerConfig() && !d.Config.hasServiceConfig() {
		return errors.New("no containers or services configuration provided")
	}

	if d.Config.UseContainerLabels && (len(d.Config.ContainerName) > 0 || len(d.Config.ContainerID) > 0 || len(d.Config.ContainerIDRegexp) > 0 || len(d.Config.ContainerNameRegexp) > 0) {
		return errors.New("use_container_labels and container_name, container_id, container_id_regexp, container_name_regexp are mutually exclusive")
	}

	if d.Config.UseServiceLabels && (len(d.Config.ServiceName) > 0 || len(d.Config.ServiceID) > 0 || len(d.Config.ServiceIDRegexp) > 0 || len(d.Config.ServiceNameRegexp) > 0) {
		return errors.New("use_service_labels and service_name, service_id, service_id_regexp, service_name_regexp are mutually exclusive")
	}

	if d.Config.CheckInterval != "" && d.logger != nil {
		d.logger.Warn("check_interval is ignored: this datasource now uses events instead of polling (will be removed in a future version)")
	}

	if d.Config.Mode == "" {
		d.Config.Mode = configuration.TAIL_MODE
	}

	if d.Config.Mode != configuration.CAT_MODE && d.Config.Mode != configuration.TAIL_MODE {
		return fmt.Errorf("unsupported mode %s for docker datasource", d.Config.Mode)
	}

	for _, cont := range d.Config.ContainerNameRegexp {
		compiled, err := regexp.Compile(cont)
		if err != nil {
			return fmt.Errorf("container_name_regexp: %w", err)
		}

		d.compiledContainerName = append(d.compiledContainerName, compiled)
	}

	for _, cont := range d.Config.ContainerIDRegexp {
		compiled, err := regexp.Compile(cont)
		if err != nil {
			return fmt.Errorf("container_id_regexp: %w", err)
		}

		d.compiledContainerID = append(d.compiledContainerID, compiled)
	}

	for _, svc := range d.Config.ServiceNameRegexp {
		compiled, err := regexp.Compile(svc)
		if err != nil {
			return fmt.Errorf("service_name_regexp: %w", err)
		}

		d.compiledServiceName = append(d.compiledServiceName, compiled)
	}

	for _, svc := range d.Config.ServiceIDRegexp {
		compiled, err := regexp.Compile(svc)
		if err != nil {
			return fmt.Errorf("service_id_regexp: %w", err)
		}

		d.compiledServiceID = append(d.compiledServiceID, compiled)
	}

	if d.Config.Since == "" {
		d.Config.Since = time.Now().UTC().Format(time.RFC3339)
	}

	d.containerLogsOptions = &client.ContainerLogsOptions{
		ShowStdout: d.Config.FollowStdout,
		ShowStderr: d.Config.FollowStdErr,
		Follow:     true,
		Since:      d.Config.Since,
	}

	if d.Config.Until != "" {
		d.containerLogsOptions.Until = d.Config.Until
	}

	return nil
}

func (d *Source) Configure(ctx context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	d.logger = logger
	d.metricsLevel = metricsLevel

	err := d.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	d.runningContainerState = tracker.NewTracker[*ContainerConfig]()
	d.runningServiceState = tracker.NewTracker[*ContainerConfig]()

	d.logger.Tracef("Actual DockerAcquisition configuration %+v", d.Config)

	opts := []client.Opt{
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	}

	if d.Config.DockerHost != "" {
		opts = append(opts, client.WithHost(d.Config.DockerHost))
	}

	d.Client, err = client.New(opts...)
	if err != nil {
		return err
	}

	info, err := d.Client.Info(ctx, client.InfoOptions{})
	if err != nil {
		return fmt.Errorf("failed to get docker info: %w", err)
	}

	if info.Info.Swarm.LocalNodeState == dockerTypesSwarm.LocalNodeStateActive && info.Info.Swarm.ControlAvailable {
		hasServiceConfig := d.Config.hasServiceConfig()
		if hasServiceConfig {
			d.isSwarmManager = true
			d.logger.Info("node is swarm manager, enabling swarm detection mode")
		}

		if !hasServiceConfig {
			// we set to false cause user didnt provide service configuration even though we are a swarm manager
			d.isSwarmManager = false
			d.logger.Warn("node is swarm manager, but no service configuration provided - service monitoring will be disabled, if this is unintentional please apply constraints")
		}
	}

	d.backoffFactory = newDockerBackOffFactory()

	return nil
}

func (d *Source) ConfigureByDSN(_ context.Context, dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	var err error

	parsedURL, err := url.Parse(dsn)
	if err != nil {
		return fmt.Errorf("failed to parse DSN %s: %w", dsn, err)
	}

	if parsedURL.Scheme != d.GetName() {
		return fmt.Errorf("invalid DSN %s for docker source, must start with %s://", dsn, d.GetName())
	}

	d.Config = Configuration{
		FollowStdout:  true,
		FollowStdErr:  true,
	}
	d.Config.UniqueId = uuid
	d.Config.ContainerName = make([]string, 0)
	d.Config.ContainerID = make([]string, 0)
	d.runningContainerState = tracker.NewTracker[*ContainerConfig]()
	d.runningServiceState = tracker.NewTracker[*ContainerConfig]()
	d.Config.Mode = configuration.CAT_MODE
	d.logger = logger
	d.Config.Labels = labels

	opts := []client.Opt{
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	}

	d.containerLogsOptions = &client.ContainerLogsOptions{
		ShowStdout: d.Config.FollowStdout,
		ShowStderr: d.Config.FollowStdErr,
		Follow:     false,
	}

	containerNameOrID := parsedURL.Host

	if containerNameOrID == "" {
		return fmt.Errorf("empty %s DSN", d.GetName()+"://")
	}

	d.Config.ContainerName = append(d.Config.ContainerName, containerNameOrID)
	// we add it as an ID also so user can provide docker name or docker ID
	d.Config.ContainerID = append(d.Config.ContainerID, containerNameOrID)

	parameters := parsedURL.Query()

	for k, v := range parameters {
		switch k {
		case "log_level":
			if len(v) != 1 {
				return errors.New("only one 'log_level' parameters is required, not many")
			}
			lvl, err := log.ParseLevel(v[0])
			if err != nil {
				return fmt.Errorf("unknown level %s: %w", v[0], err)
			}
			d.logger.Logger.SetLevel(lvl)
		case "until":
			if len(v) != 1 {
				return errors.New("only one 'until' parameters is required, not many")
			}
			d.containerLogsOptions.Until = v[0]
		case "since":
			if len(v) != 1 {
				return errors.New("only one 'since' parameters is required, not many")
			}
			d.containerLogsOptions.Since = v[0]
		case "follow_stdout":
			if len(v) != 1 {
				return errors.New("only one 'follow_stdout' parameters is required, not many")
			}
			followStdout, err := strconv.ParseBool(v[0])
			if err != nil {
				return fmt.Errorf("parsing 'follow_stdout' parameters: %s", err)
			}
			d.Config.FollowStdout = followStdout
			d.containerLogsOptions.ShowStdout = followStdout
		case "follow_stderr":
			if len(v) != 1 {
				return errors.New("only one 'follow_stderr' parameters is required, not many")
			}
			followStdErr, err := strconv.ParseBool(v[0])
			if err != nil {
				return fmt.Errorf("parsing 'follow_stderr' parameters: %s", err)
			}
			d.Config.FollowStdErr = followStdErr
			d.containerLogsOptions.ShowStderr = followStdErr
		case "docker_host":
			if len(v) != 1 {
				return errors.New("only one 'docker_host' parameters is required, not many")
			}
			opts = append(opts, client.WithHost(v[0]))
		}
	}

	d.Client, err = client.New(opts...)
	if err != nil {
		return err
	}

	d.backoffFactory = newDockerBackOffFactory()

	return nil
}
