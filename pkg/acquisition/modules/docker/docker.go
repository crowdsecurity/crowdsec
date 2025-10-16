package dockeracquisition

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	backoff "github.com/cenkalti/backoff/v5"
	dockerTypes "github.com/docker/docker/api/types"
	dockerContainer "github.com/docker/docker/api/types/container"
	dockerTypesEvents "github.com/docker/docker/api/types/events"
	dockerFilter "github.com/docker/docker/api/types/filters"
	dockerTypesSwarm "github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	yaml "github.com/goccy/go-yaml"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/dlog"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type DockerConfiguration struct {
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

type DockerSource struct {
	metricsLevel          metrics.AcquisitionMetricsLevel
	Config                DockerConfiguration
	runningContainerState map[string]*ContainerConfig
	runningServiceState   map[string]*ContainerConfig
	compiledContainerName []*regexp.Regexp
	compiledContainerID   []*regexp.Regexp
	compiledServiceName   []*regexp.Regexp
	compiledServiceID     []*regexp.Regexp
	logger                *log.Entry
	Client                client.CommonAPIClient
	t                     *tomb.Tomb
	containerLogsOptions  *dockerContainer.LogsOptions
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
	logOptions *dockerContainer.LogsOptions
}

type BackOffFactory func() backoff.BackOff

func newDockerBackOffFactory() BackOffFactory {
    return func() backoff.BackOff {
        exp := backoff.NewExponentialBackOff()
        exp.InitialInterval = 2 * time.Second
        exp.Multiplier = 2.5
        exp.MaxInterval = 2 * time.Minute
        exp.RandomizationFactor = 0.5

        return exp
    }
}

func (d *DockerSource) GetUuid() string {
	return d.Config.UniqueId
}

func (dc *DockerConfiguration) hasServiceConfig() bool {
	return len(dc.ServiceName) > 0 || len(dc.ServiceID) > 0 ||
		len(dc.ServiceIDRegexp) > 0 || len(dc.ServiceNameRegexp) > 0 || dc.UseServiceLabels
}

func (dc *DockerConfiguration) hasContainerConfig() bool {
	return len(dc.ContainerName) > 0 || len(dc.ContainerID) > 0 ||
		len(dc.ContainerIDRegexp) > 0 || len(dc.ContainerNameRegexp) > 0 || dc.UseContainerLabels
}

func (d *DockerSource) UnmarshalConfig(yamlConfig []byte) error {
	d.Config = DockerConfiguration{
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
		d.logger.Warn("check_interval is deprecated, it will be removed in a future version")
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

	d.containerLogsOptions = &dockerContainer.LogsOptions{
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

func (d *DockerSource) Configure(ctx context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	d.logger = logger
	d.metricsLevel = metricsLevel

	err := d.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	d.runningContainerState = make(map[string]*ContainerConfig)
	d.runningServiceState = make(map[string]*ContainerConfig)

	d.logger.Tracef("Actual DockerAcquisition configuration %+v", d.Config)

	opts := []client.Opt{
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	}

	if d.Config.DockerHost != "" {
		opts = append(opts, client.WithHost(d.Config.DockerHost))
	}

	d.Client, err = client.NewClientWithOpts(opts...)
	if err != nil {
		return err
	}

	info, err := d.Client.Info(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker info: %w", err)
	}

	if info.Swarm.LocalNodeState == dockerTypesSwarm.LocalNodeStateActive && info.Swarm.ControlAvailable {
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

func (d *DockerSource) ConfigureByDSN(_ context.Context, dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	var err error

	parsedURL, err := url.Parse(dsn)
	if err != nil {
		return fmt.Errorf("failed to parse DSN %s: %w", dsn, err)
	}

	if parsedURL.Scheme != d.GetName() {
		return fmt.Errorf("invalid DSN %s for docker source, must start with %s://", dsn, d.GetName())
	}

	d.Config = DockerConfiguration{
		FollowStdout:  true,
		FollowStdErr:  true,
		CheckInterval: "1s",
	}
	d.Config.UniqueId = uuid
	d.Config.ContainerName = make([]string, 0)
	d.Config.ContainerID = make([]string, 0)
	d.runningContainerState = make(map[string]*ContainerConfig)
	d.runningServiceState = make(map[string]*ContainerConfig)
	d.Config.Mode = configuration.CAT_MODE
	d.logger = logger
	d.Config.Labels = labels

	opts := []client.Opt{
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	}

	d.containerLogsOptions = &dockerContainer.LogsOptions{
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

	d.Client, err = client.NewClientWithOpts(opts...)
	if err != nil {
		return err
	}

	d.backoffFactory = newDockerBackOffFactory()

	return nil
}

func (d *DockerSource) GetMode() string {
	return d.Config.Mode
}

// SupportedModes returns the supported modes by the acquisition module
func (*DockerSource) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}

// OneShotAcquisition reads a set of file and returns when done
func (d *DockerSource) OneShotAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	d.logger.Debug("In oneshot")

	runningContainers, err := d.Client.ContainerList(ctx, dockerContainer.ListOptions{})
	if err != nil {
		return err
	}

	foundOne := false

	for _, container := range runningContainers {
		if _, ok := d.runningContainerState[container.ID]; ok {
			d.logger.Debugf("container with id %s is already being read from", container.ID)
			continue
		}

		if containerConfig := d.EvalContainer(ctx, container); containerConfig != nil {
			d.logger.Infof("reading logs from container %s", containerConfig.Name)
			d.logger.Debugf("logs options: %+v", *d.containerLogsOptions)

			dockerReader, err := d.Client.ContainerLogs(ctx, containerConfig.ID, *d.containerLogsOptions)
			if err != nil {
				d.logger.Errorf("unable to read logs from container: %+v", err)
				return err
			}

			// we use this library to normalize docker API logs (cf. https://ahmet.im/blog/docker-logs-api-binary-format-explained/)
			foundOne = true

			var scanner *bufio.Scanner

			if containerConfig.Tty {
				scanner = bufio.NewScanner(dockerReader)
			} else {
				reader := dlog.NewReader(dockerReader)
				scanner = bufio.NewScanner(reader)
			}

			for scanner.Scan() {
				select {
				case <-t.Dying():
					d.logger.Infof("Shutting down reader for container %s", containerConfig.Name)
				default:
					line := scanner.Text()
					if line == "" {
						continue
					}

					l := types.Line{}
					l.Raw = line
					l.Labels = d.Config.Labels
					l.Time = time.Now().UTC()
					l.Src = containerConfig.Name
					l.Process = true
					l.Module = d.GetName()

					if d.metricsLevel != metrics.AcquisitionMetricsLevelNone {
						metrics.DockerDatasourceLinesRead.With(prometheus.Labels{"source": containerConfig.Name, "acquis_type": l.Labels["type"], "datasource_type": "docker"}).Inc()
					}

					evt := types.MakeEvent(true, types.LOG, true)
					evt.Line = l
					evt.Process = true
					evt.Type = types.LOG

					out <- evt

					d.logger.Debugf("Sent line to parsing: %+v", evt.Line.Raw)
				}
			}

			err = scanner.Err()
			if err != nil {
				d.logger.Errorf("Got error from docker read: %s", err)
			}

			d.runningContainerState[container.ID] = containerConfig
		}
	}

	t.Kill(nil)

	if !foundOne {
		return fmt.Errorf("no container found named: %s, can't run one shot acquisition", d.Config.ContainerName[0])
	}

	return nil
}

func (*DockerSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.DockerDatasourceLinesRead}
}

func (*DockerSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.DockerDatasourceLinesRead}
}

func (*DockerSource) GetName() string {
	return "docker"
}

func (*DockerSource) CanRun() error {
	return nil
}

func (d *DockerSource) getContainerTTY(ctx context.Context, containerID string) bool {
	containerDetails, err := d.Client.ContainerInspect(ctx, containerID)
	if err != nil {
		return false
	}

	return containerDetails.Config.Tty
}

func (d *DockerSource) getContainerLabels(ctx context.Context, containerID string) map[string]any {
	containerDetails, err := d.Client.ContainerInspect(ctx, containerID)
	if err != nil {
		return map[string]any{}
	}

	return parseLabels(containerDetails.Config.Labels)
}

func (d *DockerSource) processCrowdsecLabels(parsedLabels map[string]any, entityID string, entityType string) (map[string]string, error) {
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
func NewContainerConfig(baseOpts *dockerContainer.LogsOptions, id string, name string, labels map[string]string, tty bool) *ContainerConfig {
	opts := &dockerContainer.LogsOptions{
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

func (d *DockerSource) EvalContainer(ctx context.Context, container dockerTypes.Container) *ContainerConfig {
	// fixed params
	newConfig := func(name string, labels map[string]string) *ContainerConfig {
		return NewContainerConfig(d.containerLogsOptions, container.ID, name, labels, d.getContainerTTY(ctx, container.ID))
	}

	// ID match

	if slices.Contains(d.Config.ContainerID, container.ID) {
		return newConfig(container.Names[0], d.Config.Labels)
	}

	// name match

	for _, containerName := range d.Config.ContainerName {
		for _, name := range container.Names {
			if strings.HasPrefix(name, "/") && name != "" {
				name = name[1:]
			}

			if name == containerName {
				return newConfig(name, d.Config.Labels)
			}
		}
	}

	// regex ID match

	for _, cont := range d.compiledContainerID {
		if matched := cont.MatchString(container.ID); matched {
			return newConfig(container.Names[0], d.Config.Labels)
		}
	}

	// regex name match

	for _, cont := range d.compiledContainerName {
		for _, name := range container.Names {
			if matched := cont.MatchString(name); matched {
				return newConfig(name, d.Config.Labels)
			}
		}
	}

	// label match

	if d.Config.UseContainerLabels {
		parsedLabels := d.getContainerLabels(ctx, container.ID)

		labels, err := d.processCrowdsecLabels(parsedLabels, container.ID, "container")
		if err != nil {
			return nil
		}

		return newConfig(container.Names[0], labels)
	}

	return nil
}

func (d *DockerSource) EvalService(_ context.Context, service dockerTypesSwarm.Service) *ContainerConfig {
	// fixed params
	newConfig := func(labels map[string]string) *ContainerConfig {
		// Services don't use TTY
		return NewContainerConfig(d.containerLogsOptions, service.ID, service.Spec.Name, labels, false)
	}

	// service ID match

	if slices.Contains(d.Config.ServiceID, service.ID) {
		return newConfig(d.Config.Labels)
	}

	// service name match

	if slices.Contains(d.Config.ServiceName, service.Spec.Name) {
		return newConfig(d.Config.Labels)
	}

	// service ID regex match

	for _, svc := range d.compiledServiceID {
		if matched := svc.MatchString(service.ID); matched {
			return newConfig(d.Config.Labels)
		}
	}

	// service name regex match

	for _, svc := range d.compiledServiceName {
		if matched := svc.MatchString(service.Spec.Name); matched {
			return newConfig(d.Config.Labels)
		}
	}

	// labels if enabled

	if d.Config.UseServiceLabels {
		parsedLabels := parseLabels(service.Spec.Labels)

		labels, err := d.processCrowdsecLabels(parsedLabels, service.ID, "service")
		if err != nil {
			return nil
		}

		return newConfig(labels)
	}

	return nil
}

func (d *DockerSource) checkServices(ctx context.Context, monitChan chan *ContainerConfig, deleteChan chan *ContainerConfig) error {
	// Track current running services for garbage collection
	runningServicesID := make(map[string]bool)

	services, err := d.Client.ServiceList(ctx, dockerTypes.ServiceListOptions{})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "cannot connect to the docker daemon at") {
			d.logger.Errorf("cannot connect to docker daemon for service monitoring: %v", err)

			// Kill all running service monitoring if we can't connect
			for id, service := range d.runningServiceState {
				if service.t.Alive() {
					d.logger.Infof("killing tail for service %s", service.Name)
					service.t.Kill(nil)

					if err := service.t.Wait(); err != nil {
						d.logger.Infof("error while waiting for death of %s : %s", service.Name, err)
					}
				}

				delete(d.runningServiceState, id)
			}
		} else {
			d.logger.Errorf("service list err: %s", err)
		}

		return err
	}

	for _, service := range services {
		runningServicesID[service.ID] = true

		// Don't need to re-eval an already monitored service
		if _, ok := d.runningServiceState[service.ID]; ok {
			continue
		}

		if serviceConfig := d.EvalService(ctx, service); serviceConfig != nil {
			monitChan <- serviceConfig
		}
	}

	// Send deletion notifications for services that are no longer running
	for serviceStateID, serviceConfig := range d.runningServiceState {
		if _, ok := runningServicesID[serviceStateID]; !ok {
			deleteChan <- serviceConfig
		}
	}

	d.logger.Tracef("Reading logs from %d services", len(d.runningServiceState))

	return nil
}

func (d *DockerSource) checkContainers(ctx context.Context, monitChan chan *ContainerConfig, deleteChan chan *ContainerConfig) error {
	// to track for garbage collection
	runningContainersID := make(map[string]bool)

	runningContainers, err := d.Client.ContainerList(ctx, dockerContainer.ListOptions{})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "cannot connect to the docker daemon at") {
			for id, container := range d.runningContainerState {
				if container.t.Alive() {
					d.logger.Infof("killing tail for container %s", container.Name)
					container.t.Kill(nil)

					if err := container.t.Wait(); err != nil {
						d.logger.Infof("error while waiting for death of %s : %s", container.Name, err)
					}
				}

				delete(d.runningContainerState, id)
			}
		} else {
			log.Errorf("container list err: %s", err)
		}

		return err
	}

	for _, container := range runningContainers {
		runningContainersID[container.ID] = true

		// don't need to re eval an already monitored container
		if _, ok := d.runningContainerState[container.ID]; ok {
			continue
		}

		if containerConfig := d.EvalContainer(ctx, container); containerConfig != nil {
			monitChan <- containerConfig
		}
	}

	for containerStateID, containerConfig := range d.runningContainerState {
		if _, ok := runningContainersID[containerStateID]; !ok {
			deleteChan <- containerConfig
		}
	}

	d.logger.Tracef("Reading logs from %d containers", len(d.runningContainerState))

	return nil
}

type subscription struct {
    events <-chan dockerTypesEvents.Message
    errs   <-chan error
}

func (d *DockerSource) trySubscribeEvents(ctx context.Context) (*subscription, error) {
	f := dockerFilter.NewArgs()
	f.Add("type", "container")

	if d.isSwarmManager {
		f.Add("type", "service")
	}

	options := dockerTypesEvents.ListOptions{Filters: f}
	ev, errs := d.Client.Events(ctx, options)

	// Is there an immediate error (proxy/daemon unavailable) ?
	select {
	case err := <-errs:
		if err != nil {
			return nil, fmt.Errorf("docker events connection failed: %w", err)
		}
	default:
	}

	return &subscription{events: ev, errs: errs}, nil
}

// subscribeEvents will loop until it can successfully call d.Client.Events()
// without immediately receiving an error. It applies exponential backoff on failures.
// Returns the new (eventsChan, errChan) pair or an error if context/tomb is done.
func (d *DockerSource) subscribeEvents(ctx context.Context) (*subscription, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.t.Dying():
		return nil, errors.New("connection aborted, shutting down docker watcher")
	default:
	}

	d.logger.Infof("Subscribing to Docker events")

	operation := func() (*subscription, error) {
		select {
		case <-ctx.Done():
			return nil, backoff.Permanent(ctx.Err())
		case <-d.t.Dying():
			return nil, backoff.Permanent(errors.New("connection aborted, shutting down docker watcher"))
		default:
		}

		return d.trySubscribeEvents(ctx)
	}

	notify := func(err error, wait time.Duration) {
		d.logger.Warnf("failed to subscribe to Docker events: %v; retrying in %s", err, wait)
	}

	bo := d.backoffFactory()

	sub, err := backoff.Retry(ctx, operation, backoff.WithBackOff(bo), backoff.WithNotify(notify))
	if err != nil {
		return nil, err
	}

	d.logger.Info("successfully subscribed to Docker events")

	return sub, nil
}

func (d *DockerSource) Watch(ctx context.Context, containerChan chan *ContainerConfig, containerDeleteChan chan *ContainerConfig, serviceChan chan *ContainerConfig, serviceDeleteChan chan *ContainerConfig) error {
	err := d.checkContainers(ctx, containerChan, containerDeleteChan)
	if err != nil {
		return err
	}

	if d.isSwarmManager {
		err = d.checkServices(ctx, serviceChan, serviceDeleteChan)
		if err != nil {
			return err
		}
	}

	sub, err := d.subscribeEvents(ctx)
	if err != nil {
		return err
	}

	for {
		select {
		case <-d.t.Dying():
			d.logger.Infof("stopping container watcher")
			return nil

		case event := <-sub.events:
			d.logger.Tracef("Received event: %+v", event)

			if event.Type == dockerTypesEvents.ServiceEventType && (event.Action == dockerTypesEvents.ActionCreate || event.Action == dockerTypesEvents.ActionRemove) {
				if err := d.checkServices(ctx, serviceChan, serviceDeleteChan); err != nil {
					d.logger.Warnf("Failed to check services: %v", err)
				}
			}

			if event.Type == dockerTypesEvents.ContainerEventType && (event.Action == dockerTypesEvents.ActionStart || event.Action == dockerTypesEvents.ActionDie) {
				if err := d.checkContainers(ctx, containerChan, containerDeleteChan); err != nil {
					d.logger.Warnf("Failed to check containers: %v", err)
				}
			}
		case err := <-sub.errs:
			if err == nil {
				continue
			}

			d.logger.Errorf("Docker events error: %v", err)

			// try to reconnect, replacing our channels on success. They are never nil if err is nil.
			newSub, recErr := d.subscribeEvents(ctx)
			if recErr != nil {
				return recErr
			}

			sub = newSub

			d.logger.Info("Successfully reconnected to Docker events")

			// We check containers after a reconnection because the docker daemon might have restarted
			// and the container tombs may have self deleted
			if err := d.checkContainers(ctx, containerChan, containerDeleteChan); err != nil {
				d.logger.Warnf("Failed to check containers: %v", err)
			}

			if d.isSwarmManager {
				if err := d.checkServices(ctx, serviceChan, serviceDeleteChan); err != nil {
					d.logger.Warnf("Failed to check services: %v", err)
				}
			}
		}
	}
}

func (d *DockerSource) StreamingAcquisition(ctx context.Context, out chan types.Event, t *tomb.Tomb) error {
	d.t = t
	containerChan := make(chan *ContainerConfig)
	containerDeleteChan := make(chan *ContainerConfig)
	serviceChan := make(chan *ContainerConfig)
	serviceDeleteChan := make(chan *ContainerConfig)

	d.logger.Infof("Starting docker acquisition")

	t.Go(func() error {
		return d.ContainerManager(ctx, containerChan, containerDeleteChan, out)
	})

	if d.isSwarmManager {
		t.Go(func() error {
			return d.ServiceManager(ctx, serviceChan, serviceDeleteChan, out)
		})
	}

	return d.Watch(ctx, containerChan, containerDeleteChan, serviceChan, serviceDeleteChan)
}

func (d *DockerSource) Dump() any {
	return d
}

func ReadTailScanner(scanner *bufio.Scanner, out chan string, t *tomb.Tomb) error {
	for scanner.Scan() {
		out <- scanner.Text()
	}

	return scanner.Err()
}

// isContainerStillRunning checks if a container is still running via Docker API
func (d *DockerSource) isContainerStillRunning(ctx context.Context, container *ContainerConfig) bool {
	if ctx.Err() != nil {
		container.logger.Debugf("context canceled while checking container")
		return false
	}

	containerInfo, err := d.Client.ContainerInspect(ctx, container.ID)
	if err != nil {
		if errdefs.IsNotFound(err) {
			container.logger.Debugf("container no longer exists")
			return false
		}

		// Other errors (connection issues, etc.) - assume container is still running
		container.logger.Debugf("failed to inspect: %v (assuming still running)", err)

		return true
	}

	if containerInfo.State == nil {
		container.logger.Warnf("inspect returned nil state (assuming not running)")
		return false
	}

	isRunning := containerInfo.State.Running
	container.logger.Debugf("running status: %v", isRunning)

	return isRunning
}

// isServiceStillRunning checks if a service still exists via Docker API
func (d *DockerSource) isServiceStillRunning(ctx context.Context, service *ContainerConfig) bool {
	if ctx.Err() != nil {
		service.logger.Debugf("context canceled while checking service")
		return false
	}

	_, _, err := d.Client.ServiceInspectWithRaw(ctx, service.ID, dockerTypes.ServiceInspectOptions{})
	if err != nil {
		if errdefs.IsNotFound(err) {
			service.logger.Debugf("service no longer exists")
			return false
		}

		// Other errors (connection issues, etc.) - assume service still exists
		service.logger.Debugf("failed to inspect: %v (assuming still running)", err)

		return true
	}

	service.logger.Debugf("service %s still exists", service.Name)

	return true
}

func (d *DockerSource) TailContainer(ctx context.Context, container *ContainerConfig, outChan chan types.Event, deleteChan chan *ContainerConfig) error {
	container.logger.Info("start monitoring")

	// we'll use just the interval generator, won't call backoff.Retry()
	bo := d.backoffFactory()
	firstRetry := true

	for {
		err := d.tailContainerAttempt(ctx, container, outChan, bo)
		if err == nil {
			// Successful completion - container was stopped gracefully
			return nil
		}

		// Check container health to determine if we should retry or give up
		containerHealthy := d.isContainerStillRunning(ctx, container)
		if !containerHealthy {
			// Container is dead/stopped - don't retry, remove from monitoring
			container.logger.Infof("container no longer running, removing from monitoring: %v", err)
			deleteChan <- container
			return err
		}

		// Container is still running, so this is likely a temporary network/proxy issue
		// Update the Since timestamp to avoid re-reading logs from before the failure
		container.logOptions.Since = time.Now().UTC().Format(time.RFC3339)

		// retry immediately, the tail may have failed due to idle disconnection from a proxy
		if firstRetry {
			firstRetry = false
			container.logger.Debugf("tail failed but container is (presumed) healthy: %v, retrying immediately", err)
			continue
		}

		wait := bo.NextBackOff()

		container.logger.Debugf("tail failed but container is (presumed) healthy: %v, retrying in %s", err, wait)

		select {
		case <-time.After(wait):
		case <-container.t.Dying():
			container.logger.Infof("tail stopped")
			return nil
		}
	}
}

func (d *DockerSource) tailContainerAttempt(ctx context.Context, container *ContainerConfig, outChan chan types.Event, bo backoff.BackOff) error {
	dockerReader, err := d.Client.ContainerLogs(ctx, container.ID, *container.logOptions)
	if err != nil {
		return fmt.Errorf("unable to read logs from container %s: %w", container.Name, err)
	}

	// Log connection (both initial and reconnections)
	container.logger.Info("connected to container logs")

	// reset backoff so for the next disconnect, the interval doesn't start from 30sec
	bo.Reset()

	var scanner *bufio.Scanner
	// we use this library to normalize docker API logs (cf. https://ahmet.im/blog/docker-logs-api-binary-format-explained/)
	if container.Tty {
		scanner = bufio.NewScanner(dockerReader)
	} else {
		reader := dlog.NewReader(dockerReader)
		scanner = bufio.NewScanner(reader)
	}

	readerChan := make(chan string)
	readerTomb := &tomb.Tomb{}
	readerTomb.Go(func() error {
		return ReadTailScanner(scanner, readerChan, readerTomb)
	})

	for {
		select {
		case <-container.t.Dying():
			readerTomb.Kill(nil)
			return nil
		case line := <-readerChan:
			if line == "" {
				continue
			}

			l := types.Line{}
			l.Raw = line
			l.Labels = container.Labels
			l.Time = time.Now().UTC()
			l.Src = container.Name
			l.Process = true
			l.Module = d.GetName()
			evt := types.MakeEvent(d.Config.UseTimeMachine, types.LOG, true)
			evt.Line = l

			if d.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				metrics.DockerDatasourceLinesRead.With(prometheus.Labels{"source": container.Name, "datasource_type": "docker", "acquis_type": evt.Line.Labels["type"]}).Inc()
			}

			outChan <- evt

			d.logger.Debugf("Sent line to parsing: %+v", evt.Line.Raw)
		case <-readerTomb.Dying():
			// This case is to handle temporarily losing the connection to the docker socket
			// The only known case currently is when using docker-socket-proxy (and maybe a docker daemon restart)
			container.logger.Debugf("readerTomb dying, connection lost")
			readerTomb.Kill(nil)

			return fmt.Errorf("reader connection lost for container %s", container.Name)
		}
	}
}

func (d *DockerSource) TailService(ctx context.Context, service *ContainerConfig, outChan chan types.Event, deleteChan chan *ContainerConfig) error {
	service.logger.Info("start monitoring")

	// we'll use just the interval generator, won't call backoff.Retry()
	bo := d.backoffFactory()
	firstRetry := true

	for {
		err := d.tailServiceAttempt(ctx, service, outChan, bo)
		if err == nil {
			// Successful completion - service was stopped gracefully
			return nil
		}

		// Check service health to determine if we should retry or give up
		serviceHealthy := d.isServiceStillRunning(ctx, service)

		if !serviceHealthy {
			// Service was removed - don't retry, remove from monitoring
			service.logger.Infof("service no longer exists, removing from monitoring: %v", err)
			deleteChan <- service
			return err
		}

		// Service still exists, so this is likely a temporary network/proxy issue
		// Update the Since timestamp to avoid re-reading logs from before the failure
		service.logOptions.Since = time.Now().UTC().Format(time.RFC3339)

		// retry immediately, the tail may have failed due to idle disconnection from a proxy
		if firstRetry {
			firstRetry = false
			service.logger.Debugf("tail failed but service is (presumed) healthy: %v, retrying immediately", err)
			continue
		}

		wait := bo.NextBackOff()

		service.logger.Debugf("tail failed but service is (presumed) healthy: %v, retrying in %s", err, wait)

		select {
		case <-time.After(wait):
		case <-service.t.Dying():
			service.logger.Infof("tail stopped")
			return nil
		}
	}
}

func (d *DockerSource) tailServiceAttempt(ctx context.Context, service *ContainerConfig, outChan chan types.Event, bo backoff.BackOff) error {
	// For services, we need to get the service logs using the service logs API
	// Docker service logs aggregates logs from all running tasks of the service
	dockerReader, err := d.Client.ServiceLogs(ctx, service.ID, *service.logOptions)
	if err != nil {
		return fmt.Errorf("unable to read logs from service %s: %w", service.Name, err)
	}

	// Log connection (both initial and reconnections)
	service.logger.Info("connected to service logs")

	bo.Reset()

	// Service logs don't use TTY, so we always use the dlog reader
	reader := dlog.NewReader(dockerReader)
	scanner := bufio.NewScanner(reader)

	readerChan := make(chan string)
	readerTomb := &tomb.Tomb{}
	readerTomb.Go(func() error {
		return ReadTailScanner(scanner, readerChan, readerTomb)
	})

	for {
		select {
		case <-service.t.Dying():
			readerTomb.Kill(nil)
			return nil
		case line := <-readerChan:
			if line == "" {
				continue
			}

			l := types.Line{}
			l.Raw = line
			l.Labels = service.Labels
			l.Time = time.Now().UTC()
			l.Src = service.Name
			l.Process = true
			l.Module = d.GetName()
			evt := types.MakeEvent(d.Config.UseTimeMachine, types.LOG, true)
			evt.Line = l

			if d.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				metrics.DockerDatasourceLinesRead.With(prometheus.Labels{"source": service.Name, "acquis_type": l.Labels["type"], "datasource_type": "docker"}).Inc()
			}

			outChan <- evt

			d.logger.Debugf("Sent line to parsing: %+v", evt.Line.Raw)
		case <-readerTomb.Dying():
			// Handle connection loss similar to containers
			service.logger.Debugf("readerTomb dying, connection lost")
			readerTomb.Kill(nil)

			return fmt.Errorf("reader connection lost for service %s", service.Name)
		}
	}
}

func (d *DockerSource) ContainerManager(ctx context.Context, in chan *ContainerConfig, deleteChan chan *ContainerConfig, outChan chan types.Event) error {
	d.logger.Info("Container Manager started")

	for {
		select {
		case newContainer := <-in:
			if _, ok := d.runningContainerState[newContainer.ID]; !ok {
				newContainer.logger = d.logger.WithField("container_name", newContainer.Name)
				newContainer.t.Go(func() error {
					return d.TailContainer(ctx, newContainer, outChan, deleteChan)
				})

				d.runningContainerState[newContainer.ID] = newContainer
			}
		case containerToDelete := <-deleteChan:
			if containerConfig, ok := d.runningContainerState[containerToDelete.ID]; ok {
				log.Infof("container acquisition stopped for container '%s'", containerConfig.Name)
				containerConfig.t.Kill(nil)
				delete(d.runningContainerState, containerToDelete.ID)
			}
		case <-d.t.Dying():
			for _, container := range d.runningContainerState {
				if container.t.Alive() {
					d.logger.Infof("killing tail for container %s", container.Name)
					container.t.Kill(nil)

					if err := container.t.Wait(); err != nil {
						d.logger.Infof("error while waiting for death of %s : %s", container.Name, err)
					}
				}
			}

			d.runningContainerState = nil
			d.logger.Debugf("routine cleanup done, return")

			return nil
		}
	}
}

func (d *DockerSource) ServiceManager(ctx context.Context, in chan *ContainerConfig, deleteChan chan *ContainerConfig, outChan chan types.Event) error {
	d.logger.Info("Service Manager started")

	for {
		select {
		case newService := <-in:
			if _, ok := d.runningServiceState[newService.ID]; !ok {
				newService.logger = d.logger.WithField("service_name", newService.Name)
				newService.t.Go(func() error {
					return d.TailService(ctx, newService, outChan, deleteChan)
				})

				d.runningServiceState[newService.ID] = newService
			}
		case serviceToDelete := <-deleteChan:
			if serviceConfig, ok := d.runningServiceState[serviceToDelete.ID]; ok {
				d.logger.Infof("service acquisition stopped for service '%s'", serviceConfig.Name)
				serviceConfig.t.Kill(nil)
				delete(d.runningServiceState, serviceToDelete.ID)
			}
		case <-d.t.Dying():
			for _, service := range d.runningServiceState {
				if service.t.Alive() {
					d.logger.Infof("killing tail for service %s", service.Name)
					service.t.Kill(nil)

					if err := service.t.Wait(); err != nil {
						d.logger.Infof("error while waiting for death of %s : %s", service.Name, err)
					}
				}
			}

			d.runningServiceState = nil
			d.logger.Debugf("service manager cleanup done, return")

			return nil
		}
	}
}
