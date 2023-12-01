package dockeracquisition

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	dockerTypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/dlog"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

var linesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_dockersource_hits_total",
		Help: "Total lines that were read.",
	},
	[]string{"source"})

type DockerConfiguration struct {
	CheckInterval                     string   `yaml:"check_interval"`
	FollowStdout                      bool     `yaml:"follow_stdout"`
	FollowStdErr                      bool     `yaml:"follow_stderr"`
	Until                             string   `yaml:"until"`
	Since                             string   `yaml:"since"`
	DockerHost                        string   `yaml:"docker_host"`
	ContainerName                     []string `yaml:"container_name"`
	ContainerID                       []string `yaml:"container_id"`
	ContainerNameRegexp               []string `yaml:"container_name_regexp"`
	ContainerIDRegexp                 []string `yaml:"container_id_regexp"`
	ForceInotify                      bool     `yaml:"force_inotify"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type DockerSource struct {
	Config                DockerConfiguration
	runningContainerState map[string]*ContainerConfig
	compiledContainerName []*regexp.Regexp
	compiledContainerID   []*regexp.Regexp
	CheckIntervalDuration time.Duration
	logger                *log.Entry
	Client                client.CommonAPIClient
	t                     *tomb.Tomb
	containerLogsOptions  *dockerTypes.ContainerLogsOptions
}

type ContainerConfig struct {
	Name   string
	ID     string
	t      *tomb.Tomb
	logger *log.Entry
	Labels map[string]string
	Tty    bool
}

func (d *DockerSource) GetUuid() string {
	return d.Config.UniqueId
}

func (d *DockerSource) UnmarshalConfig(yamlConfig []byte) error {
	d.Config = DockerConfiguration{
		FollowStdout:  true, // default
		FollowStdErr:  true, // default
		CheckInterval: "1s", // default
	}

	err := yaml.UnmarshalStrict(yamlConfig, &d.Config)
	if err != nil {
		return fmt.Errorf("while parsing DockerAcquisition configuration: %w", err)
	}

	if d.logger != nil {
		d.logger.Tracef("DockerAcquisition configuration: %+v", d.Config)
	}

	if len(d.Config.ContainerName) == 0 && len(d.Config.ContainerID) == 0 && len(d.Config.ContainerIDRegexp) == 0 && len(d.Config.ContainerNameRegexp) == 0 {
		return fmt.Errorf("no containers names or containers ID configuration provided")
	}

	d.CheckIntervalDuration, err = time.ParseDuration(d.Config.CheckInterval)
	if err != nil {
		return fmt.Errorf("parsing 'check_interval' parameters: %s", d.CheckIntervalDuration)
	}

	if d.Config.Mode == "" {
		d.Config.Mode = configuration.TAIL_MODE
	}
	if d.Config.Mode != configuration.CAT_MODE && d.Config.Mode != configuration.TAIL_MODE {
		return fmt.Errorf("unsupported mode %s for docker datasource", d.Config.Mode)
	}

	for _, cont := range d.Config.ContainerNameRegexp {
		d.compiledContainerName = append(d.compiledContainerName, regexp.MustCompile(cont))
	}

	for _, cont := range d.Config.ContainerIDRegexp {
		d.compiledContainerID = append(d.compiledContainerID, regexp.MustCompile(cont))
	}

	if d.Config.Since == "" {
		d.Config.Since = time.Now().UTC().Format(time.RFC3339)
	}

	d.containerLogsOptions = &dockerTypes.ContainerLogsOptions{
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

func (d *DockerSource) Configure(yamlConfig []byte, logger *log.Entry) error {
	d.logger = logger

	err := d.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	d.runningContainerState = make(map[string]*ContainerConfig)

	d.logger.Tracef("Actual DockerAcquisition configuration %+v", d.Config)

	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	if d.Config.DockerHost != "" {
		err = client.WithHost(d.Config.DockerHost)(dockerClient)
		if err != nil {
			return err
		}
	}
	d.Client = dockerClient

	_, err = d.Client.Info(context.Background())
	if err != nil {
		return fmt.Errorf("failed to configure docker datasource %s: %w", d.Config.DockerHost, err)
	}

	return nil
}

func (d *DockerSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	var err error

	if !strings.HasPrefix(dsn, d.GetName()+"://") {
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
	d.Config.Mode = configuration.CAT_MODE
	d.logger = logger
	d.Config.Labels = labels

	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	d.containerLogsOptions = &dockerTypes.ContainerLogsOptions{
		ShowStdout: d.Config.FollowStdout,
		ShowStderr: d.Config.FollowStdErr,
		Follow:     false,
	}
	dsn = strings.TrimPrefix(dsn, d.GetName()+"://")
	args := strings.Split(dsn, "?")

	if len(args) == 0 {
		return fmt.Errorf("invalid dsn: %s", dsn)
	}

	if len(args) == 1 && args[0] == "" {
		return fmt.Errorf("empty %s DSN", d.GetName()+"://")
	}
	d.Config.ContainerName = append(d.Config.ContainerName, args[0])
	// we add it as an ID also so user can provide docker name or docker ID
	d.Config.ContainerID = append(d.Config.ContainerID, args[0])

	// no parameters
	if len(args) == 1 {
		d.Client = dockerClient
		return nil
	}

	parameters, err := url.ParseQuery(args[1])
	if err != nil {
		return fmt.Errorf("while parsing parameters %s: %w", dsn, err)
	}

	for k, v := range parameters {
		switch k {
		case "log_level":
			if len(v) != 1 {
				return fmt.Errorf("only one 'log_level' parameters is required, not many")
			}
			lvl, err := log.ParseLevel(v[0])
			if err != nil {
				return fmt.Errorf("unknown level %s: %w", v[0], err)
			}
			d.logger.Logger.SetLevel(lvl)
		case "until":
			if len(v) != 1 {
				return fmt.Errorf("only one 'until' parameters is required, not many")
			}
			d.containerLogsOptions.Until = v[0]
		case "since":
			if len(v) != 1 {
				return fmt.Errorf("only one 'since' parameters is required, not many")
			}
			d.containerLogsOptions.Since = v[0]
		case "follow_stdout":
			if len(v) != 1 {
				return fmt.Errorf("only one 'follow_stdout' parameters is required, not many")
			}
			followStdout, err := strconv.ParseBool(v[0])
			if err != nil {
				return fmt.Errorf("parsing 'follow_stdout' parameters: %s", err)
			}
			d.Config.FollowStdout = followStdout
			d.containerLogsOptions.ShowStdout = followStdout
		case "follow_stderr":
			if len(v) != 1 {
				return fmt.Errorf("only one 'follow_stderr' parameters is required, not many")
			}
			followStdErr, err := strconv.ParseBool(v[0])
			if err != nil {
				return fmt.Errorf("parsing 'follow_stderr' parameters: %s", err)
			}
			d.Config.FollowStdErr = followStdErr
			d.containerLogsOptions.ShowStderr = followStdErr
		case "docker_host":
			if len(v) != 1 {
				return fmt.Errorf("only one 'docker_host' parameters is required, not many")
			}
			if err := client.WithHost(v[0])(dockerClient); err != nil {
				return err
			}
		}
	}
	d.Client = dockerClient
	return nil
}

func (d *DockerSource) GetMode() string {
	return d.Config.Mode
}

// SupportedModes returns the supported modes by the acquisition module
func (d *DockerSource) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}

// OneShotAcquisition reads a set of file and returns when done
func (d *DockerSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	d.logger.Debug("In oneshot")
	runningContainer, err := d.Client.ContainerList(context.Background(), dockerTypes.ContainerListOptions{})
	if err != nil {
		return err
	}
	foundOne := false
	for _, container := range runningContainer {
		if _, ok := d.runningContainerState[container.ID]; ok {
			d.logger.Debugf("container with id %s is already being read from", container.ID)
			continue
		}
		if containerConfig, ok := d.EvalContainer(container); ok {
			d.logger.Infof("reading logs from container %s", containerConfig.Name)
			d.logger.Debugf("logs options: %+v", *d.containerLogsOptions)
			dockerReader, err := d.Client.ContainerLogs(context.Background(), containerConfig.ID, *d.containerLogsOptions)
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
					linesRead.With(prometheus.Labels{"source": containerConfig.Name}).Inc()
					evt := types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.TIMEMACHINE}
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

func (d *DockerSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (d *DockerSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (d *DockerSource) GetName() string {
	return "docker"
}

func (d *DockerSource) CanRun() error {
	return nil
}

func (d *DockerSource) getContainerTTY(containerId string) bool {
	containerDetails, err := d.Client.ContainerInspect(context.Background(), containerId)
	if err != nil {
		return false
	}
	return containerDetails.Config.Tty
}

func (d *DockerSource) EvalContainer(container dockerTypes.Container) (*ContainerConfig, bool) {
	for _, containerID := range d.Config.ContainerID {
		if containerID == container.ID {
			return &ContainerConfig{ID: container.ID, Name: container.Names[0], Labels: d.Config.Labels, Tty: d.getContainerTTY(container.ID)}, true
		}
	}

	for _, containerName := range d.Config.ContainerName {
		for _, name := range container.Names {
			if strings.HasPrefix(name, "/") && len(name) > 0 {
				name = name[1:]
			}
			if name == containerName {
				return &ContainerConfig{ID: container.ID, Name: name, Labels: d.Config.Labels, Tty: d.getContainerTTY(container.ID)}, true
			}
		}

	}

	for _, cont := range d.compiledContainerID {
		if matched := cont.MatchString(container.ID); matched {
			return &ContainerConfig{ID: container.ID, Name: container.Names[0], Labels: d.Config.Labels, Tty: d.getContainerTTY(container.ID)}, true
		}
	}

	for _, cont := range d.compiledContainerName {
		for _, name := range container.Names {
			if matched := cont.MatchString(name); matched {
				return &ContainerConfig{ID: container.ID, Name: name, Labels: d.Config.Labels, Tty: d.getContainerTTY(container.ID)}, true
			}
		}

	}

	return &ContainerConfig{}, false
}

func (d *DockerSource) WatchContainer(monitChan chan *ContainerConfig, deleteChan chan *ContainerConfig) error {
	ticker := time.NewTicker(d.CheckIntervalDuration)
	d.logger.Infof("Container watcher started, interval: %s", d.CheckIntervalDuration.String())
	for {
		select {
		case <-d.t.Dying():
			d.logger.Infof("stopping container watcher")
			return nil
		case <-ticker.C:
			// to track for garbage collection
			runningContainersID := make(map[string]bool)
			runningContainer, err := d.Client.ContainerList(context.Background(), dockerTypes.ContainerListOptions{})
			if err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "cannot connect to the docker daemon at") {
					for idx, container := range d.runningContainerState {
						if d.runningContainerState[idx].t.Alive() {
							d.logger.Infof("killing tail for container %s", container.Name)
							d.runningContainerState[idx].t.Kill(nil)
							if err := d.runningContainerState[idx].t.Wait(); err != nil {
								d.logger.Infof("error while waiting for death of %s : %s", container.Name, err)
							}
						}
						delete(d.runningContainerState, idx)
					}
				} else {
					log.Errorf("container list err: %s", err)
				}
				continue
			}

			for _, container := range runningContainer {
				runningContainersID[container.ID] = true

				// don't need to re eval an already monitored container
				if _, ok := d.runningContainerState[container.ID]; ok {
					continue
				}
				if containerConfig, ok := d.EvalContainer(container); ok {
					monitChan <- containerConfig
				}
			}

			for containerStateID, containerConfig := range d.runningContainerState {
				if _, ok := runningContainersID[containerStateID]; !ok {
					deleteChan <- containerConfig
				}
			}
			d.logger.Tracef("Reading logs from %d containers", len(d.runningContainerState))

			ticker.Reset(d.CheckIntervalDuration)
		}
	}
}

func (d *DockerSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	d.t = t
	monitChan := make(chan *ContainerConfig)
	deleteChan := make(chan *ContainerConfig)
	d.logger.Infof("Starting docker acquisition")
	t.Go(func() error {
		return d.DockerManager(monitChan, deleteChan, out)
	})

	return d.WatchContainer(monitChan, deleteChan)
}

func (d *DockerSource) Dump() interface{} {
	return d
}

func ReadTailScanner(scanner *bufio.Scanner, out chan string, t *tomb.Tomb) error {
	for scanner.Scan() {
		out <- scanner.Text()
	}
	return scanner.Err()
}

func (d *DockerSource) TailDocker(container *ContainerConfig, outChan chan types.Event, deleteChan chan *ContainerConfig) error {
	container.logger.Infof("start tail for container %s", container.Name)
	dockerReader, err := d.Client.ContainerLogs(context.Background(), container.ID, *d.containerLogsOptions)
	if err != nil {
		container.logger.Errorf("unable to read logs from container: %+v", err)
		return err
	}

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
			container.logger.Infof("tail stopped for container %s", container.Name)
			return nil
		case line := <-readerChan:
			if line == "" {
				continue
			}
			l := types.Line{}
			l.Raw = line
			l.Labels = d.Config.Labels
			l.Time = time.Now().UTC()
			l.Src = container.Name
			l.Process = true
			l.Module = d.GetName()
			var evt types.Event
			if !d.Config.UseTimeMachine {
				evt = types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.LIVE}
			} else {
				evt = types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.TIMEMACHINE}
			}
			linesRead.With(prometheus.Labels{"source": container.Name}).Inc()
			outChan <- evt
			d.logger.Debugf("Sent line to parsing: %+v", evt.Line.Raw)
		case <-readerTomb.Dying():
			//This case is to handle temporarily losing the connection to the docker socket
			//The only known case currently is when using docker-socket-proxy (and maybe a docker daemon restart)
			d.logger.Debugf("readerTomb dying for container %s, removing it from runningContainerState", container.Name)
			deleteChan <- container
			//Also reset the Since to avoid re-reading logs
			d.Config.Since = time.Now().UTC().Format(time.RFC3339)
			d.containerLogsOptions.Since = d.Config.Since
			return nil
		}
	}
}

func (d *DockerSource) DockerManager(in chan *ContainerConfig, deleteChan chan *ContainerConfig, outChan chan types.Event) error {
	d.logger.Info("DockerSource Manager started")
	for {
		select {
		case newContainer := <-in:
			if _, ok := d.runningContainerState[newContainer.ID]; !ok {
				newContainer.t = &tomb.Tomb{}
				newContainer.logger = d.logger.WithFields(log.Fields{"container_name": newContainer.Name})
				newContainer.t.Go(func() error {
					return d.TailDocker(newContainer, outChan, deleteChan)
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
			for idx, container := range d.runningContainerState {
				if d.runningContainerState[idx].t.Alive() {
					d.logger.Infof("killing tail for container %s", container.Name)
					d.runningContainerState[idx].t.Kill(nil)
					if err := d.runningContainerState[idx].t.Wait(); err != nil {
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
