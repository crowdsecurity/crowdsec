package dockeracquisition

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	dockerTypes "github.com/docker/docker/api/types"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/docker/docker/client"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

var linesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_dockersource_hits_total",
		Help: "Total lines that were read.",
	},
	[]string{"source"})

type DockerConfiguration struct {
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
}

func (d *DockerSource) Configure(Config []byte, logger *log.Entry) error {
	var err error

	d.Config = DockerConfiguration{}
	d.logger = logger

	d.runningContainerState = make(map[string]*ContainerConfig)

	err = yaml.UnmarshalStrict(Config, &d.Config)
	if err != nil {
		return errors.Wrap(err, "Cannot parse DockerAcquisition configuration")
	}
	d.logger.Tracef("DockerAcquisition configuration: %+v", d.Config)
	if len(d.Config.ContainerName) == 0 && len(d.Config.ContainerID) == 0 && len(d.Config.ContainerIDRegexp) == 0 && len(d.Config.ContainerNameRegexp) == 0 {
		return fmt.Errorf("no containers names or containers ID configuration provided")
	}

	if d.Config.Mode == "" {
		d.Config.Mode = configuration.TAIL_MODE
	}
	if d.Config.Mode != configuration.CAT_MODE && d.Config.Mode != configuration.TAIL_MODE {
		return fmt.Errorf("unsupported mode %s for docker datasource", d.Config.Mode)
	}
	d.logger.Tracef("Actual DockerAcquisition configuration %+v", d.Config)

	for _, cont := range d.Config.ContainerNameRegexp {
		d.compiledContainerName = append(d.compiledContainerName, regexp.MustCompile(cont))
	}

	for _, cont := range d.Config.ContainerIDRegexp {
		d.compiledContainerID = append(d.compiledContainerID, regexp.MustCompile(cont))
	}

	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}

	if d.Config.Since == "" {
		d.Config.Since = time.Now().Format(time.RFC3339)
	}

	d.containerLogsOptions = &dockerTypes.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: false,
		Follow:     true,
		Since:      d.Config.Since,
	}

	if d.Config.Until != "" {
		d.containerLogsOptions.Until = d.Config.Until
	}

	if d.Config.DockerHost != "" {
		if err := client.WithHost(d.Config.DockerHost)(dockerClient); err != nil {
			return err
		}
	}
	d.Client = dockerClient

	return nil
}

func (d *DockerSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry) error {
	var err error

	if !strings.HasPrefix(dsn, d.GetName()+"://") {
		return fmt.Errorf("invalid DSN %s for docker source, must start with %s://", dsn, d.GetName())
	}

	d.Config = DockerConfiguration{}
	d.Config.ContainerName = make([]string, 0)
	d.Config.ContainerID = make([]string, 0)
	d.runningContainerState = make(map[string]*ContainerConfig)
	d.Config.Mode = configuration.CAT_MODE
	d.logger = logger
	d.Config.Labels = labels
	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}

	d.containerLogsOptions = &dockerTypes.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: false,
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
		return errors.Wrapf(err, "while parsing parameters %s: %s", dsn, err)
	}

	for k, v := range parameters {
		switch k {
		case "log_level":
			if len(v) != 1 {
				return fmt.Errorf("only one 'log_level' parameters is required, not many")
			}
			lvl, err := log.ParseLevel(v[0])
			if err != nil {
				return errors.Wrapf(err, "unknown level %s", v[0])
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
			d.containerLogsOptions.Until = v[0]
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

//SupportedModes returns the supported modes by the acquisition module
func (d *DockerSource) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}

//OneShotAcquisition reads a set of file and returns when done
func (d *DockerSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	d.logger.Debug("In oneshot")

	options := dockerTypes.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: false,
		Follow:     false,
	}

	runningContainer, err := d.Client.ContainerList(context.Background(), dockerTypes.ContainerListOptions{})
	if err != nil {
		return err
	}

	foundOne := false
	for _, container := range runningContainer {
		if _, ok := d.runningContainerState[container.ID]; ok {
			d.logger.Debugf("container with id %s was already read", container.ID)
			continue
		}
		if containerConfig, ok := d.EvalContainer(container); ok {
			reader, err := d.Client.ContainerLogs(context.Background(), containerConfig.ID, options)
			if err != nil {
				d.logger.Errorf("unable to read logs from container: %+v", err)
				return err
			}
			foundOne = true
			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				line := scanner.Text()
				if line == "" {
					continue
				}
				if len(line) > 8 {
					line = line[8:]
				}
				if line == "" {
					continue
				}
				l := types.Line{}
				l.Raw = line
				l.Labels = d.Config.Labels
				l.Time = time.Now()
				l.Src = containerConfig.Name
				l.Process = true
				l.Module = d.GetName()
				linesRead.With(prometheus.Labels{"source": containerConfig.Name}).Inc()
				evt := types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}
				out <- evt
				d.logger.Debugf("Send line to parsing: %+v", evt.Line.Raw)
			}
			d.runningContainerState[container.ID] = containerConfig
		}
	}

	t.Kill(nil)

	if !foundOne {
		return fmt.Errorf("no docker found, can't run one shot acquisition")
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

func (d *DockerSource) EvalContainer(container dockerTypes.Container) (*ContainerConfig, bool) {
	for _, containerID := range d.Config.ContainerID {
		if containerID == container.ID {
			return &ContainerConfig{ID: container.ID, Name: container.Names[0], Labels: d.Config.Labels}, true
		}
	}

	for _, containerName := range d.Config.ContainerName {
		for _, name := range container.Names {
			if strings.HasPrefix(name, "/") && len(name) > 0 {
				name = name[1:]
			}
			if name == containerName {
				return &ContainerConfig{ID: container.ID, Name: name, Labels: d.Config.Labels}, true
			}
		}

	}

	for _, cont := range d.compiledContainerID {
		if matched := cont.Match([]byte(container.ID)); matched {
			return &ContainerConfig{ID: container.ID, Name: container.Names[0], Labels: d.Config.Labels}, true
		}
	}

	for _, cont := range d.compiledContainerName {
		for _, name := range container.Names {
			if matched := cont.Match([]byte(name)); matched {
				return &ContainerConfig{ID: container.ID, Name: name, Labels: d.Config.Labels}, true
			}
		}

	}

	return &ContainerConfig{}, false
}

func (d *DockerSource) WatchContainer(monitChan chan *ContainerConfig) error {
	ticker := time.NewTicker(1 * time.Second)

	for {
		select {
		case <-d.t.Dying():
			d.logger.Infof("stopping group watch")
			return nil
		case <-ticker.C:
			runningContainer, err := d.Client.ContainerList(context.Background(), dockerTypes.ContainerListOptions{})
			if err != nil {
				return err
			}
			for _, container := range runningContainer {
				// don't need to re eval an already monitored container
				if _, ok := d.runningContainerState[container.ID]; ok {
					continue
				}
				if containerConfig, ok := d.EvalContainer(container); ok {
					monitChan <- containerConfig
				}
			}
			ticker.Reset(1 * time.Second)
		}
	}
}

func (d *DockerSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	d.t = t
	monitChan := make(chan *ContainerConfig)
	d.logger.Infof("Starting docker acquisition")
	t.Go(func() error {
		return d.DockerManager(monitChan, out)
	})

	return d.WatchContainer(monitChan)
}

func (d *DockerSource) Dump() interface{} {
	return d
}

func ReadTailScanner(scanner *bufio.Scanner, out chan string, t *tomb.Tomb) error {
	for scanner.Scan() {
		out <- scanner.Text()
	}
	return nil
}

func (d *DockerSource) TailDocker(container *ContainerConfig, outChan chan types.Event) error {
	container.logger.Infof("start tail for container %s", container.Name)
	reader, err := d.Client.ContainerLogs(context.Background(), container.ID, *d.containerLogsOptions)
	if err != nil {
		container.logger.Errorf("unable to read logs from container: %+v", err)
		return err
	}
	scanner := bufio.NewScanner(reader)
	readerChan := make(chan string)
	readerTomb := &tomb.Tomb{}
	readerTomb.Go(func() error {
		return ReadTailScanner(scanner, readerChan, readerTomb)
	})
	for {
		select {
		case <-container.t.Dying():
			container.logger.Infof("stop tail for container %s", container.Name)
			readerTomb.Kill(nil)
			container.logger.Infof("tail stopped for container %s", container.Name)
			return fmt.Errorf("killed")
		case line := <-readerChan:
			if line == "" {
				continue
			}
			if len(line) > 8 {
				line = line[8:]
			}
			if line == "" {
				continue
			}

			l := types.Line{}
			l.Raw = line
			l.Labels = d.Config.Labels
			l.Time = time.Now()
			l.Src = container.Name
			l.Process = true
			l.Module = d.GetName()
			evt := types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}
			linesRead.With(prometheus.Labels{"source": container.Name}).Inc()
			outChan <- evt
			d.logger.Infof("Send line to parsing: %+v", evt.Line.Raw)
		}
	}
}

func (d *DockerSource) DockerManager(in chan *ContainerConfig, outChan chan types.Event) error {
	d.logger.Info("DockerSource Manager started")
	for {
		select {
		case newContainer := <-in:
			if _, ok := d.runningContainerState[newContainer.ID]; !ok {
				newContainer.t = &tomb.Tomb{}
				newContainer.logger = d.logger.WithFields(log.Fields{"container_name": newContainer.Name})
				d.logger.Debugf("starting tail of docker %s", newContainer.Name)
				newContainer.t.Go(func() error {
					return d.TailDocker(newContainer, outChan)
				})
				d.runningContainerState[newContainer.ID] = newContainer
			}
		case <-d.t.Dying():
			for idx, container := range d.runningContainerState {
				if d.runningContainerState[idx].t.Alive() {
					d.logger.Infof("killing tail for container %s", container.Name)
					d.runningContainerState[idx].t.Kill(nil)
					/*if err := d.runningContainerState[idx].t.Wait(); err != nil {
						d.logger.Infof("error while waiting for death of %s : %s", container.Name, err)
					}*/
				}
			}
			d.runningContainerState = nil
			d.logger.Debugf("routine cleanup done, return")
			return nil
		}
	}
}
