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
	Until                             []string `yaml:"until"`
	Since                             []string `yaml:"since"`
	DockerHost                        []string `yaml:"docker_host"`
	ContainerName                     []string `yaml:"container_name"`
	ContainerID                       []string `yaml:"container_id"`
	ContainerNameRegexp               []string `yaml:"container_name_regexp"`
	ContainerIDRegexp                 []string `yaml:"container_id_regexp"`
	ForceInotify                      bool     `yaml:"force_inotify"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type DockerSource struct {
	Config               DockerConfiguration
	watcherDockersByName map[string]bool
	watcherDockersByID   map[string]bool
	runningDockersByID   map[string]*ContainerConfig
	compileContainerName []*regexp.Regexp
	compileContainerID   []*regexp.Regexp
	logger               *log.Entry
	docker               []string
	Client               *client.Client
	t                    *tomb.Tomb
}

type ContainerConfig struct {
	Name       string
	ID         string
	t          *tomb.Tomb
	logger     *log.Entry
	readerTomb *tomb.Tomb
	Labels     map[string]string
}

func (d *DockerSource) Configure(Config []byte, logger *log.Entry) error {
	var err error
	dockerConfig := DockerConfiguration{}
	d.logger = logger
	d.Client, err = client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}
	d.runningDockersByID = make(map[string]*ContainerConfig)
	d.watcherDockersByName = make(map[string]bool)
	d.watcherDockersByID = make(map[string]bool)
	err = yaml.UnmarshalStrict(Config, &dockerConfig)
	if err != nil {
		return errors.Wrap(err, "Cannot parse DockerAcquisition configuration")
	}
	d.logger.Tracef("DockerAcquisition configuration: %+v", dockerConfig)
	if len(dockerConfig.ContainerName) == 0 && len(dockerConfig.ContainerID) == 0 {
		return fmt.Errorf("no containers names or containers ID configuration provided")
	}
	d.Config = dockerConfig
	if d.Config.Mode == "" {
		d.Config.Mode = configuration.TAIL_MODE
	}
	if d.Config.Mode != configuration.CAT_MODE && d.Config.Mode != configuration.TAIL_MODE {
		return fmt.Errorf("unsupported mode %s for file source", d.Config.Mode)
	}
	d.logger.Tracef("Actual FileAcquisition Configuration %+v", d.Config)

	for _, cont := range d.Config.ContainerNameRegexp {
		d.compileContainerName = append(d.compileContainerName, regexp.MustCompile(cont))
	}

	for _, cont := range d.Config.ContainerIDRegexp {
		d.compileContainerID = append(d.compileContainerID, regexp.MustCompile(cont))
	}

	return nil
}

func (d *DockerSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry) error {
	if !strings.HasPrefix(dsn, "docker://") {
		return fmt.Errorf("invalid DSN %s for file source, must start with file://", dsn)
	}
	d.Config.Mode = configuration.CAT_MODE
	d.logger = logger

	dsn = strings.TrimPrefix(dsn, "docker://")

	args := strings.Split(dsn, "?")

	if len(args[0]) == 0 {
		return fmt.Errorf("empty docker:// DSN")
	}

	if len(args) == 2 && len(args[1]) != 0 {
		params, err := url.ParseQuery(args[1])
		if err != nil {
			return fmt.Errorf("could not parse docker args : %s", err)
		}
		for key, value := range params {
			if key != "log_level" {
				return fmt.Errorf("unsupported key %s in docker DSN", key)
			}
			if len(value) != 1 {
				return fmt.Errorf("expected zero or one value for 'log_level'")
			}
			lvl, err := log.ParseLevel(value[0])
			if err != nil {
				return errors.Wrapf(err, "unknown level %s", value[0])
			}
			d.logger.Logger.SetLevel(lvl)
		}
	}

	d.Config = DockerConfiguration{}
	d.Config.Labels = labels

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
	for _, container := range runningContainer {
		if containerConfig, ok := d.EvalContainer(container); ok {
			reader, err := d.Client.ContainerLogs(context.Background(), containerConfig.ID, options)
			if err != nil {
				d.logger.Error("unable to read logs from container: %+v", err)
				return err
			}
			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				if scanner.Text() == "" {
					continue
				}
				l := types.Line{}
				l.Raw = scanner.Text()
				l.Labels = d.Config.Labels
				l.Time = time.Now()
				l.Src = containerConfig.Name
				l.Process = true
				l.Module = d.GetName()
				linesRead.With(prometheus.Labels{"source": containerConfig.Name}).Inc()
				evt := types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}
				out <- evt
			}
		}
	}
	d.t.Kill(nil)

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
	for _, containerName := range d.Config.ContainerName {
		for _, name := range container.Names {
			if name == containerName {
				return &ContainerConfig{ID: container.ID, Name: name, Labels: d.Config.Labels}, true
			}
		}

	}

	for _, containerID := range d.Config.ContainerID {
		if containerID == container.ID {
			return &ContainerConfig{ID: container.ID, Name: container.Names[0], Labels: d.Config.Labels}, true
		}
	}

	for _, cont := range d.compileContainerName {
		for _, name := range container.Names {
			if matched := cont.Match([]byte(name)); matched {
				return &ContainerConfig{ID: container.ID, Name: name, Labels: d.Config.Labels}, true
			}
		}

	}

	for _, cont := range d.compileContainerID {
		if matched := cont.Match([]byte(container.ID)); matched {
			return &ContainerConfig{ID: container.ID, Name: container.Names[0], Labels: d.Config.Labels}, true

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
				if containerConfig, ok := d.EvalContainer(container); ok {
					monitChan <- containerConfig
				}
			}
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
	options := dockerTypes.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: false,
		Follow:     true,
		Since:      time.Now().Format(time.RFC3339),
	}
	container.logger.Infof("start tail for container %s", container.Name)
	reader, err := d.Client.ContainerLogs(context.Background(), container.ID, options)
	if err != nil {
		container.logger.Error("unable to read logs from container: %+v", err)
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
			d.logger.Infof("Line: %s", line)
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
			d.logger.Debugf("Send event to parsing: %+v", evt)
		}
	}
}

func (d *DockerSource) DockerManager(in chan *ContainerConfig, outChan chan types.Event) error {
	d.logger.Info("DockerSource Manager started")
	for {
		select {
		case newContainer := <-in:
			if _, ok := d.runningDockersByID[newContainer.ID]; !ok {
				newContainer.t = &tomb.Tomb{}
				newContainer.logger = d.logger.WithFields(log.Fields{"container_name": newContainer.Name})
				d.logger.Debugf("starting tail of docker %s", newContainer.Name)
				newContainer.t.Go(func() error {
					return d.TailDocker(newContainer, outChan)
				})
				d.runningDockersByID[newContainer.ID] = newContainer
			}
		case <-d.t.Dying():
			for idx, container := range d.runningDockersByID {
				if d.runningDockersByID[idx].t.Alive() {
					d.logger.Infof("killing tail for container %s", container.Name)
					d.runningDockersByID[idx].t.Kill(nil)
					if err := d.runningDockersByID[idx].t.Wait(); err != nil {
						d.logger.Infof("error while waiting for death of %s : %s", container.Name, err)
					}
				}
			}
			d.runningDockersByID = nil
			d.logger.Debugf("routine cleanup done, return")
			return nil
		}
	}
}
