package journalctlacquisition

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type JournalCtlConfiguration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	Filters                           []string `yaml:"journalctl_filter"`
}

type JournalCtlSource struct {
	config JournalCtlConfiguration
	logger *log.Entry
	src    string
	args   []string
}

const journalctlCmd string = "journalctl"

var (
	journalctlArgsOneShot  = []string{}
	journalctlArgstreaming = []string{"--follow", "-n", "0"}
)

var linesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_journalctlsource_hits_total",
		Help: "Total lines that were read.",
	},
	[]string{"source"})

func readLine(scanner *bufio.Scanner, out chan string, errChan chan error) error {
	for scanner.Scan() {
		txt := scanner.Text()
		out <- txt
	}
	if errChan != nil && scanner.Err() != nil {
		errChan <- scanner.Err()
		close(errChan)
		// the error is already consumed by runJournalCtl
		return nil //nolint:nilerr
	}
	if errChan != nil {
		close(errChan)
	}
	return nil
}

func (j *JournalCtlSource) runJournalCtl(out chan types.Event, t *tomb.Tomb) error {
	ctx, cancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, journalctlCmd, j.args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("could not get journalctl stdout: %s", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("could not get journalctl stderr: %s", err)
	}

	stderrChan := make(chan string)
	stdoutChan := make(chan string)
	errChan := make(chan error, 1)

	logger := j.logger.WithField("src", j.src)

	logger.Infof("Running journalctl command: %s %s", cmd.Path, cmd.Args)
	err = cmd.Start()
	if err != nil {
		cancel()
		logger.Errorf("could not start journalctl command : %s", err)
		return err
	}

	stdoutscanner := bufio.NewScanner(stdout)

	if stdoutscanner == nil {
		cancel()
		cmd.Wait()
		return fmt.Errorf("failed to create stdout scanner")
	}

	stderrScanner := bufio.NewScanner(stderr)

	if stderrScanner == nil {
		cancel()
		cmd.Wait()
		return fmt.Errorf("failed to create stderr scanner")
	}
	t.Go(func() error {
		return readLine(stdoutscanner, stdoutChan, errChan)
	})
	t.Go(func() error {
		//looks like journalctl closes stderr quite early, so ignore its status (but not its output)
		return readLine(stderrScanner, stderrChan, nil)
	})

	for {
		select {
		case <-t.Dying():
			logger.Infof("journalctl datasource %s stopping", j.src)
			cancel()
			cmd.Wait() //avoid zombie process
			return nil
		case stdoutLine := <-stdoutChan:
			l := types.Line{}
			l.Raw = stdoutLine
			logger.Debugf("getting one line : %s", l.Raw)
			l.Labels = j.config.Labels
			l.Time = time.Now().UTC()
			l.Src = j.src
			l.Process = true
			l.Module = j.GetName()
			linesRead.With(prometheus.Labels{"source": j.src}).Inc()
			var evt types.Event
			if !j.config.UseTimeMachine {
				evt = types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.LIVE}
			} else {
				evt = types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.TIMEMACHINE}
			}
			out <- evt
		case stderrLine := <-stderrChan:
			logger.Warnf("Got stderr message : %s", stderrLine)
			err := fmt.Errorf("journalctl error : %s", stderrLine)
			t.Kill(err)
		case errScanner, ok := <-errChan:
			if !ok {
				logger.Debugf("errChan is closed, quitting")
				t.Kill(nil)
			}
			if errScanner != nil {
				t.Kill(errScanner)
			}
		}
	}
}

func (j *JournalCtlSource) GetUuid() string {
	return j.config.UniqueId
}

func (j *JournalCtlSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (j *JournalCtlSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (j *JournalCtlSource) UnmarshalConfig(yamlConfig []byte) error {
	j.config = JournalCtlConfiguration{}
	err := yaml.UnmarshalStrict(yamlConfig, &j.config)
	if err != nil {
		return fmt.Errorf("cannot parse JournalCtlSource configuration: %w", err)
	}

	if j.config.Mode == "" {
		j.config.Mode = configuration.TAIL_MODE
	}

	var args []string
	if j.config.Mode == configuration.TAIL_MODE {
		args = journalctlArgstreaming
	} else {
		args = journalctlArgsOneShot
	}

	if len(j.config.Filters) == 0 {
		return fmt.Errorf("journalctl_filter is required")
	}
	j.args = append(args, j.config.Filters...)
	j.src = fmt.Sprintf("journalctl-%s", strings.Join(j.config.Filters, "."))

	return nil
}

func (j *JournalCtlSource) Configure(yamlConfig []byte, logger *log.Entry) error {
	j.logger = logger

	err := j.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	return nil
}

func (j *JournalCtlSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	j.logger = logger
	j.config = JournalCtlConfiguration{}
	j.config.Mode = configuration.CAT_MODE
	j.config.Labels = labels
	j.config.UniqueId = uuid

	//format for the DSN is : journalctl://filters=FILTER1&filters=FILTER2
	if !strings.HasPrefix(dsn, "journalctl://") {
		return fmt.Errorf("invalid DSN %s for journalctl source, must start with journalctl://", dsn)
	}

	qs := strings.TrimPrefix(dsn, "journalctl://")
	if len(qs) == 0 {
		return fmt.Errorf("empty journalctl:// DSN")
	}

	params, err := url.ParseQuery(qs)
	if err != nil {
		return fmt.Errorf("could not parse journalctl DSN : %s", err)
	}
	for key, value := range params {
		switch key {
		case "filters":
			j.config.Filters = append(j.config.Filters, value...)
		case "log_level":
			if len(value) != 1 {
				return fmt.Errorf("expected zero or one value for 'log_level'")
			}
			lvl, err := log.ParseLevel(value[0])
			if err != nil {
				return errors.Wrapf(err, "unknown level %s", value[0])
			}
			j.logger.Logger.SetLevel(lvl)
		case "since":
			j.args = append(j.args, "--since", value[0])
		default:
			return fmt.Errorf("unsupported key %s in journalctl DSN", key)
		}
	}
	j.args = append(j.args, j.config.Filters...)
	return nil
}

func (j *JournalCtlSource) GetMode() string {
	return j.config.Mode
}

func (j *JournalCtlSource) GetName() string {
	return "journalctl"
}

func (j *JournalCtlSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	defer trace.CatchPanic("crowdsec/acquis/journalctl/oneshot")
	err := j.runJournalCtl(out, t)
	j.logger.Debug("Oneshot journalctl acquisition is done")
	return err

}

func (j *JournalCtlSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/journalctl/streaming")
		return j.runJournalCtl(out, t)
	})
	return nil
}
func (j *JournalCtlSource) CanRun() error {
	//TODO: add a more precise check on version or something ?
	_, err := exec.LookPath(journalctlCmd)
	return err
}
func (j *JournalCtlSource) Dump() interface{} {
	return j
}
