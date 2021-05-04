package journalctlacquisition

import (
	"bufio"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
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
	journalctlArgsOneShot  = []string{""}
	journalctlArgstreaming = []string{"--follow"}
)

func (j *JournalCtlSource) runJournalCtl(out chan types.Event, t *tomb.Tomb) error {
	cmd := exec.Command(journalctlCmd, j.args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("could not get journalctl stdout: %s", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("could not get journalctl stderr: %s", err)
	}

	readErr := make(chan error)

	j.logger.Debugf("Running journalctl command: %s %s", cmd.Path, cmd.Args)
	err = cmd.Start()
	if err != nil {
		j.logger.Errorf("could not start journalctl command : %s", err)
		return err
	}

	go func() {
		scanner := bufio.NewScanner(stderr)
		if scanner == nil {
			readErr <- fmt.Errorf("failed to create stderr scanner")
			return
		}
		for scanner.Scan() {
			txt := scanner.Text()
			j.logger.Warningf("got stderr message : %s", txt)
			readErr <- fmt.Errorf(txt)
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner == nil {
			readErr <- fmt.Errorf("failed to create stdout scanner")
			return
		}
		for scanner.Scan() {
			l := types.Line{}
			//ReaderHits.With(prometheus.Labels{"source": j.SrcName}).Inc()
			l.Raw = scanner.Text()
			j.logger.Debugf("getting one line : %s", l.Raw)
			l.Labels = j.config.Labels
			l.Time = time.Now()
			l.Src = j.src
			l.Process = true
			evt := types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}
			out <- evt
		}
		j.logger.Debugf("finished reading from journalctl")
		if err := scanner.Err(); err != nil {
			j.logger.Debugf("got an error while reading %s : %s", j.src, err)
			readErr <- err
			return
		}
		readErr <- nil
	}()

	for {
		select {
		case <-t.Dying():
			j.logger.Debugf("journalctl datasource %s stopping", j.src)
			return nil
		case err := <-readErr:
			j.logger.Debugf("the subroutine returned, leave as well")
			if err != nil {
				j.logger.Warningf("journalctl reader error : %s", err)
				t.Kill(err)
			}
			return err
		}
	}
}

func (j *JournalCtlSource) GetMetrics() []prometheus.Collector {
	return nil
}

func (j *JournalCtlSource) Configure(yamlConfig []byte, logger *log.Entry) error {
	config := JournalCtlConfiguration{}
	j.logger = logger
	err := yaml.UnmarshalStrict(yamlConfig, &config)
	if err != nil {
		return errors.Wrap(err, "Cannot parse JournalCtlSource configuration")
	}
	if config.Mode == "" {
		config.Mode = configuration.TAIL_MODE
	}
	var args []string
	if config.Mode == configuration.TAIL_MODE {
		args = journalctlArgstreaming
	} else {
		args = journalctlArgsOneShot
	}
	j.args = append(args, config.Filters...)
	j.src = fmt.Sprintf("journalctl-%s", strings.Join(config.Filters, "."))
	j.config = config
	return nil
}

func (j *JournalCtlSource) ConfigureByDSN(dsn string, labelType string, logger *log.Entry) error {
	j.logger = logger
	j.config = JournalCtlConfiguration{}
	j.config.Mode = configuration.CAT_MODE
	j.config.Labels = map[string]string{"type": labelType}

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
		if key != "filters" {
			return fmt.Errorf("unsupported key %s in journalctl DSN", key)
		}
		j.config.Filters = append(j.config.Filters, value...)
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
	t.Go(func() error {
		defer types.CatchPanic("crowdsec/acquis/journalctl/oneshot")
		return j.runJournalCtl(out, t)
	})
	return nil
}

func (j *JournalCtlSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	t.Go(func() error {
		defer types.CatchPanic("crowdsec/acquis/journalctl/streaming")
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
