package acquisition

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	tomb "gopkg.in/tomb.v2"
)

/*
 journald/systemd support :

 systemd has its own logging system, which stores files in non-text mode.
 To be able to read those, we're going to read the output of journalctl, see https://github.com/crowdsecurity/crowdsec/issues/423


 TBD :
  - handle journalctl errors
*/

type JournaldSource struct {
	Config  DataSourceCfg
	Cmd     *exec.Cmd
	Stdout  io.ReadCloser
	Stderr  io.ReadCloser
	Decoder *json.Decoder
	SrcName string
}

func (j *JournaldSource) Configure(config DataSourceCfg) error {
	var journalArgs []string

	j.Config = config
	if config.JournalctlFilters == nil {
		return fmt.Errorf("journalctl_filter shouldn't be empty")
	}

	if j.Config.Mode == TAIL_MODE {
		journalArgs = []string{"--follow"}
	} else if j.Config.Mode == CAT_MODE {
		journalArgs = []string{}
	} else {
		return fmt.Errorf("unknown mode '%s' for journald source", j.Config.Mode)
	}
	journalArgs = append(journalArgs, config.JournalctlFilters...)

	j.Cmd = exec.Command("journalctl", journalArgs...)
	j.Stderr, _ = j.Cmd.StderrPipe()
	j.Stdout, _ = j.Cmd.StdoutPipe()
	j.SrcName = fmt.Sprintf("journalctl-%s", strings.Join(config.JournalctlFilters, "."))
	log.Infof("Configured with source : %+v", journalArgs)
	return nil
}

func (j *JournaldSource) Mode() string {
	return j.Config.Mode
}

func (j *JournaldSource) StartReading(out chan types.Event, t *tomb.Tomb) error {

	if j.Config.Mode == CAT_MODE {
		return j.StartCat(out, t)
	} else if j.Config.Mode == TAIL_MODE {
		return j.StartTail(out, t)
	} else {
		return fmt.Errorf("unknown mode '%s' for file acquisition", j.Config.Mode)
	}
}

func (j *JournaldSource) StartCat(out chan types.Event, t *tomb.Tomb) error {

	/*
		todo : handle the channel
	*/
	clog := log.WithFields(log.Fields{
		"acquisition file": j.SrcName,
	})
	clog.Infof("starting (cat) journalctlxxxx")
	if err := j.Cmd.Start(); err != nil {
		clog.Errorf("failed to start journalctl: %s", err)
		return errors.Wrapf(err, "starting journalctl (%s)", j.SrcName)
	}
	scanner := bufio.NewScanner(j.Stdout)
	if scanner == nil {
		clog.Errorf("failed to create scanner :<")
		return fmt.Errorf("failed to create scanner")
	}
	for scanner.Scan() {
		l := types.Line{}

		ReaderHits.With(prometheus.Labels{"source": j.SrcName}).Inc()

		l.Raw = scanner.Text()
		l.Labels = j.Config.Labels
		l.Time = time.Now()
		l.Src = j.SrcName
		l.Process = true
		evt := types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}
		log.Debugf("event -> %+v", evt)
		out <- evt
		if err := scanner.Err(); err != nil {
			return errors.Wrapf(err, "reading %s", j.SrcName)
		}
	}
	log.Errorf("Journald scanner %s returns", j.SrcName)
	if err := scanner.Err(); err != nil {
		return errors.Wrapf(err, "reading %s", j.SrcName)
	}
	t.Kill(nil)
	return nil
}

func (j *JournaldSource) StartTail(out chan types.Event, t *tomb.Tomb) error {

	/*
		todo : handle the channel
	*/
	clog := log.WithFields(log.Fields{
		"acquisition file": j.SrcName,
	})
	clog.Infof("starting journalctlxxxx")
	if err := j.Cmd.Start(); err != nil {
		clog.Errorf("failed to start journalctl: %s", err)
		return errors.Wrapf(err, "starting journalctl (%s)", j.SrcName)
	}
	scanner := bufio.NewScanner(j.Stdout)
	if scanner == nil {
		clog.Errorf("failed to create scanner :<")
		return fmt.Errorf("failed to create scanner")
	}

	readErr := make(chan error)
	go func() {
		for scanner.Scan() {
			l := types.Line{}
			ReaderHits.With(prometheus.Labels{"source": j.SrcName}).Inc()
			l.Raw = scanner.Text()
			l.Labels = j.Config.Labels
			l.Time = time.Now()
			l.Src = j.SrcName
			l.Process = true
			evt := types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}
			log.Debugf("event -> %+v", evt)
			out <- evt
		}
		if err := scanner.Err(); err != nil {
			log.Warningf("reading %s : %s", j.SrcName, err)
			readErr <- err
		}
	}()

	for {
		select {
		case <-t.Dying():
			log.Infof("journalctl datasource %s stopping", j.SrcName)
			return nil
		case err := <-readErr:
			log.Infof("journalctl reader error : %s", err)
			t.Kill(err)
			return err
		}
	}
}

func (j *JournaldSource) Exists() (bool, error) {
	return true, nil
}
