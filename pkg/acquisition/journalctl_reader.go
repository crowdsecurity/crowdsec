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

var JOURNALD_CMD = "journalctl"
var JOURNALD_DEFAULT_TAIL_ARGS = []string{"--follow"}
var JOURNALD_DEFAULT_CAT_ARGS = []string{}

func (j *JournaldSource) Configure(config DataSourceCfg) error {
	var journalArgs []string

	j.Config = config
	if config.JournalctlFilters == nil {
		return fmt.Errorf("journalctl_filter shouldn't be empty")
	}

	if j.Config.Mode == TAIL_MODE {
		journalArgs = JOURNALD_DEFAULT_TAIL_ARGS
	} else if j.Config.Mode == CAT_MODE {
		journalArgs = JOURNALD_DEFAULT_CAT_ARGS
	} else {
		return fmt.Errorf("unknown mode '%s' for journald source", j.Config.Mode)
	}
	journalArgs = append(journalArgs, config.JournalctlFilters...)

	j.Cmd = exec.Command(JOURNALD_CMD, journalArgs...)
	j.Stderr, _ = j.Cmd.StderrPipe()
	j.Stdout, _ = j.Cmd.StdoutPipe()
	j.SrcName = fmt.Sprintf("journalctl-%s", strings.Join(config.JournalctlFilters, "."))
	log.Infof("[journald datasource] Configured with filters : %+v", journalArgs)
	log.Debugf("cmd path : %s", j.Cmd.Path)
	log.Debugf("cmd args : %+v", j.Cmd.Args)

	return nil
}

func (j *JournaldSource) Mode() string {
	return j.Config.Mode
}

func (j *JournaldSource) readOutput(out chan types.Event, t *tomb.Tomb) error {

	/*
		todo : handle the channel
	*/
	clog := log.WithFields(log.Fields{
		"acquisition file": j.SrcName,
	})
	if err := j.Cmd.Start(); err != nil {
		clog.Errorf("failed to start journalctl: %s", err)
		return errors.Wrapf(err, "starting journalctl (%s)", j.SrcName)
	}

	readErr := make(chan error)

	/*read stderr*/
	go func() {
		scanner := bufio.NewScanner(j.Stderr)
		if scanner == nil {
			readErr <- fmt.Errorf("failed to create stderr scanner")
			return
		}
		for scanner.Scan() {
			txt := scanner.Text()
			clog.Warningf("got stderr message : %s", txt)
			readErr <- fmt.Errorf(txt)
		}
	}()
	/*read stdout*/
	go func() {
		scanner := bufio.NewScanner(j.Stdout)
		if scanner == nil {
			readErr <- fmt.Errorf("failed to create stdout scanner")
			return
		}
		for scanner.Scan() {
			l := types.Line{}
			ReaderHits.With(prometheus.Labels{"source": j.SrcName}).Inc()
			l.Raw = scanner.Text()
			clog.Debugf("getting one line : %s", l.Raw)
			l.Labels = j.Config.Labels
			l.Time = time.Now()
			l.Src = j.SrcName
			l.Process = true
			evt := types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}
			out <- evt
		}
		clog.Debugf("finished reading from journalctl")
		if err := scanner.Err(); err != nil {
			clog.Debugf("got an error while reading %s : %s", j.SrcName, err)
			readErr <- err
			return
		}
		readErr <- nil
	}()

	for {
		select {
		case <-t.Dying():
			clog.Debugf("journalctl datasource %s stopping", j.SrcName)
			return nil
		case err := <-readErr:
			clog.Debugf("the subroutine returned, leave as well")
			if err != nil {
				clog.Warningf("journalctl reader error : %s", err)
				t.Kill(err)
			}
			return err
		}
	}
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
	t.Go(func() error {
		defer types.CatchPanic("crowdsec/acquis/tailjournalctl")
		return j.readOutput(out, t)
	})
	return nil
}

func (j *JournaldSource) StartTail(out chan types.Event, t *tomb.Tomb) error {
	t.Go(func() error {
		defer types.CatchPanic("crowdsec/acquis/catjournalctl")
		return j.readOutput(out, t)
	})
	return nil
}
