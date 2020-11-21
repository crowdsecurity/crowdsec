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
	j.Config = config
	if config.JournalctlFilters == nil {
		return fmt.Errorf("journalctl_filter shouldn't be empty")
	}
	journalArgs := []string{"--follow"}
	journalArgs = append(journalArgs, config.JournalctlFilters...)

	j.Cmd = exec.Command("journalctl", journalArgs...)
	j.Stderr, _ = j.Cmd.StderrPipe()
	j.Stdout, _ = j.Cmd.StdoutPipe()
	j.SrcName = fmt.Sprintf("journalctl-%s", strings.Join(config.JournalctlFilters, "."))
	log.Infof("Configured with source : %+v", journalArgs)
	return nil
}

func (j *JournaldSource) StartCat(out chan types.Event, t *tomb.Tomb) error {
	return fmt.Errorf("JournaldSource doesn't support cat")
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
	for scanner.Scan() {
		clog.Errorf("SCANNING LINNNNNE")
		l := types.Line{}

		ReaderHits.With(prometheus.Labels{"source": j.SrcName}).Inc()

		l.Raw = scanner.Text()
		l.Labels = j.Config.Labels
		l.Time = time.Now()
		l.Src = j.SrcName
		l.Process = true
		evt := types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}
		log.Printf("event -> %+v", evt)
		out <- evt
		if err := scanner.Err(); err != nil {
			return errors.Wrapf(err, "reading %s", j.SrcName)
		}
	}
	if err := scanner.Err(); err != nil {
		return errors.Wrapf(err, "reading %s", j.SrcName)
	}
	return nil
}

func (j *JournaldSource) Exists() (bool, error) {
	return true, nil
}
