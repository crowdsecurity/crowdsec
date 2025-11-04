package journalctlacquisition

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
	"golang.org/x/sync/errgroup"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

const journalctlCmd = "journalctl"

func (j *JournalCtlSource) OneShotAcquisition(ctx context.Context, out chan pipeline.Event, acquisTomb *tomb.Tomb) error {
	if acquisTomb != nil {
		tombCtx, cancel := context.WithCancel(ctx)

		go func() {
			<-acquisTomb.Dying()
			cancel()
		}()

		ctx = tombCtx
	}

	err := j.runJournalCtl(ctx, out)
	j.logger.Debug("Oneshot journalctl acquisition is done")
	return err
}

func (j *JournalCtlSource) StreamingAcquisition(ctx context.Context, out chan pipeline.Event, acquisTomb *tomb.Tomb) error {
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		<-acquisTomb.Dying()
		cancel()
	}()

	acquisTomb.Go(func() error {
		return j.runJournalCtl(ctx, out)
	})

	return nil
}

func (j *JournalCtlSource) getCommandArgs() []string {
	args := []string{}

	if j.config.Mode == configuration.TAIL_MODE {
		args = []string{"--follow", "-n", "0"}
	}

	if j.config.since != "" {
		args = append(args, "--since", j.config.since)
	}

	return append(args, j.config.Filters...)
}

func (j *JournalCtlSource) runJournalCtl(ctx context.Context, out chan pipeline.Event) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(ctx, journalctlCmd, j.getCommandArgs()...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("could not get journalctl stdout: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("could not get journalctl stderr: %w", err)
	}

	stderrChan := make(chan string)
	stdoutChan := make(chan string)
	errChan := make(chan error, 1)

	logger := j.logger.WithField("src", j.src)

	logger.Infof("Running journalctl command: %s %s", cmd.Path, cmd.Args)

	err = cmd.Start()
	if err != nil {
		logger.Errorf("could not start journalctl command : %s", err)
		return err
	}

	defer func() {
		if err := cmd.Wait(); err != nil {
			logger.Debugf("journalctl exited after cancel: %v", err)
		}
	}()

	stdoutscanner := bufio.NewScanner(stdout)

	if stdoutscanner == nil {
		return errors.New("failed to create stdout scanner")
	}

	stderrScanner := bufio.NewScanner(stderr)

	if stderrScanner == nil {
		return errors.New("failed to create stderr scanner")
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		for stdoutscanner.Scan() {
			txt := stdoutscanner.Text()
			stdoutChan <- txt
		}

		if stdoutscanner.Err() != nil {
			errChan <- stdoutscanner.Err()
			close(errChan)
			// the error is already consumed by runJournalCtl
			return nil //nolint:nilerr
		}

		close(errChan)

		return nil
	})

	g.Go(func() error {
		// looks like journalctl closes stderr quite early, so ignore its status (but not its output)
		for stderrScanner.Scan() {
			txt := stderrScanner.Text()
			stderrChan <- txt
		}

		return nil
	})

	for {
		select {
		case <-ctx.Done():
			logger.Infof("journalctl datasource %s stopping", j.src)
			return g.Wait()
		case stdoutLine := <-stdoutChan:
			l := pipeline.Line{}
			l.Raw = stdoutLine
			logger.Debugf("getting one line : %s", l.Raw)
			l.Labels = j.config.Labels
			l.Time = time.Now().UTC()
			l.Src = j.src
			l.Process = true
			l.Module = j.GetName()

			if j.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				metrics.JournalCtlDataSourceLinesRead.With(prometheus.Labels{"source": j.src, "datasource_type": "journalctl", "acquis_type": l.Labels["type"]}).Inc()
			}

			evt := pipeline.MakeEvent(j.config.UseTimeMachine, pipeline.LOG, true)
			evt.Line = l
			out <- evt
		case stderrLine := <-stderrChan:
			logger.Warnf("Got stderr message : %s", stderrLine)
			if j.config.Mode == configuration.CAT_MODE {
				continue
			}
			return fmt.Errorf("journalctl error : %s", stderrLine)
		case scanErr, ok := <-errChan:
			if ok && scanErr != nil {
				return g.Wait()
			}

			logger.Debugf("errChan is closed, quitting")
			return g.Wait()
		}
	}
}
