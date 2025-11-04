package journalctlacquisition

import (
	"bufio"
	"context"
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

func (s *Source) OneShotAcquisition(ctx context.Context, out chan pipeline.Event, acquisTomb *tomb.Tomb) error {
	if acquisTomb != nil {
		tombCtx, cancel := context.WithCancel(ctx)

		go func() {
			<-acquisTomb.Dying()
			cancel()
		}()

		ctx = tombCtx
	}

	err := s.runJournalCtl(ctx, out)
	s.logger.Debug("Oneshot journalctl acquisition is done")

	return err
}

func (s *Source) StreamingAcquisition(ctx context.Context, out chan pipeline.Event, acquisTomb *tomb.Tomb) error {
	tombCtx, cancel := context.WithCancel(ctx)

	go func() {
		<-acquisTomb.Dying()
		cancel()
	}()

	acquisTomb.Go(func() error {
		return s.runJournalCtl(tombCtx, out)
	})

	return nil
}

func (s *Source) getCommandArgs() []string {
	args := []string{}

	if s.config.Mode == configuration.TAIL_MODE {
		args = []string{"--follow", "-n", "0"}
	}

	if s.config.since != "" {
		args = append(args, "--since", s.config.since)
	}

	return append(args, s.config.Filters...)
}

func (s *Source) runJournalCtl(ctx context.Context, out chan pipeline.Event) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(ctx, journalctlCmd, s.getCommandArgs()...)

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

	logger := s.logger.WithField("src", s.src)

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

	stdoutScanner := bufio.NewScanner(stdout)
	stderrScanner := bufio.NewScanner(stderr)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer close(stdoutChan)

		// XXX: lines can be >64k. should we buffer?
		for stdoutScanner.Scan() {
			stdoutChan <- stdoutScanner.Text()
		}

		if err := stdoutScanner.Err(); err != nil {
			errChan <- err
		}

		return nil
	})

	g.Go(func() error {
		// looks like journalctl closes stderr quite early, so ignore its status (but not its output)
		defer close(stderrChan)

		for stderrScanner.Scan() {
			stderrChan <- stderrScanner.Text()
		}

		return nil
	})

	for {
		select {
		case <-ctx.Done():
			logger.Info("datasource stopping")
			return g.Wait()
		case stdoutLine, ok := <-stdoutChan:
			if !ok {
				// channel closed
				logger.Debug("stdoutChan is closed, quitting")
				return g.Wait()
			}

			line := pipeline.Line{
				Raw: stdoutLine,
				Src: s.src,
				Time: time.Now().UTC(),
				Labels: s.config.Labels,
				Process: true,
				Module: s.GetName(),
			}

			logger.Debugf("getting one line: %s", line.Raw)

			if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				// XXX: label map allocation
				metrics.JournalCtlDataSourceLinesRead.With(prometheus.Labels{"source": s.src, "datasource_type": "journalctl", "acquis_type": line.Labels["type"]}).Inc()
			}

			evt := pipeline.MakeEvent(s.config.UseTimeMachine, pipeline.LOG, true)
			evt.Line = line

			out <- evt
		case stderrLine, ok := <-stderrChan:
			if !ok {
				// channel closed
				continue
			}

			logger.Warnf("Got stderr message: %s", stderrLine)

			if s.config.Mode == configuration.CAT_MODE {
				continue
			}
			// XXX: handle this error
			return fmt.Errorf("journalctl error: %s", stderrLine)
		case scanErr := <-errChan:
			return scanErr
		}
	}
}
