package journalctlacquisition

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"time"
	"golang.org/x/sync/errgroup"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

const journalctlCmd = "journalctl"

func (s *Source) OneShot(ctx context.Context, out chan pipeline.Event) error {
	err := s.runJournalCtl(ctx, out)
	s.logger.Debug("Oneshot acquisition is done")

	return err
}

func (s *Source) Stream(ctx context.Context, out chan pipeline.Event) error {
	return s.runJournalCtl(ctx, out)
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

	s.logger.WithField("command", formatShellCommand(cmd.Args)).Info("Spawning process")

	err = cmd.Start()
	if err != nil {
		s.logger.Errorf("Error spawning process: %s", err)
		return err
	}

	stdoutScanner := bufio.NewScanner(stdout)
	stderrScanner := bufio.NewScanner(stderr)

	// don't shadow parent context, we'll monitor later if it's canceled
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer close(stdoutChan)

		// NOTE: lines can be >64k. should we have a configurable buffer?
		// check context with for - select
		for stdoutScanner.Scan() {
			select {
			case <-gctx.Done():
				return gctx.Err()
			case stdoutChan <- stdoutScanner.Text():
			}
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
			select {
			case <-gctx.Done():
				return gctx.Err()
			case stderrChan <- stderrScanner.Text():
			}
		}

		return nil
	})

	cleanup := func() error {
		// drain scanners
		_ = g.Wait()
		// reap journalctl, check status code
		cmdErr := cmd.Wait()

		// if the parent context was canceled, the journalctl error is likely "signal: killed" and we ignore that
		if ctx.Err() != nil {
			return nil //nolint:nilerr
		}

		if cmdErr != nil {
			return fmt.Errorf("journalctl exited with error: %w", cmdErr)
		}

		// clean journalctl exit: should only happen in oneshot
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("Datasource stopping")
			return cleanup()
		case stdoutLine, ok := <-stdoutChan:
			if !ok {
				s.logger.Debug("stdout channel is closed, stopping datasource")
				return cleanup()
			}

			line := pipeline.Line{
				Raw: stdoutLine,
				Src: s.src,
				Time: time.Now().UTC(),
				Labels: s.config.Labels,
				Process: true,
				Module: s.GetName(),
			}

			s.logger.Debugf("getting one line: %s", line.Raw)

			if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				metrics.JournalCtlDataSourceLinesRead.With(prometheus.Labels{"source": s.src, "datasource_type": ModuleName, "acquis_type": line.Labels["type"]}).Inc()
			}

			evt := pipeline.MakeEvent(s.config.UseTimeMachine, pipeline.LOG, true)
			evt.Line = line

			out <- evt
		case stderrLine, ok := <-stderrChan:
			if !ok {
				// channel closed
				continue
			}

			s.logger.Warnf("Got stderr: %s", stderrLine)
			// NOTE: can journalctl go into a failed state without quitting?
			// if so, we can detect it here and treat it as an error.
			continue
		case scanErr := <-errChan:
			s.logger.Warnf("scanner error: %v", scanErr)
			return cleanup()
		}
	}
}
