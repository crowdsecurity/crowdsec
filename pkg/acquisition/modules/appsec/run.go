package appsecacquisition

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"

	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/csnet"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func (w *Source) listenAndServe(ctx context.Context, t *tomb.Tomb) error {
	w.logger.Infof("%d appsec runner to start", len(w.AppsecRunners))

	serverError := make(chan error, 2)

	startServer := func(listener net.Listener, canTLS bool) {
		// The listener is this goroutine's to close. http.Server closes the ones
		// it tracks, but it never gets to track this one when the TLS config is
		// rejected below or by ServeTLS itself (a cert that fails to load returns
		// before the listener reaches Serve), and an untracked listener is one
		// Shutdown cannot release either.
		defer listener.Close()

		var err error

		if canTLS && (w.config.CertFilePath != "" || w.config.KeyFilePath != "") {
			if w.config.KeyFilePath == "" {
				serverError <- errors.New("missing TLS key file")
				return
			}

			if w.config.CertFilePath == "" {
				serverError <- errors.New("missing TLS cert file")
				return
			}

			err = w.server.ServeTLS(listener, w.config.CertFilePath, w.config.KeyFilePath)
		} else {
			err = w.server.Serve(listener)
		}

		switch {
		case errors.Is(err, http.ErrServerClosed):
			break
		case err != nil:
			serverError <- err
		}
	}

	listenConfig := &net.ListenConfig{}

	// Starting Unix socket listener
	go func(socket string) {
		if socket == "" {
			return
		}

		if err := os.Remove(w.config.ListenSocket); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				w.logger.Errorf("can't remove socket %s: %s", socket, err)
			}
		}

		w.logger.Infof("creating unix socket %s", socket)

		listener, err := listenConfig.Listen(ctx, "unix", socket)
		if err != nil {
			serverError <- csnet.WrapSockErr(err, socket)
			return
		}

		w.logger.Infof("Appsec listening on Unix socket %s", socket)
		startServer(listener, false)
	}(w.config.ListenSocket)

	// Starting TCP listener
	go func(url string) {
		if url == "" {
			return
		}

		listener, err := listenConfig.Listen(ctx, "tcp", url)
		if err != nil {
			serverError <- fmt.Errorf("listening on %s: %w", url, err)
			return
		}

		w.logger.Infof("Appsec listening on %s", url)
		startServer(listener, true)
	}(w.config.ListenAddr)

	// Whichever way this returns, the server goes with it. One listener failing
	// to bind used to return straight away and leave the other one serving: the
	// port stayed held for the lifetime of the process, and because nothing
	// rebinds, every later reload failed on an address that was still in use
	// while the rest of the process carried on looking healthy.
	defer w.shutdownServer(ctx)

	select {
	case err := <-serverError:
		return err
	case <-t.Dying():
		return nil
	}
}

// shutdownServer stops the HTTP server and releases what the listeners hold.
func (w *Source) shutdownServer(ctx context.Context) {
	w.logger.Info("Shutting down Appsec server")

	// xx let's clean up the appsec runners :)
	appsec.AppsecRulesDetails = make(map[int]appsec.RulesDetails)

	if err := w.server.Shutdown(ctx); err != nil {
		w.logger.Errorf("Error shutting down Appsec server: %s", err.Error())
	}

	if w.AppsecRuntime != nil && w.AppsecRuntime.ChallengeRuntime != nil {
		if err := w.AppsecRuntime.ChallengeRuntime.Close(ctx); err != nil {
			w.logger.Errorf("Error closing challenge runtime: %s", err)
		}
	}

	if w.config.ListenSocket != "" {
		if err := os.Remove(w.config.ListenSocket); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				w.logger.Errorf("can't remove socket %s: %s", w.config.ListenSocket, err)
			}
		}
	}
}

func (w *Source) StreamingAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	lapiClient, err := apiclient.GetLAPIClient()
	if err != nil {
		return fmt.Errorf("unable to get authenticated LAPI client: %w", err)
	}

	err = w.appsecAllowlistClient.Start(ctx, lapiClient)
	if err != nil {
		w.logger.Errorf("failed to fetch allowlists for appsec, disabling them: %s", err)
	} else {
		w.appsecAllowlistClient.StartRefresh(ctx, t)
	}

	t.Go(func() error {
		defer trace.ReportPanic()

		// Runners share this pointer; it owns the only handle on the channel.
		w.AppsecRuntime.OutChan = out

		// runner is a per-iteration copy (Go >= 1.22), which the closure relies on.
		for _, runner := range w.AppsecRunners {
			t.Go(func() error {
				defer trace.ReportPanic()
				return runner.Run(ctx, t)
			})
		}

		return w.listenAndServe(ctx, t)
	})

	return nil
}
