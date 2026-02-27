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

	select {
	case err := <-serverError:
		return err
	case <-t.Dying():
		w.logger.Info("Shutting down Appsec server")
		// xx let's clean up the appsec runners :)
		appsec.AppsecRulesDetails = make(map[int]appsec.RulesDetails)

		if err := w.server.Shutdown(ctx); err != nil {
			w.logger.Errorf("Error shutting down Appsec server: %s", err.Error())
		}

		if w.config.ListenSocket != "" {
			if err := os.Remove(w.config.ListenSocket); err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					w.logger.Errorf("can't remove socket %s: %s", w.config.ListenSocket, err)
				}
			}
		}
	}

	return nil
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
		refreshCtx, refreshCancel := context.WithCancel(ctx)
		t.Go(func() error {
			<-t.Dying()
			refreshCancel()
			return nil
		})

		w.appsecAllowlistClient.StartRefresh(refreshCtx)
	}

	t.Go(func() error {
		defer trace.ReportPanic()

		for _, runner := range w.AppsecRunners {
			runner.outChan = out

			t.Go(func() error {
				defer trace.ReportPanic()
				return runner.Run(t)
			})
		}

		return w.listenAndServe(ctx, t)
	})

	return nil
}
