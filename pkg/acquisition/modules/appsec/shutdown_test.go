package appsecacquisition

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec"
)

func waitForDispatch(t *testing.T, finished <-chan error) error {
	t.Helper()

	select {
	case err := <-finished:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch remained blocked")
		return nil
	}
}

func waitForAppsecRequest(t *testing.T, requests <-chan appsec.ParsedRequest) appsec.ParsedRequest {
	t.Helper()

	select {
	case request := <-requests:
		return request
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not receive request")
		return appsec.ParsedRequest{}
	}
}

func TestDispatchToRunnerShutdown(t *testing.T) {
	t.Run("blocked send", func(t *testing.T) {
		stopping := make(chan struct{})
		w := &Source{InChan: make(chan appsec.ParsedRequest), shutdown: stopping}
		finished := make(chan error, 1)

		go func() {
			_, err := w.dispatchToRunner(t.Context(), appsec.ParsedRequest{})
			finished <- err
		}()

		close(stopping)
		require.ErrorIs(t, waitForDispatch(t, finished), errAppsecStopping)
	})

	t.Run("client disconnect before dispatch", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		w := &Source{InChan: make(chan appsec.ParsedRequest)}
		finished := make(chan error, 1)

		go func() {
			_, err := w.dispatchToRunner(ctx, appsec.ParsedRequest{})
			finished <- err
		}()

		cancel()
		require.ErrorIs(t, waitForDispatch(t, finished), context.Canceled)
	})

	t.Run("blocked response", func(t *testing.T) {
		stopping := make(chan struct{})
		w := &Source{InChan: make(chan appsec.ParsedRequest), shutdown: stopping}
		finished := make(chan error, 1)
		request := appsec.ParsedRequest{ResponseChannel: make(chan appsec.AppsecTempResponse, 1)}

		go func() {
			_, err := w.dispatchToRunner(t.Context(), request)
			finished <- err
		}()

		received := waitForAppsecRequest(t, w.InChan)
		close(stopping)
		require.ErrorIs(t, waitForDispatch(t, finished), errAppsecStopping)

		select {
		case received.ResponseChannel <- appsec.AppsecTempResponse{}:
		default:
			t.Fatal("runner reply blocked after handler exited")
		}
	})

	t.Run("client disconnect after dispatch", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		w := &Source{InChan: make(chan appsec.ParsedRequest)}
		finished := make(chan error, 1)
		request := appsec.ParsedRequest{ResponseChannel: make(chan appsec.AppsecTempResponse, 1)}

		go func() {
			_, err := w.dispatchToRunner(ctx, request)
			finished <- err
		}()

		received := waitForAppsecRequest(t, w.InChan)
		cancel()
		require.ErrorIs(t, waitForDispatch(t, finished), context.Canceled)

		select {
		case received.ResponseChannel <- appsec.AppsecTempResponse{}:
		default:
			t.Fatal("runner reply blocked after client disconnected")
		}
	})

	t.Run("normal response", func(t *testing.T) {
		w := &Source{InChan: make(chan appsec.ParsedRequest)}
		finished := make(chan error, 1)
		go func() {
			response, err := w.dispatchToRunner(t.Context(), appsec.ParsedRequest{
				ResponseChannel: make(chan appsec.AppsecTempResponse, 1),
			})
			if err == nil && response.InBandInterrupt {
				finished <- errors.New("unexpected interrupted response")
				return
			}

			finished <- err
		}()

		received := waitForAppsecRequest(t, w.InChan)
		received.ResponseChannel <- appsec.AppsecTempResponse{}
		require.NoError(t, waitForDispatch(t, finished))
	})
}

func TestAppsecHandlerReturnsUnavailableWhenStopping(t *testing.T) {
	w := authTestSource(t, "http://lapi.invalid", time.Second)
	w.config.BodyReadTimeout = ptr.Of(time.Second)
	w.config.Name = "test"
	w.AppsecRuntime = &appsec.AppsecRuntimeConfig{}
	w.InChan = make(chan appsec.ParsedRequest)
	stopping := make(chan struct{})
	close(stopping)
	w.shutdown = stopping

	w.AuthCache.Set("valid-key", time.Now().Add(time.Minute))
	request := httptest.NewRequest(http.MethodPost, "http://example.test/", http.NoBody)
	request.Header.Set(appsec.APIKeyHeaderName, "valid-key")
	request.Header.Set(appsec.IPHeaderName, "192.0.2.1")
	request.Header.Set(appsec.URIHeaderName, "/")
	request.Header.Set(appsec.VerbHeaderName, http.MethodPost)

	response := httptest.NewRecorder()
	w.appsecHandler(response, request)
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
}

func TestShutdownHTTPServerForcesClose(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	})}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(listener)
	}()

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + listener.Addr().String())
		if err == nil {
			_ = resp.Body.Close()
		}
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		_ = server.Close()
		t.Fatal("HTTP handler did not start")
	}

	source := &Source{server: server}
	started := time.Now()
	err = source.shutdownHTTPServer(t.Context(), 100*time.Millisecond)
	close(release)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), 2*time.Second)
	require.ErrorIs(t, <-serveDone, http.ErrServerClosed)

	select {
	case <-clientDone:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP client did not exit after forced close")
	}
}

func TestShutdownHTTPServerAllowsGraceWithCanceledParent(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusNoContent)
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	defer server.Close()

	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()

	clientDone := make(chan int, 1)
	go func() {
		resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + listener.Addr().String())
		if err != nil {
			clientDone <- 0
			return
		}
		defer resp.Body.Close()
		clientDone <- resp.StatusCode
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP handler did not start")
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Acquisition is already canceled when listener shutdown begins.

	stopped := make(chan error, 1)
	go func() {
		stopped <- (&Source{server: server}).shutdownHTTPServer(ctx, time.Second)
	}()

	select {
	case err := <-stopped:
		t.Fatalf("shutdown did not honor grace period: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP shutdown did not finish")
	}
	require.Equal(t, http.StatusNoContent, <-clientDone)
	require.ErrorIs(t, <-serveDone, http.ErrServerClosed)
}
