package appsecacquisition

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"
)

// freeAddr returns a loopback address that was bindable a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := l.Addr().String()
	require.NoError(t, l.Close())

	return addr
}

func newTestSource(t *testing.T, cfg Configuration) *Source {
	t.Helper()

	w := &Source{
		logger: log.NewEntry(log.StandardLogger()),
		mux:    http.NewServeMux(),
		config: cfg,
	}
	w.server = &http.Server{Addr: cfg.ListenAddr, Handler: w.mux}

	return w
}

// runListenAndServe runs listenAndServe to completion and returns its error.
func runListenAndServe(t *testing.T, w *Source) error {
	t.Helper()

	var tb tomb.Tomb

	done := make(chan error, 1)

	tb.Go(func() error {
		done <- w.listenAndServe(context.Background(), &tb)
		return nil
	})

	defer func() {
		tb.Kill(nil)
		_ = tb.Wait()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("listenAndServe did not return")
		return nil
	}
}

// requireAddrFree fails unless addr can be bound again.
func requireAddrFree(t *testing.T, addr string) {
	t.Helper()

	// the goroutine that owns the listener releases it as it unwinds
	require.Eventually(t, func() bool {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return false
		}

		l.Close()

		return true
	}, 10*time.Second, 50*time.Millisecond, "%s is still bound after listenAndServe returned", addr)
}

// A listener that fails to bind must not leave the other one holding its port.
// Before this was fixed, listenAndServe returned the error without shutting the
// server down, so the surviving listener kept the port for the lifetime of the
// process and every later reload failed with "address already in use" while the
// rest of CrowdSec carried on looking healthy.
func TestListenAndServeReleasesTCPWhenTheSocketFails(t *testing.T) {
	addr := freeAddr(t)

	w := newTestSource(t, Configuration{
		ListenAddr: addr,
		// a directory that does not exist, so the bind fails
		ListenSocket: filepath.Join(t.TempDir(), "absent", "appsec.sock"),
	})

	require.Error(t, runListenAndServe(t, w))
	requireAddrFree(t, addr)
}

// The mirror of the above: the TCP bind fails and the socket must be released.
func TestListenAndServeReleasesSocketWhenTCPFails(t *testing.T) {
	// hold the address so the appsec listener cannot have it
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer blocker.Close()

	socket := filepath.Join(t.TempDir(), "appsec.sock")

	w := newTestSource(t, Configuration{
		ListenAddr:   blocker.Addr().String(),
		ListenSocket: socket,
	})

	require.Error(t, runListenAndServe(t, w))

	// the socket file is removed on the way out, so it can be bound again
	require.Eventually(t, func() bool {
		l, err := net.Listen("unix", socket)
		if err != nil {
			return false
		}

		l.Close()

		return true
	}, 10*time.Second, 50*time.Millisecond, "%s was not released", socket)
}

// A TLS listener that never reaches Serve is one the server never tracks, so
// Shutdown cannot release it either - the goroutine that opened it has to.
func TestListenAndServeReleasesTCPWhenTLSIsMisconfigured(t *testing.T) {
	for name, cfg := range map[string]Configuration{
		"cert file that does not exist": {
			CertFilePath: filepath.Join(t.TempDir(), "absent.pem"),
			KeyFilePath:  filepath.Join(t.TempDir(), "absent.key"),
		},
		"key file not configured": {
			CertFilePath: filepath.Join(t.TempDir(), "absent.pem"),
		},
		"cert file not configured": {
			KeyFilePath: filepath.Join(t.TempDir(), "absent.key"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.ListenAddr = freeAddr(t)
			w := newTestSource(t, cfg)

			require.Error(t, runListenAndServe(t, w))
			requireAddrFree(t, cfg.ListenAddr)
		})
	}
}

// The ordinary path still works: a clean shutdown releases the port.
func TestListenAndServeReleasesTCPOnShutdown(t *testing.T) {
	addr := freeAddr(t)
	w := newTestSource(t, Configuration{ListenAddr: addr})

	var tb tomb.Tomb

	done := make(chan error, 1)

	tb.Go(func() error {
		done <- w.listenAndServe(context.Background(), &tb)
		return nil
	})

	// wait until it is actually serving
	require.Eventually(t, func() bool {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return false
		}

		c.Close()

		return true
	}, 10*time.Second, 50*time.Millisecond, "appsec never started listening on %s", addr)

	tb.Kill(nil)
	require.NoError(t, <-done)
	require.NoError(t, tb.Wait())

	requireAddrFree(t, addr)
}
