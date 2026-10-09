package v1

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

// limitedStream puts the limiter in front of a handler that holds its slot until the test releases it.
type limitedStream struct {
	router  *gin.Engine
	entered chan struct{}
	release chan struct{}
}

func newLimitedStream(t *testing.T, limit int) limitedStream {
	t.Helper()

	gin.SetMode(gin.TestMode)

	ctrl, err := New(&ControllerV1Config{DecisionsStream: &csconfig.DecisionsStreamCfg{MaxConcurrentRequests: limit}})
	require.NoError(t, err)

	s := limitedStream{
		router:  gin.New(),
		entered: make(chan struct{}, 16),
		release: make(chan struct{}),
	}

	s.router.GET("/stream", ctrl.LimitStreamConcurrency, func(gctx *gin.Context) {
		s.entered <- struct{}{}
		<-s.release
		gctx.Status(http.StatusOK)
	})

	// Frees any handler a failed assertion left blocked.
	t.Cleanup(func() { close(s.release) })

	return s
}

// start sends a request in the background; the channel receives its status code.
func (s limitedStream) start(ctx context.Context) <-chan int {
	code := make(chan int, 1)

	go func() {
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, httptest.NewRequestWithContext(ctx, http.MethodGet, "/stream", nil))
		code <- w.Code
	}()

	return code
}

func (s limitedStream) requireEntered(t *testing.T) {
	t.Helper()

	select {
	case <-s.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached the handler")
	}
}

// requireQueued can only fail if the limiter lets a request through, never because the machine is slow.
func (s limitedStream) requireQueued(t *testing.T) {
	t.Helper()

	select {
	case <-s.entered:
		t.Fatal("request got past the limit")
	case <-time.After(100 * time.Millisecond):
	}
}

func requireCode(t *testing.T, want int, code <-chan int) {
	t.Helper()

	select {
	case got := <-code:
		require.Equal(t, want, got)
	case <-time.After(5 * time.Second):
		t.Fatal("request never returned")
	}
}

func TestLimitStreamConcurrency(t *testing.T) {
	t.Run("requests beyond the limit wait for a slot", func(t *testing.T) {
		for _, limit := range []int{1, 3} {
			t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
				s := newLimitedStream(t, limit)

				codes := make([]<-chan int, 0, limit+1)
				for range limit {
					codes = append(codes, s.start(t.Context()))
					s.requireEntered(t)
				}

				codes = append(codes, s.start(t.Context()))
				s.requireQueued(t)

				// freeing one slot lets exactly the queued request in
				s.release <- struct{}{}
				s.requireEntered(t)

				for range limit {
					s.release <- struct{}{}
				}

				for _, code := range codes {
					requireCode(t, http.StatusOK, code)
				}
			})
		}
	})

	t.Run("a request canceled while queued leaves without taking a slot", func(t *testing.T) {
		s := newLimitedStream(t, 1)

		first := s.start(t.Context())
		s.requireEntered(t)

		ctx, cancel := context.WithCancel(t.Context())
		queued := s.start(ctx)
		s.requireQueued(t)

		cancel()
		requireCode(t, http.StatusServiceUnavailable, queued)

		s.release <- struct{}{}
		requireCode(t, http.StatusOK, first)

		// the only slot is free again
		next := s.start(t.Context())
		s.requireEntered(t)
		s.release <- struct{}{}
		requireCode(t, http.StatusOK, next)
	})

	t.Run("zero or negative does not limit", func(t *testing.T) {
		for _, limit := range []int{0, -1} {
			t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
				s := newLimitedStream(t, limit)

				codes := make([]<-chan int, 0, 5)
				for range 5 {
					codes = append(codes, s.start(t.Context()))
					s.requireEntered(t)
				}

				for range 5 {
					s.release <- struct{}{}
				}

				for _, code := range codes {
					requireCode(t, http.StatusOK, code)
				}
			})
		}
	})
}
