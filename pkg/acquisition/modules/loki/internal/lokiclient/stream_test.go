package lokiclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"
)

type lokiTransport func(*http.Request) (*http.Response, error)

func (f lokiTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// An in-memory transport keeps all I/O inside synctest's virtual clock.
func mockLoki(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	original := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: lokiTransport(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		handler(w, r)
		return w.Result(), nil
	})}
	t.Cleanup(func() { http.DefaultClient = original })
}

func writeStreams(w http.ResponseWriter, streams map[string][]Entry) {
	result := []any{}
	for pod, entries := range streams {
		values := [][]string{}
		for _, entry := range entries {
			values = append(values, []string{strconv.FormatInt(entry.Timestamp.UnixNano(), 10), entry.Line})
		}
		result = append(result, map[string]any{"stream": map[string]string{"pod": pod}, "values": values})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": result}})
}

func receiveEntries(t *testing.T, ctx context.Context, out <-chan *LokiQueryRangeResponse, count int) []string {
	t.Helper()
	lines := []string{}
	for {
		select {
		case page, ok := <-out:
			if !ok {
				return lines
			}
			for _, stream := range page.Data.Result {
				for _, entry := range stream.Entries {
					lines = append(lines, entry.Line)
				}
			}
			if count > 0 && len(lines) >= count {
				return lines
			}
		case <-ctx.Done():
			t.Fatalf("read %d/%d records", len(lines), count)
		}
	}
}

func TestPaginationPreservesEntries(t *testing.T) {
	for _, infinite := range []bool{false, true} {
		for _, tc := range []struct {
			name                       string
			count                      int
			identical, multipleStreams bool
		}{
			{"full timestamp across pages", 1505, false, false},
			{"identical legitimate entries", 1505, true, false},
			{"full page across streams", 1505, false, true},
			{"same entry in different streams", 2, true, true},
		} {
			t.Run(fmt.Sprintf("%s/streaming=%t", tc.name, infinite), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					timestamp := time.Now().Add(-2 * time.Second)
					mockLoki(t, func(w http.ResponseWriter, r *http.Request) {
						start, _ := strconv.ParseInt(r.URL.Query().Get("start"), 10, 64)
						end, _ := strconv.ParseInt(r.URL.Query().Get("end"), 10, 64)
						limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
						streams := map[string][]Entry{}
						if timestamp.UnixNano() >= start && timestamp.UnixNano() < end {
							for i := 0; i < tc.count && i < limit; i++ {
								line := fmt.Sprintf("request-%d", i)
								if tc.identical {
									line = "identical request"
								}
								pod := "one"
								if tc.multipleStreams {
									pod = strconv.Itoa(i % 2)
								}
								streams[pod] = append(streams[pod], Entry{timestamp, line})
							}
						}
						writeStreams(w, streams)
					})
					ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
					defer cancel()
					life := &tomb.Tomb{}
					client := NewLokiClient(Config{LokiURL: "http://loki", Query: `{app="traefik"}`, Since: time.Hour, Limit: 1000, QueryDelay: time.Second, PollInterval: time.Second})
					client.SetTomb(life)
					out := client.QueryRange(ctx, infinite)
					want := 0
					if infinite {
						want = tc.count
					}
					lines := receiveEntries(t, ctx, out, want)
					cancel()
					life.Kill(nil)
					require.NoError(t, life.Wait())
					require.Len(t, lines, tc.count)
					if !tc.identical {
						sort.Strings(lines)
						expected := []string{}
						for i := range tc.count {
							expected = append(expected, fmt.Sprintf("request-%d", i))
						}
						sort.Strings(expected)
						require.Equal(t, expected, lines)
					}
				})
			})
		}
	}
}

func TestSettledWindowIncludesLateStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		timestamp := now.Add(5 * time.Millisecond)
		mockLoki(t, func(w http.ResponseWriter, r *http.Request) {
			start, _ := strconv.ParseInt(r.URL.Query().Get("start"), 10, 64)
			end, _ := strconv.ParseInt(r.URL.Query().Get("end"), 10, 64)
			streams := map[string][]Entry{}
			for i := range 2 {
				ts := timestamp
				if i == 1 {
					ts = ts.Add(-time.Millisecond)
				}
				if ts.UnixNano() < start || ts.UnixNano() >= end {
					continue
				}
				if i == 1 && time.Since(now) < 600*time.Millisecond {
					continue
				}
				pod := strconv.Itoa(i)
				streams[pod] = []Entry{{ts, pod}}
			}
			writeStreams(w, streams)
		})
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		life := &tomb.Tomb{}
		client := NewLokiClient(Config{LokiURL: "http://loki", Query: `{app="traefik"}`, Limit: 1000, QueryDelay: time.Second, PollInterval: 100 * time.Millisecond})
		client.SetTomb(life)
		lines := receiveEntries(t, ctx, client.QueryRange(ctx, true), 2)
		cancel()
		life.Kill(nil)
		require.NoError(t, life.Wait())
		require.ElementsMatch(t, []string{"0", "1"}, lines)
	})
}

func TestWindowEndIsExclusive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		boundary := time.Now().Add(-time.Second)
		var starts []int64
		mockLoki(t, func(w http.ResponseWriter, r *http.Request) {
			start, _ := strconv.ParseInt(r.URL.Query().Get("start"), 10, 64)
			end, _ := strconv.ParseInt(r.URL.Query().Get("end"), 10, 64)
			starts = append(starts, start)
			streams := map[string][]Entry{}
			if start <= boundary.UnixNano() && boundary.UnixNano() < end {
				streams["one"] = []Entry{{boundary, "boundary"}}
			}
			writeStreams(w, streams)
		})
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		life := &tomb.Tomb{}
		client := NewLokiClient(Config{LokiURL: "http://loki", Query: `{app="traefik"}`, Since: time.Hour, Limit: 1000, QueryDelay: time.Second, PollInterval: time.Second})
		client.SetTomb(life)
		out := client.QueryRange(ctx, true)
		lines := []string{}
		for range 3 {
			page := <-out
			for _, stream := range page.Data.Result {
				for _, entry := range stream.Entries {
					lines = append(lines, entry.Line)
				}
			}
		}
		cancel()
		life.Kill(nil)
		require.NoError(t, life.Wait())
		require.Equal(t, []string{"boundary"}, lines)
		require.Equal(t, boundary.UnixNano(), starts[1])
		require.Greater(t, starts[2], starts[1])
	})
}

func TestQueryRetriesSameWindowWithBackoff(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"HTTP failure", http.StatusServiceUnavailable, "temporarily unavailable"},
		{"invalid success", http.StatusOK, `{"status":"error","data":{"resultType":"streams","result":[]}}`},
		{"invalid JSON", http.StatusOK, `{`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var queries []string
				var times []time.Time
				mockLoki(t, func(w http.ResponseWriter, r *http.Request) {
					queries = append(queries, r.URL.RawQuery)
					times = append(times, time.Now())
					if len(queries) <= 2 {
						w.WriteHeader(tc.status)
						_, _ = fmt.Fprint(w, tc.body)
						return
					}
					writeStreams(w, map[string][]Entry{})
				})
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				life := &tomb.Tomb{}
				client := NewLokiClient(Config{LokiURL: "http://loki", Query: `{app="traefik"}`, Since: time.Hour, Limit: 1000, QueryDelay: time.Second, PollInterval: time.Second, FailMaxDuration: time.Minute})
				client.SetTomb(life)
				out := client.QueryRange(ctx, true)
				<-out
				<-out
				cancel()
				life.Kill(nil)
				require.NoError(t, life.Wait())
				require.GreaterOrEqual(t, len(queries), 4)
				require.Equal(t, queries[0], queries[1])
				require.Equal(t, queries[1], queries[2])
				require.Equal(t, 2*time.Second, times[1].Sub(times[0]))
				require.Equal(t, 4*time.Second, times[2].Sub(times[1]))
				require.Equal(t, time.Second, times[3].Sub(times[2]))
			})
		})
	}
}

func TestPageLimitRejectionDoesNotAdvanceCursor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		timestamp := time.Now().Add(-time.Second)
		var rejected []string
		mockLoki(t, func(w http.ResponseWriter, r *http.Request) {
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			if limit > 1000 {
				rejected = append(rejected, r.URL.RawQuery)
				http.Error(w, "max entries limit exceeded", http.StatusBadRequest)
				return
			}
			entries := []Entry{}
			for i := range 1000 {
				entries = append(entries, Entry{timestamp, strconv.Itoa(i)})
			}
			writeStreams(w, map[string][]Entry{"one": entries})
		})
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		life := &tomb.Tomb{}
		client := NewLokiClient(Config{LokiURL: "http://loki", Query: `{app="traefik"}`, Since: time.Hour, Limit: 1000, PollInterval: time.Second, FailMaxDuration: 3 * time.Second})
		client.SetTomb(life)
		count := 0
		for page := range client.QueryRange(ctx, false) {
			for _, stream := range page.Data.Result {
				count += len(stream.Entries)
			}
		}
		require.ErrorContains(t, life.Wait(), "HTTP 400")
		require.Equal(t, 1000, count)
		require.GreaterOrEqual(t, len(rejected), 2)
		for _, query := range rejected {
			require.Equal(t, rejected[0], query)
		}
	})
}

func TestQueryStopsWhenOutputIsNotConsumed(t *testing.T) {
	for _, cancelTomb := range []bool{false, true} {
		t.Run(fmt.Sprintf("tomb=%t", cancelTomb), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				mockLoki(t, func(w http.ResponseWriter, _ *http.Request) { writeStreams(w, map[string][]Entry{}) })
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				life := &tomb.Tomb{}
				client := NewLokiClient(Config{LokiURL: "http://loki", Query: `{app="traefik"}`, Since: time.Hour, Limit: 1000, PollInterval: time.Second})
				client.SetTomb(life)
				out := client.QueryRange(ctx, true)
				synctest.Wait()
				if cancelTomb {
					life.Kill(nil)
				} else {
					cancel()
				}
				require.NoError(t, life.Wait())
				_, ok := <-out
				require.False(t, ok)
			})
		})
	}
}
