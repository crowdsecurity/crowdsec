package lokiclient

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Streaming polls settled windows; replay drains the fixed range from the URL.
func (lc *LokiClient) readRange(ctx context.Context, uri string, out chan *LokiQueryRangeResponse, infinite bool) error {
	defer close(out)
	parsed, err := url.Parse(uri)
	if err != nil {
		return err
	}
	params := parsed.Query()
	start, err := strconv.ParseInt(params.Get("start"), 10, 64)
	if err != nil {
		return err
	}
	end, err := strconv.ParseInt(params.Get("end"), 10, 64)
	if err != nil {
		return err
	}
	if lc.config.Limit <= 0 || lc.config.PollInterval <= 0 {
		return errors.New("Loki limit and poll_interval must be positive")
	}
	lc.currentTickerInterval = lc.config.PollInterval
	ticker := time.NewTicker(lc.currentTickerInterval)
	defer ticker.Stop()
	for {
		if infinite {
			end = time.Now().Add(-lc.config.QueryDelay).UnixNano()
		}
		if end > start {
			err = lc.readWindow(ctx, parsed, start, end, out, ticker)
			if ctx.Err() != nil || !lc.t.Alive() {
				return nil
			}
			if err != nil {
				return err
			}
			start = end
		}
		if !infinite {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-lc.t.Dying():
			return nil
		case <-ticker.C:
		}
	}
}

func (lc *LokiClient) readWindow(ctx context.Context, uri *url.URL, start, end int64, out chan *LokiQueryRangeResponse, ticker *time.Ticker) error {
	params := uri.Query()
	seen := make(map[[32]byte]int)
	limit := lc.config.Limit
	for {
		params.Set("start", strconv.FormatInt(start, 10))
		params.Set("end", strconv.FormatInt(end, 10))
		params.Set("limit", strconv.Itoa(limit))
		uri.RawQuery = params.Encode()
		page, err := lc.queryPage(ctx, uri.String())
		if err != nil {
			if ctx.Err() != nil || !lc.t.Alive() {
				return err
			}
			if !lc.shouldRetry() {
				return fmt.Errorf("querying loki: %w", err)
			}
			lc.increaseTicker(ticker)
			lc.Logger.Warnf("loki query failed, retrying the same window in %s: %s", lc.currentTickerInterval, err)
			select {
			case <-ctx.Done():
				return nil
			case <-lc.t.Dying():
				return nil
			case <-ticker.C:
			}
			continue
		}
		lc.resetFailStart()
		lc.currentTickerInterval = lc.config.PollInterval
		ticker.Reset(lc.currentTickerInterval)
		count := 0
		latest := start
		for _, stream := range page.Data.Result {
			for _, entry := range stream.Entries {
				count++
				latest = max(latest, entry.Timestamp.UnixNano())
			}
		}
		boundary := filterSeenEntries(&page, latest, seen)
		select {
		case out <- &page:
		case <-ctx.Done():
			return nil
		case <-lc.t.Dying():
			return nil
		}
		if count < limit {
			// Loki log queries use [start, end), so the next window may start at end.
			return nil
		}
		if latest == start {
			// Re-read the inclusive boundary with a larger page to retrieve all ties.
			if limit > math.MaxInt-lc.config.Limit {
				return fmt.Errorf("too many Loki entries at timestamp %d", start)
			}
			for key, n := range boundary {
				seen[key] = max(seen[key], n)
			}
			limit += lc.config.Limit
		} else {
			start = latest
			seen = boundary
			limit = lc.config.Limit
		}
	}
}

func filterSeenEntries(page *LokiQueryRangeResponse, latest int64, seen map[[32]byte]int) map[[32]byte]int {
	occurrences := make(map[[32]byte]int)
	boundary := make(map[[32]byte]int)
	for i := range page.Data.Result {
		stream := &page.Data.Result[i]
		labels, _ := json.Marshal(stream.Stream)
		fresh := stream.Entries[:0]
		for _, entry := range stream.Entries {
			key := sha256.Sum256([]byte(string(labels) + "\x00" + strconv.FormatInt(entry.Timestamp.UnixNano(), 10) + "\x00" + entry.Line))
			occurrences[key]++
			if entry.Timestamp.UnixNano() == latest {
				boundary[key] = occurrences[key]
			}
			// Count occurrences so identical legitimate entries are not collapsed.
			if occurrences[key] > seen[key] {
				fresh = append(fresh, entry)
			}
		}
		stream.Entries = fresh
	}
	return boundary
}

func (lc *LokiClient) queryPage(ctx context.Context, uri string) (LokiQueryRangeResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var page LokiQueryRangeResponse
	resp, err := lc.Get(ctx, uri)
	if err != nil {
		return page, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return page, fmt.Errorf("loki returned HTTP %d: %s", resp.StatusCode, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return page, err
	}
	if page.Status != "success" || page.Data.ResultType != "streams" {
		return page, fmt.Errorf("invalid Loki response: status=%q resultType=%q", page.Status, page.Data.ResultType)
	}
	return page, nil
}
