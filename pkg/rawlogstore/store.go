package rawlogstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	_ "modernc.org/sqlite"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type Store struct {
	cfg       *csconfig.RawLogCfg
	logger    *log.Entry
	db        *sql.DB
	in        chan entry
	dropped   atomic.Uint64
	startedAt time.Time
}

type entry struct {
	ts         int64
	src        string
	labelsJSON string
	module     string
	acquisType string
	raw        string
}

func Start(ctx context.Context, cfg *csconfig.RawLogCfg, logger *log.Entry) (*Store, error) {
	if cfg == nil || cfg.Enabled == nil || !*cfg.Enabled {
		return nil, nil
	}

	if logger == nil {
		logger = log.StandardLogger().WithField("service", "rawlogstore")
	}

	dsn := buildSQLiteDSN(cfg.DbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("rawlogstore open db: %w", err)
	}

	if err := initializeSchema(db); err != nil {
		return nil, fmt.Errorf("rawlogstore schema init: %w", err)
	}

	store := &Store{
		cfg:       cfg,
		logger:    logger,
		db:        db,
		in:        make(chan entry, cfg.QueueSize),
		startedAt: time.Now().UTC(),
	}

	go store.run(ctx)

	return store, nil
}

func (s *Store) Ingest(evt pipeline.Event) {
	if s == nil || s.cfg == nil || s.cfg.Enabled == nil || !*s.cfg.Enabled {
		return
	}

	if s.cfg.CaptureType != "" {
		if evt.Line.Labels == nil || evt.Line.Labels["type"] != s.cfg.CaptureType {
			return
		}
	}

	if evt.Line.Raw == "" {
		return
	}

	labelsJSON, _ := json.Marshal(evt.Line.Labels)
	acquisType := ""
	if evt.Line.Labels != nil {
		acquisType = evt.Line.Labels["type"]
	}

	ts := time.Now().UTC()
	if !evt.Line.Time.IsZero() {
		ts = evt.Line.Time.UTC()
	}

	e := entry{
		ts:         ts.Unix(),
		src:        evt.Line.Src,
		labelsJSON: string(labelsJSON),
		module:     evt.Line.Module,
		acquisType: acquisType,
		raw:        evt.Line.Raw,
	}

	select {
	case s.in <- e:
	default:
		if s.dropped.Add(1)%1000 == 1 {
			s.logger.WithField("dropped", s.dropped.Load()).Warn("rawlogstore queue full, dropping logs")
		}
	}
}

func (s *Store) run(ctx context.Context) {
	flushTicker := time.NewTicker(s.cfg.FlushIntervalDuration)
	defer flushTicker.Stop()

	cleanupTicker := time.NewTicker(1 * time.Hour)
	defer cleanupTicker.Stop()

	batch := make([]entry, 0, s.cfg.BatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}

		if err := s.insertBatch(ctx, batch); err != nil {
			s.logger.WithError(err).Error("rawlogstore insert batch failed")
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			_ = s.db.Close()
			return
		case e := <-s.in:
			batch = append(batch, e)
			if len(batch) >= s.cfg.BatchSize {
				flush()
			}
		case <-flushTicker.C:
			flush()
		case <-cleanupTicker.C:
			if s.cfg.RetentionDuration > 0 {
				if err := s.deleteExpired(ctx); err != nil {
					s.logger.WithError(err).Warn("rawlogstore cleanup failed")
				}
			}
		}
	}
}

func (s *Store) insertBatch(ctx context.Context, batch []entry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO raw_access_logs (ts, src, labels, module, acquis_type, raw) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, e := range batch {
		if _, err := stmt.ExecContext(ctx, e.ts, e.src, e.labelsJSON, e.module, e.acquisType, e.raw); err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) deleteExpired(ctx context.Context) error {
	cutoff := time.Now().UTC().Add(-s.cfg.RetentionDuration).Unix()
	_, err := s.db.ExecContext(ctx, `DELETE FROM raw_access_logs WHERE ts < ?`, cutoff)
	return err
}

func initializeSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS raw_access_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts INTEGER NOT NULL,
			src TEXT,
			labels TEXT,
			module TEXT,
			acquis_type TEXT,
			raw TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_raw_access_logs_ts ON raw_access_logs(ts);
		CREATE INDEX IF NOT EXISTS idx_raw_access_logs_type ON raw_access_logs(acquis_type);
	`)
	return err
}

func buildSQLiteDSN(path string) string {
	p := filepath.ToSlash(path)
	if strings.HasPrefix(p, "//") {
		p = p[1:]
	}
	return fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)", p)
}
