package rawlogstore

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	_ "modernc.org/sqlite"
)

// AccessLog represents a single access log entry from raw_access_logs table.
type AccessLog struct {
	ID         int64  `json:"id"`
	Ts         int64  `json:"ts"`
	Src        string `json:"src,omitempty"`
	Labels     string `json:"labels,omitempty"`
	Module     string `json:"module,omitempty"`
	AcquisType string `json:"acquis_type,omitempty"`
	Raw        string `json:"raw"`
}

// QueryResult contains the query results and pagination info.
type QueryResult struct {
	Items       []AccessLog `json:"items"`
	NextSinceID int64       `json:"next_since_id"`
	HasMore     bool        `json:"has_more"`
	Total       *int64      `json:"total,omitempty"`
}

// QueryOptions specifies optional query parameters.
type QueryOptions struct {
	Type         string // filter by acquis_type
	SinceTs      *int64 // filter by timestamp >= sinceTs
	IncludeTotal bool   // include total count in response
}

// Reader provides read-only access to the raw_access_logs SQLite database.
type Reader struct {
	db     *sql.DB
	logger *log.Entry
}

// NewReader creates a new Reader with a read-only SQLite connection.
func NewReader(dbPath string, logger *log.Entry) (*Reader, error) {
	if logger == nil {
		logger = log.StandardLogger().WithField("service", "rawlogstore-reader")
	}

	dsn := buildReadOnlyDSN(dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("rawlogstore reader open db: %w", err)
	}

	// Set connection pool settings for read-only access
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Verify connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("rawlogstore reader ping: %w", err)
	}

	return &Reader{
		db:     db,
		logger: logger,
	}, nil
}

// Close closes the reader's database connection.
func (r *Reader) Close() error {
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

// Query retrieves access logs with pagination support.
// sinceID: return records with id > sinceID (use 0 for first query)
// limit: max number of records to return (capped at 5000)
func (r *Reader) Query(ctx context.Context, sinceID int64, limit int, opts *QueryOptions) (*QueryResult, error) {
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}

	if opts == nil {
		opts = &QueryOptions{}
	}

	result := &QueryResult{
		Items: make([]AccessLog, 0),
	}

	// Build query with exponential backoff retry for SQLITE_BUSY
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * 100 * time.Millisecond
			r.logger.WithField("attempt", attempt+1).Debug("retrying after SQLITE_BUSY")
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		result, err = r.queryOnce(ctx, sinceID, limit, opts)
		if err == nil {
			return result, nil
		}

		// Check if it's a busy error
		if !isSQLiteBusy(err) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("rawlogstore query failed after retries: %w", err)
}

func (r *Reader) queryOnce(ctx context.Context, sinceID int64, limit int, opts *QueryOptions) (*QueryResult, error) {
	result := &QueryResult{
		Items: make([]AccessLog, 0, limit),
	}

	// Build WHERE clause
	conditions := []string{"id > ?"}
	args := []interface{}{sinceID}

	if opts.Type != "" {
		conditions = append(conditions, "acquis_type = ?")
		args = append(args, opts.Type)
	}

	if opts.SinceTs != nil {
		conditions = append(conditions, "ts >= ?")
		args = append(args, *opts.SinceTs)
	}

	whereClause := strings.Join(conditions, " AND ")

	// Query with limit+1 to detect has_more
	query := fmt.Sprintf(`
		SELECT id, ts, src, labels, module, acquis_type, raw 
		FROM raw_access_logs 
		WHERE %s 
		ORDER BY id ASC 
		LIMIT ?
	`, whereClause)

	args = append(args, limit+1)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("rawlogstore query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var item AccessLog
		var src, labels, module, acquisType sql.NullString

		if err := rows.Scan(&item.ID, &item.Ts, &src, &labels, &module, &acquisType, &item.Raw); err != nil {
			return nil, fmt.Errorf("rawlogstore scan: %w", err)
		}

		item.Src = src.String
		item.Labels = labels.String
		item.Module = module.String
		item.AcquisType = acquisType.String

		result.Items = append(result.Items, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rawlogstore rows: %w", err)
	}

	// Determine has_more and trim to limit
	if len(result.Items) > limit {
		result.HasMore = true
		result.Items = result.Items[:limit]
	}

	// Set next_since_id
	if len(result.Items) > 0 {
		result.NextSinceID = result.Items[len(result.Items)-1].ID
	} else {
		result.NextSinceID = sinceID
	}

	// Optionally include total count
	if opts.IncludeTotal {
		total, err := r.countTotal(ctx, opts)
		if err != nil {
			r.logger.WithError(err).Warn("failed to get total count")
		} else {
			result.Total = &total
		}
	}

	return result, nil
}

func (r *Reader) countTotal(ctx context.Context, opts *QueryOptions) (int64, error) {
	conditions := []string{"1=1"}
	args := []interface{}{}

	if opts.Type != "" {
		conditions = append(conditions, "acquis_type = ?")
		args = append(args, opts.Type)
	}

	if opts.SinceTs != nil {
		conditions = append(conditions, "ts >= ?")
		args = append(args, *opts.SinceTs)
	}

	query := fmt.Sprintf(`SELECT COUNT(*) FROM raw_access_logs WHERE %s`, strings.Join(conditions, " AND "))

	var total int64
	if err := r.db.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return 0, err
	}

	return total, nil
}

func buildReadOnlyDSN(path string) string {
	p := filepath.ToSlash(path)
	if strings.HasPrefix(p, "//") {
		p = p[1:]
	}
	return fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(5000)", p)
}

func isSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "SQLITE_BUSY") ||
		strings.Contains(errStr, "database is locked") ||
		strings.Contains(errStr, "busy")
}
