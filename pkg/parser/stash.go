package parser

import (
	"errors"
	"fmt"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/cache"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type Stash struct {
	Name       string `yaml:"name,omitempty"`
	Key        string `yaml:"key,omitempty"`
	Value      string `yaml:"value,omitempty"`
	TTL        string `yaml:"ttl,omitempty"`
	MaxMapSize int    `yaml:"size,omitempty"`
	Strategy   string `yaml:"strategy,omitempty"`
}

type RuntimeStash struct {
	Config          *Stash
	KeyExpression   *vm.Program
	ValueExpression *vm.Program
	TTLVal          time.Duration
}

func (s *Stash) Validate() error {
	if s.Name == "" {
		return errors.New("name must be set")
	}

	if s.Value == "" {
		return fmt.Errorf("%s: value expression must be set", s.Name)
	}

	if s.Key == "" {
		return fmt.Errorf("%s: key expression must be set", s.Name)
	}

	if s.TTL == "" {
		return fmt.Errorf("%s: ttl must be set", s.Name)
	}

	if s.Strategy == "" {
		s.Strategy = "LRU"
	}

	// should be configurable
	if s.MaxMapSize == 0 {
		s.MaxMapSize = 100
	}

	return nil
}

func (s *Stash) Compile(logger *log.Entry) (*RuntimeStash, error) {
	var err error

	rs := &RuntimeStash{Config: s}

	rs.ValueExpression, err = expr.Compile(s.Value,
		exprhelpers.GetExprOptions(map[string]any{"evt": &pipeline.Event{}})...)
	if err != nil {
		return nil, fmt.Errorf("while compiling stash value expression: %w", err)
	}

	rs.KeyExpression, err = expr.Compile(s.Key,
		exprhelpers.GetExprOptions(map[string]any{"evt": &pipeline.Event{}})...)
	if err != nil {
		return nil, fmt.Errorf("while compiling stash key expression: %w", err)
	}

	rs.TTLVal, err = time.ParseDuration(s.TTL)
	if err != nil {
		return nil, fmt.Errorf("while parsing stash ttl: %w", err)
	}

	// init the cache, does it make sense to create it here just to be sure everything is fine ?

	cacheCfg := cache.CacheCfg{
		Size:     s.MaxMapSize,
		TTL:      rs.TTLVal,
		Name:     s.Name,
		Strategy: s.Strategy,
		LogLevel: logger.Logger.GetLevel(),
	}

	if err = cache.CacheInit(cacheCfg, cacheCfg.NewLogger()); err != nil {
		return nil, fmt.Errorf("while initializing cache: %w", err)
	}

	return rs, nil
}

func (rs *RuntimeStash) Apply(idx int, cachedExprEnv map[string]any, logger *log.Entry, debug bool) {
	var (
		key   string
		value string
	)

	if rs.ValueExpression == nil {
		logger.Warningf("Stash %d has no value expression, skipping", idx)
		return
	}

	if rs.KeyExpression == nil {
		logger.Warningf("Stash %d has no key expression, skipping", idx)
		return
	}
	// collect the data
	output, err := exprhelpers.Run(rs.ValueExpression, cachedExprEnv, logger, debug)
	if err != nil {
		logger.Warningf("Error while running stash val expression: %v", err)
	}
	// can we expect anything else than a string ?
	switch output := output.(type) {
	case string:
		value = output
	default:
		logger.Warningf("unexpected type %T (%v) while running %q", output, output, rs.Config.Value)
		return
	}

	// collect the key
	output, err = exprhelpers.Run(rs.KeyExpression, cachedExprEnv, logger, debug)
	if err != nil {
		logger.Warningf("Error while running stash key expression: %v", err)
	}
	// can we expect anything else than a string ?
	switch output := output.(type) {
	case string:
		key = output
	default:
		logger.Warningf("unexpected type %T (%v) while running %q", output, output, rs.Config.Key)
		return
	}

	if err = cache.SetKey(rs.Config.Name, key, value, &rs.TTLVal); err != nil {
		logger.Warningf("failed to store data in cache: %s", err.Error())
	}
}
