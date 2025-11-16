package fileacquisition

import (
	"regexp"
	"sync"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Source struct {
	metricsLevel       metrics.AcquisitionMetricsLevel
	config             Configuration
	watcher            *fsnotify.Watcher
	watchedDirectories map[string]bool
	tails              map[string]bool
	logger             *log.Entry
	files              []string
	exclude_regexps    []*regexp.Regexp
	tailMapMutex       *sync.RWMutex
}

func (s *Source) GetUuid() string {
	return s.config.UniqueId
}

func (s *Source) GetMode() string {
	return s.config.Mode
}

func (*Source) GetName() string {
	return "file"
}

func (*Source) CanRun() error {
	return nil
}

func (s *Source) Dump() any {
	return s
}
