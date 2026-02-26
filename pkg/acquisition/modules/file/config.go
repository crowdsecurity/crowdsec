package fileacquisition

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	yaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Configuration struct {
	Filenames                         []string
	ExcludeRegexps                    []string `yaml:"exclude_regexps"`
	Filename                          string
	ForceInotify                      bool          `yaml:"force_inotify"`
	MaxBufferSize                     int           `yaml:"max_buffer_size"`
	PollWithoutInotify                *bool         `yaml:"poll_without_inotify"`
	DiscoveryPollEnable               bool          `yaml:"discovery_poll_enable"`
	DiscoveryPollInterval             time.Duration `yaml:"discovery_poll_interval"`
	TailMode                          string        `yaml:"tail_mode"`          // "default" or "stat" (defaults to "default" if empty)
	StatPollInterval                  time.Duration `yaml:"stat_poll_interval"` // stat poll interval used when tail_mode=stat (default 1s, 0=1s, -1=manual)
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

func (s *Source) UnmarshalConfig(yamlConfig []byte) error {
	s.config = Configuration{}

	err := yaml.UnmarshalWithOptions(yamlConfig, &s.config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse FileAcquisition configuration: %s", yaml.FormatError(err, false, false))
	}

	if s.logger != nil {
		s.logger.Tracef("FileAcquisition configuration: %+v", s.config)
	}

	if s.config.Filename != "" {
		s.config.Filenames = append(s.config.Filenames, s.config.Filename)
	}

	if len(s.config.Filenames) == 0 {
		return errors.New("no filename or filenames configuration provided")
	}

	if s.config.Mode == "" {
		s.config.Mode = configuration.TAIL_MODE
	}

	if s.config.Mode != configuration.CAT_MODE && s.config.Mode != configuration.TAIL_MODE {
		return fmt.Errorf("unsupported mode %s for file source", s.config.Mode)
	}

	for _, exclude := range s.config.ExcludeRegexps {
		re, err := regexp.Compile(exclude)
		if err != nil {
			return fmt.Errorf("could not compile regexp %s: %w", exclude, err)
		}

		s.exclude_regexps = append(s.exclude_regexps, re)
	}

	return nil
}

func (s *Source) Configure(_ context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	s.logger = logger
	s.metricsLevel = metricsLevel

	err := s.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	s.watchedDirectories = make(map[string]bool)
	s.tailMapMutex = &sync.RWMutex{}
	s.tails = make(map[string]bool)

	s.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("could not create fsnotify watcher: %w", err)
	}

	s.logger.Tracef("Actual FileAcquisition Configuration %+v", s.config)

	for _, pattern := range s.config.Filenames {
		if s.config.ForceInotify {
			directory := filepath.Dir(pattern)
			s.logger.Infof("Force add watch on %s", directory)

			if !s.watchedDirectories[directory] {
				err = s.watcher.Add(directory)
				if err != nil {
					s.logger.Errorf("Could not create watch on directory %s : %s", directory, err)
					continue
				}

				s.watchedDirectories[directory] = true
			}
		}

		files, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("glob failure: %w", err)
		}

		if len(files) == 0 {
			s.logger.Warnf("No matching files for pattern %s", pattern)
			continue
		}

		for _, file := range files {
			if s.isExcluded(file) {
				continue
			}

			if files[0] != pattern && s.config.Mode == configuration.TAIL_MODE { // we have a glob pattern
				directory := filepath.Dir(file)
				s.logger.Debugf("Will add watch to directory: %s", directory)

				if !s.watchedDirectories[directory] {
					err = s.watcher.Add(directory)
					if err != nil {
						s.logger.Errorf("Could not create watch on directory %s : %s", directory, err)
						continue
					}

					s.watchedDirectories[directory] = true
				} else {
					s.logger.Debugf("Watch for directory %s already exists", directory)
				}
			}

			s.logger.Infof("Adding file %s to datasources", file)
			s.files = append(s.files, file)
		}
	}

	return nil
}

func (s *Source) ConfigureByDSN(_ context.Context, dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	if !strings.HasPrefix(dsn, "file://") {
		return fmt.Errorf("invalid DSN %s for file source, must start with file://", dsn)
	}

	s.logger = logger
	s.config = Configuration{}

	dsn = strings.TrimPrefix(dsn, "file://")

	args := strings.Split(dsn, "?")

	if args[0] == "" {
		return errors.New("empty file:// DSN")
	}

	if len(args) == 2 && args[1] != "" {
		params, err := url.ParseQuery(args[1])
		if err != nil {
			return fmt.Errorf("could not parse file args: %w", err)
		}

		for key, value := range params {
			switch key {
			case "log_level":
				if len(value) != 1 {
					return errors.New("expected zero or one value for 'log_level'")
				}

				lvl, err := log.ParseLevel(value[0])
				if err != nil {
					return fmt.Errorf("unknown level %s: %w", value[0], err)
				}

				s.logger.Logger.SetLevel(lvl)
			case "max_buffer_size":
				if len(value) != 1 {
					return errors.New("expected zero or one value for 'max_buffer_size'")
				}

				maxBufferSize, err := strconv.Atoi(value[0])
				if err != nil {
					return fmt.Errorf("could not parse max_buffer_size %s: %w", value[0], err)
				}

				s.config.MaxBufferSize = maxBufferSize
			default:
				return fmt.Errorf("unknown parameter %s", key)
			}
		}
	}

	s.config.Labels = labels
	s.config.Mode = configuration.CAT_MODE
	s.config.UniqueId = uuid

	s.logger.Debugf("Will try pattern %s", args[0])

	files, err := filepath.Glob(args[0])
	if err != nil {
		return fmt.Errorf("glob failure: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no matching files for pattern %s", args[0])
	}

	if len(files) > 1 {
		s.logger.Infof("Will read %d files", len(files))
	}

	for _, file := range files {
		s.logger.Infof("Adding file %s to filelist", file)
		s.files = append(s.files, file)
	}

	return nil
}
