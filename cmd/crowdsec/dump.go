package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
)

func dumpAllStates(dir string, pourCollector *leakybucket.PourCollector, stageCollector *parser.StageParseCollector) error {
	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		return err
	}

	if err := dumpCollector(dir, "parser-dump.yaml", stageCollector); err != nil {
		return fmt.Errorf("dumping parser state: %w", err)
	}

	if err := dumpState(dir, "bucket-dump.yaml", bucketOverflows); err != nil {
		return fmt.Errorf("dumping bucket overflow state: %w", err)
	}

	if err := dumpCollector(dir, "bucketpour-dump.yaml", pourCollector); err != nil {
		return fmt.Errorf("dumping bucket pour state: %w", err)
	}

	return nil
}

type YAMLDumper interface {
	DumpYAML() ([]byte, error)
}

func dumpCollector(dir, name string, collector YAMLDumper) error {
	out, err := collector.DumpYAML()
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(dir, name), out, 0o644)
}

func dumpState(dir, name string, obj any) error {
	out, err := yaml.Marshal(obj)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(dir, name), out, 0o666)
}
