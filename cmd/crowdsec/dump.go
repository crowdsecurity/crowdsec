package main

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
)

func dumpAllStates() error {
	log.Debugf("Dumping parser+bucket states to %s", parser.DumpFolder)

	if err := dumpState(
		filepath.Join(parser.DumpFolder, "parser-dump.yaml"),
		parser.StageParseCache,
	); err != nil {
		return fmt.Errorf("while dumping parser state: %w", err)
	}

	if err := dumpState(
		filepath.Join(parser.DumpFolder, "bucket-dump.yaml"),
		bucketOverflows,
	); err != nil {
		return fmt.Errorf("while dumping bucket overflow state: %w", err)
	}

	if err := dumpState(
		filepath.Join(parser.DumpFolder, "bucketpour-dump.yaml"),
		leaky.BucketPourCache,
	); err != nil {
		return fmt.Errorf("while dumping bucket pour state: %w", err)
	}

	return nil
}

func dumpState(destPath string, obj any) error {
	dir := filepath.Dir(destPath)

	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		return err
	}

	out, err := yaml.Marshal(obj)
	if err != nil {
		return err
	}

	return os.WriteFile(destPath, out, 0o666)
}
