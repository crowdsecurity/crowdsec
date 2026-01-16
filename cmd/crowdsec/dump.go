package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
)

func dumpAllStates(dir string) error {
	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		return err
	}

	if err := dumpState(dir, "parser-dump.yaml", parser.StageParseCache); err != nil {
		return fmt.Errorf("dumping parser state: %w", err)
	}

	if err := dumpState(dir, "bucket-dump.yaml", bucketOverflows); err != nil {
		return fmt.Errorf("dumping bucket overflow state: %w", err)
	}

	if err := dumpState(dir, "bucketpour-dump.yaml", leaky.BucketPourCache); err != nil {
		return fmt.Errorf("dumping bucket pour state: %w", err)
	}

	return nil
}

func dumpState(dir, name string, obj any) error {
	out, err := yaml.Marshal(obj)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(dir, name), out, 0o666)
}
