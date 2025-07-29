package setup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"sort"

	goccyyaml "github.com/goccy/go-yaml"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// BuildSetup creates a Setup. The actual detection of services is done here.
func BuildSetup(ctx context.Context, detectConfig *DetectConfig, opts DetectOptions, exprPath ExprPath, installedUnits UnitMap, runningProcesses ProcessMap, logger logrus.FieldLogger) (*Setup, error) {
	s := Setup{}

	// explicitly initialize to avoid json marshaling an empty slice as "null"
	s.Plans = make([]ServicePlan, 0)

	exprOS, err := DetectOS(opts.ForcedOS, logger)
	if err != nil {
		return nil, err
	}

	if len(opts.ForcedUnits) > 0 {
		logger.Debugf("Forced units - %v", opts.ForcedUnits)
	}

	if len(opts.ForcedProcesses) > 0 {
		logger.Debugf("Forced processes - %v", opts.ForcedProcesses)
	}

	exprSystemd := NewExprSystemd(installedUnits, opts.ForcedUnits)
	exprSystem := NewExprSystem(runningProcesses, opts.ForcedProcesses)

	exprWindows, err := NewExprWindows()
	if err != nil {
		return nil, err
	}

	env := &ExprEnvironment{
		OS:      exprOS,
		Path:    exprPath,
		System:  exprSystem,
		Systemd: exprSystemd,
		Windows: exprWindows,
		Ctx:     ctx,
	}

	detected := make(map[string]ServicePlan)

	for name, svc := range detectConfig.Detect {
		match, err := svc.Evaluate(env, logger)
		if err != nil {
			return nil, fmt.Errorf("while looking for service %s: %w", name, err)
		}

		if !match {
			continue
		}

		// User asked to ignore this service
		if slices.Contains(opts.SkipServices, name) {
			continue
		}

		detected[name] = ServicePlan{
			Name:                  name,
			InstallRecommendation: svc.InstallRecommendation,
		}
	}

	env.checkConsumedForcedItems(logger)

	// sort the keys (service names) to have them in a predictable
	// order in the final output

	keys := make([]string, 0)
	for k := range detected {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, name := range keys {
		s.Plans = append(s.Plans, detected[name])
	}

	return &s, nil
}

// ParseSetupYAML creates a Setup from setup.yaml, which can be user-provided or the result of a service detection.
func ParseSetupYAML(input io.Reader, showSource bool, wantColor bool) (*Setup, error) {
	inputBytes, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("while reading setup file: %w", err)
	}

	// parse with goccy to have better error messages in many cases
	dec := goccyyaml.NewDecoder(bytes.NewBuffer(inputBytes), goccyyaml.Strict())

	s := Setup{}

	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%v", goccyyaml.FormatError(err, wantColor, showSource))
	}

	// parse again because goccy is not strict enough anyway
	dec2 := yaml.NewDecoder(bytes.NewBuffer(inputBytes))
	dec2.KnownFields(true)

	if err := dec2.Decode(&s); err != nil {
		return nil, fmt.Errorf("while parsing setup file: %w", err)
	}

	return &s, nil
}
