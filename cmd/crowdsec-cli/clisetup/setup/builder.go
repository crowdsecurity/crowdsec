package setup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"

	goccyyaml "github.com/goccy/go-yaml"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type SetupBuilder struct{}

func NewSetupBuilder() *SetupBuilder {
	return &SetupBuilder{}
}

func (b *SetupBuilder) Build(ctx context.Context, detector *Detector, opts DetectOptions, pathChecker PathChecker, installedUnits UnitMap, runningProcesses ProcessMap, logger *logrus.Logger) (*Setup, error) {
	s := Setup{}

	// explicitly initialize to avoid json marshaling an empty slice as "null"
	s.Plans = make([]ServicePlan, 0)

	os, err := DetectOS(opts.ForcedOS, logger)
	if err != nil {
		return nil, err
	}

	if len(opts.ForcedUnits) > 0 {
		logger.Debugf("Forced units - %v", opts.ForcedUnits)
	}

	if len(opts.ForcedProcesses) > 0 {
		logger.Debugf("Forced processes - %v", opts.ForcedProcesses)
	}

	state := NewExprState(opts, installedUnits, runningProcesses)
	env := NewExprEnvironment(ctx, os, state, pathChecker)

	detected := make(map[string]ServicePlan)

	for name, svc := range detector.Detect {
		match, err := svc.Evaluate(env, logger)
		if err != nil {
			return nil, fmt.Errorf("while looking for service %s: %w", name, err)
		}

		if !match {
			continue
		}

		detected[name] = ServicePlan{
			Name:                  name,
			InstallRecommendation: svc.InstallRecommendation,
		}
	}

	if err = checkConsumedForcedItems(env); err != nil {
		return nil, err
	}

	// remove services the user asked to ignore
	for _, name := range opts.SkipServices {
		delete(detected, name)
	}

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

func (b *SetupBuilder) FromYAML(input io.Reader, showSource bool, wantColor bool) (*Setup, error) {
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
