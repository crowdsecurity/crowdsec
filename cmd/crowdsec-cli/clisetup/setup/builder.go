package setup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"

	goccyyaml "github.com/goccy/go-yaml"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

func toSet(list []string) map[string]struct{} {
	set := make(map[string]struct{}, len(list))
	for _, v := range list {
		set[v] = struct{}{}
	}
	return set
}

// BuildSetup creates a Setup. The actual detection of services is done here.
func BuildSetup(ctx context.Context, detectConfig *DetectConfig, opts DetectOptions, exprPath ExprPath, installedUnits UnitMap, runningProcesses ProcessMap, logger logrus.FieldLogger) (*Setup, error) {
	s := Setup{}

	// explicitly initialize to avoid json marshaling an empty slice as "null"
	s.Plans = make([]ServicePlan, 0)

	hostInfo, err := host.InfoWithContext(ctx)
	if err != nil {
		return nil, err
	}

	logger.Debugf("Detected host info: %s", hostInfo)

	exprSystemd := NewExprSystemd(installedUnits, logger)
	exprSystem := NewExprSystem(runningProcesses)

	exprWindows, err := NewExprWindows()
	if err != nil {
		return nil, err
	}

	env := &ExprEnvironment{
		Host:    *hostInfo,
		Path:    exprPath,
		System:  exprSystem,
		Systemd: exprSystemd,
		Version: ExprVersion{},
		Windows: exprWindows,
		Ctx:     ctx,
	}

	detected := make(map[string]ServicePlan)

	want := toSet(opts.WantServices)
	skip := toSet(opts.SkipServices)

	for name, svc := range detectConfig.Detect {
		match, err := svc.Evaluate(env, logger)
		if err != nil {
			return nil, fmt.Errorf("while looking for service %s: %w", name, err)
		}

		_, forced := want[name]
		if forced {
			delete(want, name)
		}

		if !match && !forced {
			continue
		}

		// User asked to ignore this service
		if _, skipIt := skip[name]; skipIt {
			continue
		}

		detected[name] = ServicePlan{
			Name:                  name,
			InstallRecommendation: svc.InstallRecommendation,
		}
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

	if len(want) > 0 {
		missing := make([]string, 0, len(want))
		for name := range want {
			missing = append(missing, name)
		}

		sort.Strings(missing)

		return nil, fmt.Errorf("could not find the following services: %v, please check the service detection rules", missing)
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
