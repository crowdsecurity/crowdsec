package setup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

func NewDetectConfig(detectReader io.Reader) (*DetectConfig, error) {
	d := DetectConfig{}

	yamlBytes, err := io.ReadAll(detectReader)
	if err != nil {
		return nil, err
	}

	dec := yaml.NewDecoder(bytes.NewBuffer(yamlBytes))
	dec.KnownFields(true)

	if err = dec.Decode(&d); err != nil {
		return nil, err
	}

	for name := range d.Detect {
		svc := d.Detect[name]
		if err := svc.Compile(); err != nil {
			return nil, fmt.Errorf("%q: %w", name, err)
		}

		d.Detect[name] = svc // reassign to ensure the compiled rules are stored
	}

	for name, svc := range d.Detect {
		if err := svc.AcquisitionSpec.Validate(); err != nil {
			return nil, fmt.Errorf("invalid acquisition spec for %s: %w", name, err)
		}
	}

	return &d, nil
}

// ListSupportedServices returns a sorted list of the services recognized by the detectConfig.
func (d *DetectConfig) ListSupportedServices() []string {
	keys := make([]string, 0)
	for k := range d.Detect {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

func (s *ServiceProfile) Compile() error {
	s.compiledWhen = make([]*vm.Program, len(s.When))
	for i, rule := range s.When {
		// pass an empty environment struct so the compiler can know the types
		compiled, err := expr.Compile(rule, expr.WithContext("Ctx"), expr.Env(&ExprEnvironment{}))
		if err != nil {
			return fmt.Errorf("compiling rule %q: %w", rule, err)
		}

		s.compiledWhen[i] = compiled
	}

	return nil
}

func (s *ServiceProfile) Evaluate(env *ExprEnvironment, logger logrus.FieldLogger) (bool, error) {
	match := true

	if len(s.compiledWhen) != len(s.When) {
		return false, errors.New("rules not compiled, call Compile() first")
	}

	for _, rule := range s.compiledWhen {
		out, err := expr.Run(rule, env)
		logger.Debugf("  Rule %q -> %t, %v", rule.Source(), out, err)

		if err != nil {
			return false, fmt.Errorf("rule %q: %w", rule.Source(), err)
		}

		outbool, ok := out.(bool)
		if !ok {
			return false, fmt.Errorf("rule %q: type must be a boolean", rule.Source())
		}

		match = match && outbool
		// keep evaluating, to detect possible expression errors
	}

	return match, nil
}
