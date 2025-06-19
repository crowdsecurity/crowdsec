package setup

import (
	"bytes"
	"github.com/mohae/deepcopy"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"sort"

	"github.com/Masterminds/semver/v3"
	"github.com/blackfireio/osinfo"
	"github.com/expr-lang/expr"
	"github.com/shirou/gopsutil/v3/process"
	log "github.com/sirupsen/logrus"
	goccyyaml "github.com/goccy/go-yaml"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
)

// ExecCommand can be replaced with a mock during tests.
var ExecCommand = exec.Command

// HubItems contains the objects (mostly collections) that are recommended to support a service.
type HubItems map[string][]string

type DataSourceItem map[string]any

type ServiceRecommendation struct {
	Install    HubItems       `yaml:"install,omitempty"`
	DataSource DataSourceItem `yaml:"datasource,omitempty"`
}

// ServicePlan describes the actions to perform for a detected service.
type ServicePlan struct {
	Name       string     `yaml:"detected_service"`
	ServiceRecommendation `yaml:",inline"`
}

// XXX: TODO: Setup is not validated in any way. it can contain non-existent items, malformed acquisition etc.

// Setup is a container for a list of ServiceSetup objects, allowing for future extensions.
type Setup struct {
	Setup []ServicePlan `yaml:"setup"`
}

func (s *Setup) WantedHubItems() []HubItems {
	ret := []HubItems{}

	for _, svc := range s.Setup {
		ret = append(ret, svc.Install)
	}

	return ret
}

func (s *Setup) WantedAcquisition() map[string]DataSourceItem {
	ret := map[string]DataSourceItem{}

	for _, svc := range s.Setup {
		if len(svc.DataSource) > 0 {
			ret[svc.Name] = svc.DataSource
		}
	}

	return ret
}

func (s *Setup) DetectedServices() []string {
	ret := make([]string, 0, len(s.Setup))

	for _, svc := range s.Setup {
		ret = append(ret, svc.Name)
	}

	slices.Sort(ret)

	return ret
}

func NewSetupFromYAML(input io.Reader, fancyErrors bool) (Setup, error) {
	inputBytes, err := io.ReadAll(input)
	if err != nil {
		return Setup{}, fmt.Errorf("while reading setup file: %w", err)
	}

	// parse with goccy to have better error messages in many cases
	dec := goccyyaml.NewDecoder(bytes.NewBuffer(inputBytes), goccyyaml.Strict())

	s := Setup{}

	if err := dec.Decode(&s); err != nil {
		if fancyErrors {
			return Setup{}, fmt.Errorf("%v", goccyyaml.FormatError(err, true, true))
		}
		// XXX errors here are multiline, should we just print them to stderr instead of logging?
		return Setup{}, fmt.Errorf("%v", err)
	}

	// parse again because goccy is not strict enough anyway
	dec2 := yaml.NewDecoder(bytes.NewBuffer(inputBytes))
	dec2.KnownFields(true)

	if err := dec2.Decode(&s); err != nil {
		return Setup{}, fmt.Errorf("while parsing setup file: %w", err)
	}

	return s, nil
}

func (s *Setup) ToYAML(outYaml bool) ([]byte, error) {
	var (
		ret []byte
		err error
	)

	indentLevel := 2
	buf := &bytes.Buffer{}
	enc := yaml.NewEncoder(buf)
	enc.SetIndent(indentLevel)

	if err = enc.Encode(s); err != nil {
		return nil, err
	}

	if err = enc.Close(); err != nil {
		return nil, err
	}

	ret = buf.Bytes()

	if !outYaml {
		// take a general approach to output json, so we avoid the
		// double tags in the structures and can use go-yaml features
		// missing from the json package
		ret, err = goccyyaml.YAMLToJSON(ret)
		if err != nil {
			return nil, err
		}
	}

	return ret, nil
}

func validateDataSource(opaqueDS DataSourceItem) error {
	if len(opaqueDS) == 0 {
		// empty datasource is valid
		return nil
	}

	// formally validate YAML

	commonDS := configuration.DataSourceCommonCfg{}

	body, err := yaml.Marshal(opaqueDS)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(body, &commonDS)
	if err != nil {
		return err
	}

	// source is mandatory // XXX unless it's not?

	if commonDS.Source == "" {
		return errors.New("source is empty")
	}

	// source must be known

	ds, err := acquisition.GetDataSourceIface(commonDS.Source)
	if err != nil {
		return err
	}

	// unmarshal and validate the rest with the specific implementation

	err = ds.UnmarshalConfig(body)
	if err != nil {
		return err
	}

	// pp.Println(ds)
	return nil
}

func NewDetector(detectReader io.Reader) (*Detector, error) {
	d := Detector{}

	yamlBytes, err := io.ReadAll(detectReader)
	if err != nil {
		return nil, err
	}

	dec := yaml.NewDecoder(bytes.NewBuffer(yamlBytes))
	dec.KnownFields(true)

	if err = dec.Decode(&d); err != nil {
		return nil, err
	}

	switch d.Version {
	case "":
		return nil, errors.New("missing version tag (must be 1.0)")
	case "1.0":
		// all is well
	default:
		return nil, fmt.Errorf("invalid version tag '%s' (must be 1.0)", d.Version)
	}

	for name, svc := range d.Detect {
		err = validateDataSource(svc.DataSource)
		if err != nil {
			return nil, fmt.Errorf("invalid datasource for %s: %w", name, err)
		}
	}

	return &d, nil
}

// ListSupported parses the configuration file and outputs a list of the supported services.
func (d *Detector) ListSupportedServices() []string {
	keys := make([]string, 0)
	for k := range d.Detect {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

func NewSetup(detector *Detector, opts DetectOptions) (*Setup, error) {
	s := Setup{}

	// explicitly initialize to avoid json mashaling an empty slice as "null"
	s.Setup = make([]ServicePlan, 0)

	os := opts.ForcedOS
	if os == (ExprOS{}) {
		osfull, err := osinfo.GetOSInfo()
		if err != nil {
			return nil, fmt.Errorf("detecting OS: %w", err)
		}

		log.Tracef("Detected OS - %+v", *osfull)

		os = ExprOS{
			Family:     osfull.Family,
			ID:         osfull.ID,
			RawVersion: osfull.Version,
		}
	} else {
		log.Tracef("Forced OS - %+v", os)
	}

	if len(opts.ForcedUnits) > 0 {
		log.Tracef("Forced units - %v", opts.ForcedUnits)
	}

	if len(opts.ForcedProcesses) > 0 {
		log.Tracef("Forced processes - %v", opts.ForcedProcesses)
	}

	env := NewExprEnvironment(opts, os)

	detected, err := filterWithRules(detector, env)
	if err != nil {
		return nil, err
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
		svc := detected[name]

		s.Setup = append(s.Setup, ServicePlan{
			Name:                  name,
			ServiceRecommendation: svc.ServiceRecommendation,
		})
	}

	return &s, nil
}

// ServiceRules describes the rules for detecting a service and its recommended items.
type ServiceRules struct {
	When []string         `yaml:"when"`
	ServiceRecommendation `yaml:",inline"`
}

// Detector is generated from the detection rules (detect.yaml) and can generate the setup plan.
type Detector struct {
	Version string                  `yaml:"version"`
	Detect  map[string]ServiceRules `yaml:"detect"`
}

// ExprState keeps a global state for the duration of the service detection (cache etc.)
type ExprState struct {
	unitsSearched map[string]bool
	detectOptions DetectOptions

	// cache
	installedUnits map[string]bool
	// true if the list of running processes has already been retrieved, we can
	// avoid getting it a second time.
	processesSearched map[string]bool
	// cache
	runningProcesses map[string]bool
}

// ExprServiceState keeps a local state during the detection of a single service. It is reset before each service rules' evaluation.
type ExprServiceState struct {
	detectedUnits []string
}

// ExprOS contains the detected (or forced) OS fields available to the rule engine.
type ExprOS struct {
	Family     string
	ID         string
	RawVersion string
}

// This is not required with Masterminds/semver
/*
// normalizeVersion strips leading zeroes from each part, to allow comparison of ubuntu-like versions.
func normalizeVersion(version string) string {
	// if it doesn't match a version string, return unchanged
	if ok := regexp.MustCompile(`^(\d+)(\.\d+)?(\.\d+)?$`).MatchString(version); !ok {
		// definitely not an ubuntu-like version, return unchanged
		return version
	}

	ret := []rune{}

	var cur rune

	trim := true
	for _, next := range version + "." {
		if trim && cur == '0' && next != '.' {
			cur = next

			continue
		}

		if cur != 0 {
			ret = append(ret, cur)
		}

		trim = (cur == '.' || cur == 0)
		cur = next
	}

	return string(ret)
}
*/

// VersionCheck returns true if the version of the OS matches the given constraint
func (os ExprOS) VersionCheck(constraint string) (bool, error) {
	v, err := semver.NewVersion(os.RawVersion)
	if err != nil {
		return false, err
	}

	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return false, err
	}

	return c.Check(v), nil
}

// VersionAtLeast returns true if the version of the OS is at least the given version.
func (os ExprOS) VersionAtLeast(constraint string) (bool, error) {
	return os.VersionCheck(">=" + constraint)
}

// VersionIsLower returns true if the version of the OS is lower than the given version.
func (os ExprOS) VersionIsLower(version string) (bool, error) {
	result, err := os.VersionAtLeast(version)
	if err != nil {
		return false, err
	}

	return !result, nil
}

// ExprEnvironment is used to expose functions and values to the rule engine.
// It can cache the results of service detection commands, like systemctl etc.
type ExprEnvironment struct {
	OS ExprOS

	_serviceState *ExprServiceState
	_state        *ExprState
}

// NewExprEnvironment creates an environment object for the rule engine.
func NewExprEnvironment(opts DetectOptions, os ExprOS) ExprEnvironment {
	return ExprEnvironment{
		_state: &ExprState{
			detectOptions: opts,

			unitsSearched:  make(map[string]bool),
			installedUnits: make(map[string]bool),

			processesSearched: make(map[string]bool),
			runningProcesses:  make(map[string]bool),
		},
		_serviceState: &ExprServiceState{},
		OS:            os,
	}
}

// PathExists returns true if the given path exists.
func (e ExprEnvironment) PathExists(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}

// UnitFound returns true if the unit is listed in the systemctl output.
// Whether a disabled or failed unit is considered found or not, depends on the
// systemctl parameters used.
func (e ExprEnvironment) UnitFound(unitName string) (bool, error) {
	// fill initial caches
	if len(e._state.unitsSearched) == 0 {
		if !e._state.detectOptions.SnubSystemd {
			units, err := systemdUnitList()
			if err != nil {
				return false, err
			}

			for _, name := range units {
				e._state.installedUnits[name] = true
			}
		}

		for _, name := range e._state.detectOptions.ForcedUnits {
			e._state.installedUnits[name] = true
		}
	}

	e._state.unitsSearched[unitName] = true
	if e._state.installedUnits[unitName] {
		e._serviceState.detectedUnits = append(e._serviceState.detectedUnits, unitName)

		return true, nil
	}

	return false, nil
}

// ProcessRunning returns true if there is a running process with the given name.
func (e ExprEnvironment) ProcessRunning(processName string) (bool, error) {
	if len(e._state.processesSearched) == 0 {
		procs, err := process.Processes()
		if err != nil {
			return false, fmt.Errorf("while looking up running processes: %w", err)
		}

		for _, p := range procs {
			name, err := p.Name()
			if err != nil {
				return false, fmt.Errorf("while looking up running processes: %w", err)
			}

			e._state.runningProcesses[name] = true
		}

		for _, name := range e._state.detectOptions.ForcedProcesses {
			e._state.runningProcesses[name] = true
		}
	}

	e._state.processesSearched[processName] = true

	return e._state.runningProcesses[processName], nil
}

// applyRules checks if the 'when' expressions are true and returns a ServiceRules struct,
// augmented with default values and anything that might be useful later on
//
// All expressions are evaluated (no short-circuit) because we want to know if there are errors.
func applyRules(svc ServiceRules, env ExprEnvironment) (ServiceRules, bool, error) {
	// make a copy because we need the original to detect more stuff
	newsvc := deepcopy.Copy(svc).(ServiceRules)
	svcok := true
	env._serviceState = &ExprServiceState{}

	for _, rule := range svc.When {
		out, err := expr.Eval(rule, env)
		log.Tracef("  Rule '%s' -> %t, %v", rule, out, err)

		if err != nil {
			return ServiceRules{}, false, fmt.Errorf("rule '%s': %w", rule, err)
		}

		outbool, ok := out.(bool)
		if !ok {
			return ServiceRules{}, false, fmt.Errorf("rule '%s': type must be a boolean", rule)
		}

		svcok = svcok && outbool
	}

	// XXX: want to get fancy, and generate a filter from the name of the unit? or maybe not
	//	if newsvc.Acquis == nil || (newsvc.Acquis.LogFiles == nil && newsvc.Acquis.JournalCTLFilter == nil) {
	//		for _, unitName := range env._serviceState.detectedUnits {
	//			if newsvc.Acquis == nil {
	//				newsvc.Acquis = &AcquisItem{}
	//			}
	//			// if there is reference to more than one unit in the rules, we use the first one
	//			newsvc.Acquis.JournalCTLFilter = []string{fmt.Sprintf(`_SYSTEMD_UNIT=%s`, unitName)}
	//			break //nolint  // we want to exit after one iteration
	//		}
	//	}

	return newsvc, svcok, nil
}

// filterWithRules decorates a DetectConfig map by filtering according to the when: clauses,
// and applying default values or whatever useful to the Service items.
func filterWithRules(detector *Detector, env ExprEnvironment) (map[string]ServiceRules, error) {
	ret := make(map[string]ServiceRules)

	for name := range detector.Detect {
		//
		// an empty list of when: clauses defaults to true, if we want
		// to change this behavior, the place is here.
		// if len(svc.When) == 0 {
		// 	log.Warningf("empty 'when' clause: %+v", svc)
		// }
		//
		log.Trace("Evaluating rules for: ", name)

		svc, ok, err := applyRules(detector.Detect[name], env)
		if err != nil {
			return nil, fmt.Errorf("while looking for service %s: %w", name, err)
		}

		if !ok {
			log.Tracef("  Skipping %s", name)

			continue
		}

		log.Tracef("  Detected %s", name)

		ret[name] = svc
	}

	return ret, nil
}

// return units that have been forced but not searched yet.
func (e ExprEnvironment) unsearchedUnits() []string {
	ret := []string{}

	for _, unit := range e._state.detectOptions.ForcedUnits {
		if !e._state.unitsSearched[unit] {
			ret = append(ret, unit)
		}
	}

	return ret
}

// return processes that have been forced but not searched yet.
func (e ExprEnvironment) unsearchedProcesses() []string {
	ret := []string{}

	for _, proc := range e._state.detectOptions.ForcedProcesses {
		if !e._state.processesSearched[proc] {
			ret = append(ret, proc)
		}
	}

	return ret
}

// checkConsumedForcedItems checks if all the "forced" options (units or processes) have been evaluated during the service detection.
func checkConsumedForcedItems(e ExprEnvironment) error {
	unconsumed := e.unsearchedUnits()

	unitMsg := ""
	if len(unconsumed) > 0 {
		unitMsg = fmt.Sprintf("unit(s) required but not supported: %v", unconsumed)
	}

	unconsumed = e.unsearchedProcesses()

	procsMsg := ""
	if len(unconsumed) > 0 {
		procsMsg = fmt.Sprintf("process(es) required but not supported: %v", unconsumed)
	}

	join := ""
	if unitMsg != "" && procsMsg != "" {
		join = "; "
	}

	if unitMsg != "" || procsMsg != "" {
		return fmt.Errorf("%s%s%s", unitMsg, join, procsMsg)
	}

	return nil
}

// DetectOptions contains parameters for the Detect function.
type DetectOptions struct {
	// slice of unit names that we want to force-detect
	ForcedUnits []string
	// slice of process names that we want to force-detect
	ForcedProcesses []string
	ForcedOS        ExprOS
	SkipServices    []string
	SnubSystemd     bool
}

