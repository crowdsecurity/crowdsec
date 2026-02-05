package leakybucket

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/expr-lang/expr/vm"
	"github.com/goombaio/namegenerator"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/alertcontext"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion/constraint"
	"github.com/crowdsecurity/crowdsec/pkg/enrichment"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/logging"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type BucketSpec struct {
	FormatVersion       string                     `yaml:"format"`
	Description         string                     `yaml:"description"`
	References          []string                   `yaml:"references"`
	Type                string                     `yaml:"type"`                // Type can be : leaky, counter, trigger. It determines the main bucket characteristics
	Name                string                     `yaml:"name"`                // Name of the bucket, used later in log and user-messages. Should be unique
	Capacity            int                        `yaml:"capacity"`            // Capacity is applicable to leaky buckets and determines the "burst" capacity
	LeakSpeed           string                     `yaml:"leakspeed"`           // Leakspeed is a float representing how many events per second leak out of the bucket
	Filter              string                     `yaml:"filter"`              // Filter is an expr that determines if an event is elligible for said bucket. Filter is evaluated against the Event struct
	GroupBy             string                     `yaml:"groupby,omitempty"`   // groupy is an expr that allows to determine the partitions of the bucket. A common example is the source_ip
	Distinct            string                     `yaml:"distinct"`            // Distinct, when present, adds a `Pour()` processor that will only pour uniq items (based on distinct expr result)
	Debug               bool                       `yaml:"debug"`               // Debug, when set to true, will enable debugging for _this_ scenario specifically
	Labels              map[string]any             `yaml:"labels"`              // Labels is K:V list aiming at providing context the overflow
	Blackhole           string                     `yaml:"blackhole,omitempty"` // Blackhole is a duration that, if present, will prevent same bucket partition to overflow more often than $duration
	ScopeType           ScopeType                  `yaml:"scope,omitempty"`     // to enforce a different remediation than blocking an IP. Will default this to IP
	Reprocess           bool                       `yaml:"reprocess"`       // Reprocess, if true, will for the bucket to be re-injected into processing chain
	Data                []*enrichment.DataProvider `yaml:"data,omitempty"`
	ConditionalOverflow string                     `yaml:"condition"`       // condition if present, is an expression that must return true for the bucket to overflow
	CacheSize           int                        `yaml:"cache_size"`      // CacheSize, if > 0, limits the size of in-memory cache of the bucket
	CancelOnFilter      string                     `yaml:"cancel_on,omitempty"` // a filter that, if matched, kills the bucket
	BayesianPrior       float32                    `yaml:"bayesian_prior"`
	BayesianThreshold   float32                    `yaml:"bayesian_threshold"`
	BayesianConditions  []RawBayesianCondition     `yaml:"bayesian_conditions"` // conditions for the bayesian bucket
	OverflowFilter      string                     `yaml:"overflow_filter"` // OverflowFilter if present, is a filter that must return true for the overflow to go through
	Duration            string                     `yaml:"duration"`            // Duration allows 'counter' buckets to have a fixed life-time
	ScenarioVersion     string                     `yaml:"version,omitempty"`
}

// BucketFactory struct holds all fields for any bucket configuration. This is to have a
// generic struct for buckets. This can be seen as a bucket factory.
type BucketFactory struct {
	Spec BucketSpec

	logger              *log.Entry          // logger is bucket-specific logger (used by Debug as well)
	BucketName          string
	Filename            string
	RunTimeFilter       *vm.Program         `json:"-"`
	RunTimeGroupBy      *vm.Program         `json:"-"`
	DataDir             string
	leakspeed           time.Duration       // internal representation of `Leakspeed`
	duration            time.Duration       // internal representation of `Duration`
	ret                 chan pipeline.Event // the bucket-specific output chan for overflows
	processors          []Processor         // processors is the list of hooks for pour/overflow/create (cf. uniq, blackhole etc.)
	hash                string
	Simulated           bool                // Set to true if the scenario instantiating the bucket was in the exclusion list
	orderEvent          bool
}

// we use one NameGenerator for all the future buckets
var seed = namegenerator.NewNameGenerator(time.Now().UTC().UnixNano())

func (f *BucketFactory) Validate() error {
	if f.Spec.Name == "" {
		return errors.New("bucket must have name")
	}

	if f.Spec.Description == "" {
		return errors.New("description is mandatory")
	}

	impl, ok := bucketTypes[f.Spec.Type]
	if !ok {
		return fmt.Errorf("unknown bucket type '%s'", f.Spec.Type)
	}

	if err := impl.Validate(f); err != nil {
		return fmt.Errorf("%s bucket: %w", f.Spec.Type, err)
	}

	return f.Spec.ScopeType.CompileFilter()
}

type SimulationChecker interface {
	IsSimulated(scenario string) bool
}

func loadBucketFactoriesFromFile(
	item *cwhub.Item,
	hub *cwhub.Hub,
	response chan pipeline.Event,
	orderEvent bool,
	simcheck SimulationChecker,
) ([]BucketFactory, error) {
	itemPath := item.State.LocalPath

	// process the yaml
	bucketConfigurationFile, err := os.Open(itemPath)
	if err != nil {
		log.Errorf("Can't access leaky configuration file %s", itemPath)
		return nil, err
	}

	defer bucketConfigurationFile.Close()
	dec := yaml.NewDecoder(bucketConfigurationFile)
	dec.SetStrict(true)

	factories := []BucketFactory{}

	for {
		f := BucketFactory{}

		err = dec.Decode(&f.Spec)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Errorf("Bad yaml in %s: %v", itemPath, err)
				return nil, fmt.Errorf("bad yaml in %s: %w", itemPath, err)
			}

			log.Tracef("End of yaml file")

			break
		}

		f.DataDir = hub.GetDataDir()
		// check empty
		if f.Spec.Name == "" {
			log.Errorf("Won't load nameless bucket")
			return nil, errors.New("nameless bucket")
		}
		// check compat
		if f.Spec.FormatVersion == "" {
			log.Tracef("no version in %s : %s, assuming '1.0'", f.Spec.Name, itemPath)
			f.Spec.FormatVersion = "1.0"
		}

		ok, err := constraint.Satisfies(f.Spec.FormatVersion, constraint.Scenario)
		if err != nil {
			return nil, fmt.Errorf("failed to check version: %w", err)
		}

		if !ok {
			log.Errorf("can't load %s : %s doesn't satisfy scenario format %s, skip", f.Spec.Name, f.Spec.FormatVersion, constraint.Scenario)
			continue
		}

		f.Filename = filepath.Clean(itemPath)
		f.BucketName = seed.Generate()
		f.ret = response
		f.Simulated = simcheck.IsSimulated(f.Spec.Name)

		f.Spec.ScenarioVersion = item.State.LocalVersion
		f.hash = item.State.LocalHash

		err = f.LoadBucket()
		if err != nil {
			return nil, fmt.Errorf("bucket %s: %w", f.Spec.Name, err)
		}

		f.orderEvent = orderEvent

		factories = append(factories, f)
	}

	return factories, nil
}

func LoadBuckets(
	cscfg *csconfig.CrowdsecServiceCfg,
	hub *cwhub.Hub,
	scenarios []*cwhub.Item,
	orderEvent bool,
) ([]BucketFactory, chan pipeline.Event, error) {
	allFactories := []BucketFactory{}
	response := make(chan pipeline.Event, 1)

	for _, item := range scenarios {
		log.Debugf("Loading '%s'", item.State.LocalPath)

		factories, err := loadBucketFactoriesFromFile(item, hub, response, orderEvent, &cscfg.SimulationConfig)
		if err != nil {
			return nil, nil, err
		}

		allFactories = append(allFactories, factories...)
	}

	if err := alertcontext.NewAlertContext(cscfg.ContextToSend, cscfg.ConsoleContextValueLength); err != nil {
		return nil, nil, fmt.Errorf("unable to load alert context: %w", err)
	}

	log.Infof("Loaded %d scenarios", len(allFactories))

	return allFactories, response, nil
}

func bucketLogger(f *BucketFactory) *log.Entry {
	fields := log.Fields{"cfg": f.BucketName, "name": f.Spec.Name}

	if f.Spec.Debug {
		logger := logging.SubLogger(log.StandardLogger(), "scenario", log.DebugLevel)
		return logger.WithFields(fields)
	}

	return log.WithFields(fields)
}

func (f *BucketFactory) parseDurations() error {
	if f.Spec.LeakSpeed != "" {
		leakspeed, err := time.ParseDuration(f.Spec.LeakSpeed)
		if err != nil {
			return fmt.Errorf("invalid leakspeed '%s' in %s: %w", f.Spec.LeakSpeed, f.Filename, err)
		}
		f.leakspeed = leakspeed
	}

	if f.Spec.Duration != "" {
		duration, err := time.ParseDuration(f.Spec.Duration)
		if err != nil {
			return fmt.Errorf("invalid duration '%s' in %s: %w", f.Spec.Duration, f.Filename, err)
		}
		f.duration = duration
	}

	return nil
}

func (f *BucketFactory) compileExpr() error {
	if f.Spec.Filter == "" {
		f.logger.Warning("Bucket without filter, abort.")
		return errors.New("missing filter directive")
	}

	runtimeFilter, err := compile(f.Spec.Filter, nil)
	if err != nil {
		return fmt.Errorf("invalid filter '%s' in %s: %w", f.Spec.Filter, f.Filename, err)
	}
	f.RunTimeFilter = runtimeFilter

	if f.Spec.GroupBy != "" {
		runtimeGroupBy, err := compile(f.Spec.GroupBy, nil)
		if err != nil {
			return fmt.Errorf("invalid groupby '%s' in %s: %w", f.Spec.GroupBy, f.Filename, err)
		}
		f.RunTimeGroupBy = runtimeGroupBy
	}

	return nil
}

func (f *BucketFactory) buildOptionalProcessors() ([]Processor, error) {
	// Some optional processors depend on expressions. We compile those expressions here
	// during loading (and discard the compiled program) so misconfigurations fail fast.
	check := func(bucketType, ex string, extra map[string]any) error {
		if _, err := compile(ex, extra); err != nil {
			return fmt.Errorf("invalid %s '%s' in %s: %w", bucketType, ex, f.Filename, err)
		}
		return nil
	}

	var procs []Processor

	if f.Spec.Distinct != "" {
		f.logger.Tracef("Adding a non duplicate filter")
		procs = append(procs, &UniqProcessor{})
		if err := check("distinct", f.Spec.Distinct, nil); err != nil {
			return nil, err
		}
	}

	if f.Spec.CancelOnFilter != "" {
		f.logger.Tracef("Adding a cancel_on filter")
		procs = append(procs, &CancelProcessor{})
		if err := check("cancel_on", f.Spec.CancelOnFilter, nil); err != nil {
			return nil, err
		}
	}

	if f.Spec.OverflowFilter != "" {
		f.logger.Tracef("Adding an overflow filter")

		filovflw, err := NewOverflowProcessor(f)
		if err != nil {
			f.logger.Errorf("Error creating overflow_filter : %s", err)
			return nil, fmt.Errorf("error creating overflow_filter: %w", err)
		}

		procs = append(procs, filovflw)
	}

	if f.Spec.Blackhole != "" {
		f.logger.Tracef("Adding blackhole.")

		blackhole, err := NewBlackholeProcessor(f)
		if err != nil {
			f.logger.Errorf("Error creating blackhole : %s", err)
			return nil, fmt.Errorf("error creating blackhole : %w", err)
		}

		procs = append(procs, blackhole)
	}

	if f.Spec.ConditionalOverflow != "" {
		f.logger.Tracef("Adding conditional overflow")
		procs = append(procs, &ConditionalProcessor{})
		if err := check("condition", f.Spec.ConditionalOverflow, map[string]any{"queue": &pipeline.Queue{}, "leaky": &Leaky{}}); err != nil {
			return nil, err
		}
	}

	if f.Spec.BayesianThreshold != 0 {
		f.logger.Tracef("Adding bayesian processor")
		procs = append(procs, &BayesianProcessor{})
	}

	return procs, nil
}

func (f *BucketFactory) initDataFiles() {
	for _, data := range f.Spec.Data {
		if data.DestPath == "" {
			f.logger.Errorf("no dest_file provided for '%s'", f.Spec.Name)
			continue
		}

		if err := exprhelpers.FileInit(f.DataDir, data.DestPath, data.Type); err != nil {
			f.logger.Errorf("unable to init data for file '%s': %s", data.DestPath, err)
		}

		if data.Type == "regexp" { // cache only makes sense for regexp
			if err := exprhelpers.RegexpCacheInit(data.DestPath, *data); err != nil {
				f.logger.Error(err.Error())
			}
		}
	}
}

// LoadBucket validates and prepares a BucketFactory for runtime use (compile expressions, init processors, init data).
func (f *BucketFactory) LoadBucket() error {
	var err error

	f.logger = bucketLogger(f)
	f.logger.Infof("Adding %s bucket", f.Spec.Type)

	if err := f.parseDurations(); err != nil {
		return err
	}

	if err := f.compileExpr(); err != nil {
		return err
	}

	impl, ok := bucketTypes[f.Spec.Type]
	if !ok {
		return fmt.Errorf("invalid type '%s' in %s", f.Spec.Type, f.Filename)
	}

	procs := impl.BuildProcessors(f)

	optProcs, err := f.buildOptionalProcessors()
	if err != nil {
		return err
	}

	procs = append(procs, optProcs...)
	f.processors = procs

	f.initDataFiles()

	if err := f.Validate(); err != nil {
		return fmt.Errorf("invalid bucket from %s: %w", f.Filename, err)
	}

	return nil
}

func (f *BucketFactory) BucketKey(stackkey string) string {
	h := sha1.New()
	h.Write([]byte(f.Spec.Filter))
	// use zero byte separators to avoid conflicts, i.e. "ab"+"c" vs "a"+"bc"
	h.Write([]byte{0})
	h.Write([]byte(stackkey))
	h.Write([]byte{0})
	h.Write([]byte(f.Spec.Name))
	return hex.EncodeToString(h.Sum(nil))
}
