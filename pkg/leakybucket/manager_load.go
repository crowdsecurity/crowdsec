package leakybucket

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/goombaio/namegenerator"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	yaml "gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/alertcontext"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion/constraint"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// BucketFactory struct holds all fields for any bucket configuration. This is to have a
// generic struct for buckets. This can be seen as a bucket factory.
type BucketFactory struct {
	FormatVersion       string                 `yaml:"format"`
	Author              string                 `yaml:"author"`
	Description         string                 `yaml:"description"`
	References          []string               `yaml:"references"`
	Type                string                 `yaml:"type"`                // Type can be : leaky, counter, trigger. It determines the main bucket characteristics
	Name                string                 `yaml:"name"`                // Name of the bucket, used later in log and user-messages. Should be unique
	Capacity            int                    `yaml:"capacity"`            // Capacity is applicable to leaky buckets and determines the "burst" capacity
	LeakSpeed           string                 `yaml:"leakspeed"`           // Leakspeed is a float representing how many events per second leak out of the bucket
	Duration            string                 `yaml:"duration"`            // Duration allows 'counter' buckets to have a fixed life-time
	Filter              string                 `yaml:"filter"`              // Filter is an expr that determines if an event is elligible for said bucket. Filter is evaluated against the Event struct
	GroupBy             string                 `yaml:"groupby,omitempty"`   // groupy is an expr that allows to determine the partitions of the bucket. A common example is the source_ip
	Distinct            string                 `yaml:"distinct"`            // Distinct, when present, adds a `Pour()` processor that will only pour uniq items (based on distinct expr result)
	Debug               bool                   `yaml:"debug"`               // Debug, when set to true, will enable debugging for _this_ scenario specifically
	Labels              map[string]interface{} `yaml:"labels"`              // Labels is K:V list aiming at providing context the overflow
	Blackhole           string                 `yaml:"blackhole,omitempty"` // Blackhole is a duration that, if present, will prevent same bucket partition to overflow more often than $duration
	logger              *log.Entry             // logger is bucket-specific logger (used by Debug as well)
	Reprocess           bool                   `yaml:"reprocess"`       // Reprocess, if true, will for the bucket to be re-injected into processing chain
	CacheSize           int                    `yaml:"cache_size"`      // CacheSize, if > 0, limits the size of in-memory cache of the bucket
	Profiling           bool                   `yaml:"profiling"`       // Profiling, if true, will make the bucket record pours/overflows/etc.
	OverflowFilter      string                 `yaml:"overflow_filter"` // OverflowFilter if present, is a filter that must return true for the overflow to go through
	ConditionalOverflow string                 `yaml:"condition"`       // condition if present, is an expression that must return true for the bucket to overflow
	BayesianPrior       float32                `yaml:"bayesian_prior"`
	BayesianThreshold   float32                `yaml:"bayesian_threshold"`
	BayesianConditions  []RawBayesianCondition `yaml:"bayesian_conditions"` // conditions for the bayesian bucket
	ScopeType           types.ScopeType        `yaml:"scope,omitempty"`     // to enforce a different remediation than blocking an IP. Will default this to IP
	BucketName          string                 `yaml:"-"`
	Filename            string                 `yaml:"-"`
	RunTimeFilter       *vm.Program            `json:"-"`
	RunTimeGroupBy      *vm.Program            `json:"-"`
	Data                []*types.DataSource    `yaml:"data,omitempty"`
	DataDir             string                 `yaml:"-"`
	CancelOnFilter      string                 `yaml:"cancel_on,omitempty"` // a filter that, if matched, kills the bucket
	leakspeed           time.Duration          // internal representation of `Leakspeed`
	duration            time.Duration          // internal representation of `Duration`
	ret                 chan types.Event       // the bucket-specific output chan for overflows
	processors          []Processor            // processors is the list of hooks for pour/overflow/create (cf. uniq, blackhole etc.)
	output              bool                   // ??
	ScenarioVersion     string                 `yaml:"version,omitempty"`
	hash                string
	Simulated           bool `yaml:"simulated"` // Set to true if the scenario instantiating the bucket was in the exclusion list
	tomb                *tomb.Tomb
	wgPour              *sync.WaitGroup
	wgDumpState         *sync.WaitGroup
	orderEvent          bool
}

// we use one NameGenerator for all the future buckets
var seed = namegenerator.NewNameGenerator(time.Now().UTC().UnixNano())

func validateLeakyType(bucketFactory *BucketFactory) error {
	if bucketFactory.Capacity <= 0 { // capacity must be a positive int
		return fmt.Errorf("bad capacity for leaky '%d'", bucketFactory.Capacity)
	}

	if bucketFactory.LeakSpeed == "" {
		return errors.New("leakspeed can't be empty for leaky")
	}

	if bucketFactory.leakspeed == 0 {
		return fmt.Errorf("bad leakspeed for leaky '%s'", bucketFactory.LeakSpeed)
	}

	return nil
}

func validateCounterType(bucketFactory *BucketFactory) error {
	if bucketFactory.Duration == "" {
		return errors.New("duration can't be empty for counter")
	}

	if bucketFactory.duration == 0 {
		return fmt.Errorf("bad duration for counter bucket '%d'", bucketFactory.duration)
	}

	if bucketFactory.Capacity != -1 {
		return errors.New("counter bucket must have -1 capacity")
	}

	return nil
}

func validateTriggerType(bucketFactory *BucketFactory) error {
	if bucketFactory.Capacity != 0 {
		return errors.New("trigger bucket must have 0 capacity")
	}

	return nil
}

func validateConditionalType(bucketFactory *BucketFactory) error {
	if bucketFactory.ConditionalOverflow == "" {
		return errors.New("conditional bucket must have a condition")
	}

	if bucketFactory.Capacity != -1 {
		bucketFactory.logger.Warnf("Using a value different than -1 as capacity for conditional bucket, this may lead to unexpected overflows")
	}

	if bucketFactory.LeakSpeed == "" {
		return errors.New("leakspeed can't be empty for conditional bucket")
	}

	if bucketFactory.leakspeed == 0 {
		return fmt.Errorf("bad leakspeed for conditional bucket '%s'", bucketFactory.LeakSpeed)
	}

	return nil
}

func validateBayesianType(bucketFactory *BucketFactory) error {
	if bucketFactory.BayesianConditions == nil {
		return errors.New("bayesian bucket must have bayesian conditions")
	}

	if bucketFactory.BayesianPrior == 0 {
		return errors.New("bayesian bucket must have a valid, non-zero prior")
	}

	if bucketFactory.BayesianThreshold == 0 {
		return errors.New("bayesian bucket must have a valid, non-zero threshold")
	}

	if bucketFactory.BayesianPrior > 1 {
		return errors.New("bayesian bucket must have a valid, non-zero prior")
	}

	if bucketFactory.BayesianThreshold > 1 {
		return errors.New("bayesian bucket must have a valid, non-zero threshold")
	}

	if bucketFactory.Capacity != -1 {
		return errors.New("bayesian bucket must have capacity -1")
	}

	return nil
}

func ValidateFactory(bucketFactory *BucketFactory) error {
	if bucketFactory.Name == "" {
		return errors.New("bucket must have name")
	}

	if bucketFactory.Description == "" {
		return errors.New("description is mandatory")
	}

	switch bucketFactory.Type {
	case "leaky":
		if err := validateLeakyType(bucketFactory); err != nil {
			return err
		}
	case "counter":
		if err := validateCounterType(bucketFactory); err != nil {
			return err
		}
	case "trigger":
		if err := validateTriggerType(bucketFactory); err != nil {
			return err
		}
	case "conditional":
		if err := validateConditionalType(bucketFactory); err != nil {
			return err
		}
	case "bayesian":
		if err := validateBayesianType(bucketFactory); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown bucket type '%s'", bucketFactory.Type)
	}

	return compileScopeFilter(bucketFactory)
}

func compileScopeFilter(bucketFactory *BucketFactory) error {
	if bucketFactory.ScopeType.Scope == types.Undefined {
		bucketFactory.ScopeType.Scope = types.Ip
	}

	if bucketFactory.ScopeType.Scope == types.Ip {
		if bucketFactory.ScopeType.Filter != "" {
			return errors.New("filter is not allowed for IP scope")
		}

		return nil
	}

	if bucketFactory.ScopeType.Scope == types.Range && bucketFactory.ScopeType.Filter == "" {
		return nil
	}

	if bucketFactory.ScopeType.Filter == "" {
		return errors.New("filter is mandatory for non-IP, non-Range scope")
	}

	runTimeFilter, err := expr.Compile(bucketFactory.ScopeType.Filter, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
	if err != nil {
		return fmt.Errorf("error compiling the scope filter: %w", err)
	}

	bucketFactory.ScopeType.RunTimeFilter = runTimeFilter

	return nil
}

func loadBucketFactoriesFromFile(item *cwhub.Item, hub *cwhub.Hub, buckets *Buckets, tomb *tomb.Tomb, response chan types.Event, orderEvent bool, simulationConfig *csconfig.SimulationConfig) ([]BucketFactory, error) {
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
		bucketFactory := BucketFactory{}

		err = dec.Decode(&bucketFactory)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Errorf("Bad yaml in %s: %v", itemPath, err)
				return nil, fmt.Errorf("bad yaml in %s: %w", itemPath, err)
			}

			log.Tracef("End of yaml file")

			break
		}

		bucketFactory.DataDir = hub.GetDataDir()
		// check empty
		if bucketFactory.Name == "" {
			log.Errorf("Won't load nameless bucket")
			return nil, errors.New("nameless bucket")
		}
		// check compat
		if bucketFactory.FormatVersion == "" {
			log.Tracef("no version in %s : %s, assuming '1.0'", bucketFactory.Name, itemPath)
			bucketFactory.FormatVersion = "1.0"
		}

		ok, err := constraint.Satisfies(bucketFactory.FormatVersion, constraint.Scenario)
		if err != nil {
			return nil, fmt.Errorf("failed to check version: %w", err)
		}

		if !ok {
			log.Errorf("can't load %s : %s doesn't satisfy scenario format %s, skip", bucketFactory.Name, bucketFactory.FormatVersion, constraint.Scenario)
			continue
		}

		bucketFactory.Filename = filepath.Clean(itemPath)
		bucketFactory.BucketName = seed.Generate()
		bucketFactory.ret = response

		if simulationConfig != nil {
			bucketFactory.Simulated = simulationConfig.IsSimulated(bucketFactory.Name)
		}

		bucketFactory.ScenarioVersion = item.State.LocalVersion
		bucketFactory.hash = item.State.LocalHash

		bucketFactory.wgDumpState = buckets.wgDumpState
		bucketFactory.wgPour = buckets.wgPour

		err = LoadBucket(&bucketFactory, tomb)
		if err != nil {
			log.Errorf("Failed to load bucket %s: %v", bucketFactory.Name, err)
			return nil, fmt.Errorf("loading of %s failed: %w", bucketFactory.Name, err)
		}

		bucketFactory.orderEvent = orderEvent

		factories = append(factories, bucketFactory)
	}

	return factories, nil
}

func LoadBuckets(cscfg *csconfig.CrowdsecServiceCfg, hub *cwhub.Hub, scenarios []*cwhub.Item, tomb *tomb.Tomb, buckets *Buckets, orderEvent bool) ([]BucketFactory, chan types.Event, error) {
	allFactories := []BucketFactory{}
	response := make(chan types.Event, 1)

	for _, item := range scenarios {
		log.Debugf("Loading '%s'", item.State.LocalPath)

		factories, err := loadBucketFactoriesFromFile(item, hub, buckets, tomb, response, orderEvent, cscfg.SimulationConfig)
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

/* Init recursively process yaml files from a directory and loads them as BucketFactory */
func LoadBucket(bucketFactory *BucketFactory, tomb *tomb.Tomb) error {
	var err error

	if bucketFactory.Debug {
		clog := log.New()
		if err = types.ConfigureLogger(clog); err != nil {
			return fmt.Errorf("while creating bucket-specific logger: %w", err)
		}

		clog.SetLevel(log.DebugLevel)
		bucketFactory.logger = clog.WithFields(log.Fields{
			"cfg":  bucketFactory.BucketName,
			"name": bucketFactory.Name,
		})
	} else {
		/* else bind it to the default one (might find something more elegant here)*/
		bucketFactory.logger = log.WithFields(log.Fields{
			"cfg":  bucketFactory.BucketName,
			"name": bucketFactory.Name,
		})
	}

	if bucketFactory.LeakSpeed != "" {
		if bucketFactory.leakspeed, err = time.ParseDuration(bucketFactory.LeakSpeed); err != nil {
			return fmt.Errorf("bad leakspeed '%s' in %s: %w", bucketFactory.LeakSpeed, bucketFactory.Filename, err)
		}
	} else {
		bucketFactory.leakspeed = time.Duration(0)
	}

	if bucketFactory.Duration != "" {
		if bucketFactory.duration, err = time.ParseDuration(bucketFactory.Duration); err != nil {
			return fmt.Errorf("invalid Duration '%s' in %s: %w", bucketFactory.Duration, bucketFactory.Filename, err)
		}
	}

	if bucketFactory.Filter == "" {
		bucketFactory.logger.Warning("Bucket without filter, abort.")
		return errors.New("bucket without filter directive")
	}

	bucketFactory.RunTimeFilter, err = expr.Compile(bucketFactory.Filter, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
	if err != nil {
		return fmt.Errorf("invalid filter '%s' in %s: %w", bucketFactory.Filter, bucketFactory.Filename, err)
	}

	if bucketFactory.GroupBy != "" {
		bucketFactory.RunTimeGroupBy, err = expr.Compile(bucketFactory.GroupBy, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
		if err != nil {
			return fmt.Errorf("invalid groupby '%s' in %s: %w", bucketFactory.GroupBy, bucketFactory.Filename, err)
		}
	}

	bucketFactory.logger.Infof("Adding %s bucket", bucketFactory.Type)
	// return the Holder corresponding to the type of bucket
	bucketFactory.processors = []Processor{}
	switch bucketFactory.Type {
	case "leaky":
		bucketFactory.processors = append(bucketFactory.processors, &DumbProcessor{})
	case "trigger":
		bucketFactory.processors = append(bucketFactory.processors, &Trigger{})
	case "counter":
		bucketFactory.processors = append(bucketFactory.processors, &DumbProcessor{})
	case "conditional":
		bucketFactory.processors = append(bucketFactory.processors, &DumbProcessor{})
	case "bayesian":
		bucketFactory.processors = append(bucketFactory.processors, &DumbProcessor{})
	default:
		return fmt.Errorf("invalid type '%s' in %s: %w", bucketFactory.Type, bucketFactory.Filename, err)
	}

	if bucketFactory.Distinct != "" {
		bucketFactory.logger.Tracef("Adding a non duplicate filter")
		bucketFactory.processors = append(bucketFactory.processors, &Uniq{})
		// we're compiling and discarding the expression to be able to detect it during loading
		_, err = expr.Compile(bucketFactory.Distinct, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
		if err != nil {
			return fmt.Errorf("invalid distinct '%s' in %s: %w", bucketFactory.Distinct, bucketFactory.Filename, err)
		}
	}

	if bucketFactory.CancelOnFilter != "" {
		bucketFactory.logger.Tracef("Adding a cancel_on filter")
		bucketFactory.processors = append(bucketFactory.processors, &CancelOnFilter{})
		// we're compiling and discarding the expression to be able to detect it during loading
		_, err = expr.Compile(bucketFactory.CancelOnFilter, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
		if err != nil {
			return fmt.Errorf("invalid cancel_on '%s' in %s: %w", bucketFactory.CancelOnFilter, bucketFactory.Filename, err)
		}
	}

	if bucketFactory.OverflowFilter != "" {
		bucketFactory.logger.Tracef("Adding an overflow filter")

		filovflw, err := NewOverflowFilter(bucketFactory)
		if err != nil {
			bucketFactory.logger.Errorf("Error creating overflow_filter : %s", err)
			return fmt.Errorf("error creating overflow_filter: %w", err)
		}

		bucketFactory.processors = append(bucketFactory.processors, filovflw)
	}

	if bucketFactory.Blackhole != "" {
		bucketFactory.logger.Tracef("Adding blackhole.")

		blackhole, err := NewBlackhole(bucketFactory)
		if err != nil {
			bucketFactory.logger.Errorf("Error creating blackhole : %s", err)
			return fmt.Errorf("error creating blackhole : %w", err)
		}

		bucketFactory.processors = append(bucketFactory.processors, blackhole)
	}

	if bucketFactory.ConditionalOverflow != "" {
		bucketFactory.logger.Tracef("Adding conditional overflow")
		bucketFactory.processors = append(bucketFactory.processors, &ConditionalOverflow{})
		// we're compiling and discarding the expression to be able to detect it during loading
		_, err = expr.Compile(bucketFactory.ConditionalOverflow, exprhelpers.GetExprOptions(map[string]interface{}{"queue": &types.Queue{}, "leaky": &Leaky{}, "evt": &types.Event{}})...)
		if err != nil {
			return fmt.Errorf("invalid condition '%s' in %s: %w", bucketFactory.ConditionalOverflow, bucketFactory.Filename, err)
		}
	}

	if bucketFactory.BayesianThreshold != 0 {
		bucketFactory.logger.Tracef("Adding bayesian processor")
		bucketFactory.processors = append(bucketFactory.processors, &BayesianBucket{})
	}

	for _, data := range bucketFactory.Data {
		if data.DestPath == "" {
			bucketFactory.logger.Errorf("no dest_file provided for '%s'", bucketFactory.Name)
			continue
		}

		err = exprhelpers.FileInit(bucketFactory.DataDir, data.DestPath, data.Type)
		if err != nil {
			bucketFactory.logger.Errorf("unable to init data for file '%s': %s", data.DestPath, err)
		}

		if data.Type == "regexp" { // cache only makes sense for regexp
			if err := exprhelpers.RegexpCacheInit(data.DestPath, *data); err != nil {
				bucketFactory.logger.Error(err.Error())
			}
		}
	}

	bucketFactory.output = false
	if err := ValidateFactory(bucketFactory); err != nil {
		return fmt.Errorf("invalid bucket from %s: %w", bucketFactory.Filename, err)
	}

	bucketFactory.tomb = tomb

	return nil
}

func LoadBucketsState(file string, buckets *Buckets, bucketFactories []BucketFactory) error {
	var state map[string]Leaky

	body, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("can't read state file %s: %w", file, err)
	}

	if err := json.Unmarshal(body, &state); err != nil {
		return fmt.Errorf("can't parse state file %s: %w", file, err)
	}

	for k := range state {
		var tbucket *Leaky

		log.Debugf("Reloading bucket %s", k)

		val, ok := buckets.Bucket_map.Load(k)
		if ok {
			return fmt.Errorf("key %s already exists: %+v", k, val)
		}
		// find back our holder
		found := false

		for _, h := range bucketFactories {
			if h.Name != state[k].Name {
				continue
			}

			log.Debugf("found factory %s/%s -> %s", h.Author, h.Name, h.Description)
			// check in which mode the bucket was
			if state[k].Mode == types.TIMEMACHINE {
				tbucket = NewTimeMachine(h)
			} else if state[k].Mode == types.LIVE {
				tbucket = NewLeaky(h)
			} else {
				log.Errorf("Unknown bucket type : %d", state[k].Mode)
			}
			/*Trying to restore queue state*/
			tbucket.Queue = state[k].Queue
			/*Trying to set the limiter to the saved values*/
			tbucket.Limiter.Load(state[k].SerializedState)
			tbucket.In = make(chan *types.Event)
			tbucket.Mapkey = k
			tbucket.Signal = make(chan bool, 1)
			tbucket.First_ts = state[k].First_ts
			tbucket.Last_ts = state[k].Last_ts
			tbucket.Ovflw_ts = state[k].Ovflw_ts
			tbucket.Total_count = state[k].Total_count
			buckets.Bucket_map.Store(k, tbucket)
			h.tomb.Go(func() error {
				return LeakRoutine(tbucket)
			})
			<-tbucket.Signal

			found = true

			break
		}

		if !found {
			return fmt.Errorf("unable to find holder for bucket %s: %s", k, spew.Sdump(state[k]))
		}
	}

	log.Infof("Restored %d buckets from dump", len(state))

	return nil
}
