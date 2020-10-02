package leakybucket

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/types"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/goombaio/namegenerator"
	yaml "gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

// BucketFactory struct holds all fields for any bucket configuration. This is to have a
// generic struct for buckets. This can be seen as a bucket factory.
type BucketFactory struct {
	FormatVersion   string                    `yaml:"format"`
	Author          string                    `yaml:"author"`
	Description     string                    `yaml:"description"`
	References      []string                  `yaml:"references"`
	Type            string                    `yaml:"type"`                //Type can be : leaky, counter, trigger. It determines the main bucket characteristics
	Name            string                    `yaml:"name"`                //Name of the bucket, used later in log and user-messages. Should be unique
	Capacity        int                       `yaml:"capacity"`            //Capacity is applicable to leaky buckets and determines the "burst" capacity
	LeakSpeed       string                    `yaml:"leakspeed"`           //Leakspeed is a float representing how many events per second leak out of the bucket
	Duration        string                    `yaml:"duration"`            //Duration allows 'counter' buckets to have a fixed life-time
	Filter          string                    `yaml:"filter"`              //Filter is an expr that determines if an event is elligible for said bucket. Filter is evaluated against the Event struct
	GroupBy         string                    `yaml:"groupby,omitempty"`   //groupy is an expr that allows to determine the partitions of the bucket. A common example is the source_ip
	Distinct        string                    `yaml:"distinct"`            //Distinct, when present, adds a `Pour()` processor that will only pour uniq items (based on distinct expr result)
	Debug           bool                      `yaml:"debug"`               //Debug, when set to true, will enable debugging for _this_ scenario specifically
	Labels          map[string]string         `yaml:"labels"`              //Labels is K:V list aiming at providing context the overflow
	Blackhole       string                    `yaml:"blackhole,omitempty"` //Blackhole is a duration that, if present, will prevent same bucket partition to overflow more often than $duration
	logger          *log.Entry                `yaml:"-"`                   //logger is bucket-specific logger (used by Debug as well)
	Reprocess       bool                      `yaml:"reprocess"`           //Reprocess, if true, will for the bucket to be re-injected into processing chain
	CacheSize       int                       `yaml:"cache_size"`          //CacheSize, if > 0, limits the size of in-memory cache of the bucket
	Profiling       bool                      `yaml:"profiling"`           //Profiling, if true, will make the bucket record pours/overflows/etc.
	OverflowFilter  string                    `yaml:"overflow_filter"`     //OverflowFilter if present, is a filter that must return true for the overflow to go through
	ScopeType       types.ScopeType           `yaml:"scope,omitempty"`     //to enforce a different remediation than blocking an IP. Will default this to IP
	BucketName      string                    `yaml:"-"`
	Filename        string                    `yaml:"-"`
	RunTimeFilter   *vm.Program               `json:"-"`
	ExprDebugger    *exprhelpers.ExprDebugger `yaml:"-" json:"-"` // used to debug expression by printing the content of each variable of the expression
	RunTimeGroupBy  *vm.Program               `json:"-"`
	Data            []*types.DataSource       `yaml:"data,omitempty"`
	DataDir         string                    `yaml:"-"`
	leakspeed       time.Duration             //internal representation of `Leakspeed`
	duration        time.Duration             //internal representation of `Duration`
	ret             chan types.Event          //the bucket-specific output chan for overflows
	processors      []Processor               //processors is the list of hooks for pour/overflow/create (cf. uniq, blackhole etc.)
	output          bool                      //??
	ScenarioVersion string                    `yaml:"version,omitempty"`
	hash            string                    `yaml:"-"`
}

func ValidateFactory(bucketFactory *BucketFactory) error {
	if bucketFactory.Name == "" {
		return fmt.Errorf("bucket must have name")
	}
	if bucketFactory.Description == "" {
		return fmt.Errorf("description is mandatory")
	}
	if bucketFactory.Type == "leaky" {
		if bucketFactory.Capacity <= 0 { //capacity must be a positive int
			return fmt.Errorf("bad capacity for leaky '%d'", bucketFactory.Capacity)
		}
		if bucketFactory.LeakSpeed == "" {
			return fmt.Errorf("leakspeed can't be empty for leaky")
		}
		if bucketFactory.leakspeed == 0 {
			return fmt.Errorf("bad leakspeed for leaky '%s'", bucketFactory.LeakSpeed)
		}
	} else if bucketFactory.Type == "counter" {
		if bucketFactory.Duration == "" {
			return fmt.Errorf("duration ca't be empty for counter")
		}
		if bucketFactory.duration == 0 {
			return fmt.Errorf("bad duration for counter bucket '%d'", bucketFactory.duration)
		}
		if bucketFactory.Capacity != -1 {
			return fmt.Errorf("counter bucket must have -1 capacity")
		}
	} else if bucketFactory.Type == "trigger" {
		if bucketFactory.Capacity != 0 {
			return fmt.Errorf("trigger bucket must have 0 capacity")
		}
	} else {
		return fmt.Errorf("unknown bucket type '%s'", bucketFactory.Type)
	}

	switch bucketFactory.ScopeType.Scope {
	case types.Undefined:
		bucketFactory.ScopeType.Scope = types.Ip
	case types.Ip:
	case types.Range:
	default:
		//Compile the scope filter
		var (
			runTimeFilter *vm.Program
			err           error
		)
		if runTimeFilter, err = expr.Compile(bucketFactory.ScopeType.Filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}}))); err != nil {
			return fmt.Errorf("Error compiling the scope filter: %s", err)
		}
		bucketFactory.ScopeType.RunTimeFilter = runTimeFilter
	}
	return nil
}

func LoadBuckets(cscfg *csconfig.CrowdsecServiceCfg, files []string) ([]BucketFactory, chan types.Event, error) {
	var (
		ret      []BucketFactory = []BucketFactory{}
		response chan types.Event
	)

	var seed namegenerator.Generator = namegenerator.NewNameGenerator(time.Now().UTC().UnixNano())

	response = make(chan types.Event, 1)
	for _, f := range files {
		log.Debugf("Loading '%s'", f)
		if !strings.HasSuffix(f, ".yaml") {
			log.Debugf("Skipping %s : not a yaml file", f)
			continue
		}

		//process the yaml
		bucketConfigurationFile, err := os.Open(f)
		if err != nil {
			log.Errorf("Can't access leaky configuration file %s", f)
			return nil, nil, err
		}
		dec := yaml.NewDecoder(bucketConfigurationFile)
		dec.SetStrict(true)
		for {
			bucketFactory := BucketFactory{}
			err = dec.Decode(&bucketFactory)
			if err != nil {
				if err == io.EOF {
					log.Tracef("End of yaml file")
					break
				} else {
					log.Errorf("Bad yaml in %s : %v", f, err)
					return nil, nil, fmt.Errorf("bad yaml in %s : %v", f, err)
				}
			}
			bucketFactory.DataDir = cscfg.DataDir
			//check empty
			if bucketFactory.Name == "" {
				log.Errorf("Won't load nameless bucket")
				return nil, nil, fmt.Errorf("nameless bucket")
			}
			//check compat
			if bucketFactory.FormatVersion == "" {
				log.Tracef("no version in %s : %s, assuming '1.0'", bucketFactory.Name, f)
				bucketFactory.FormatVersion = "1.0"
			}
			ok, err := cwversion.Statisfies(bucketFactory.FormatVersion, cwversion.Constraint_scenario)
			if err != nil {
				log.Fatalf("Failed to check version : %s", err)
			}
			if !ok {
				log.Errorf("can't load %s : %s doesn't satisfy scenario format %s, skip", bucketFactory.Name, bucketFactory.FormatVersion, cwversion.Constraint_scenario)
				continue
			}

			bucketFactory.Filename = filepath.Clean(f)
			bucketFactory.BucketName = seed.Generate()
			bucketFactory.ret = response
			hubItem, err := cwhub.GetItemByPath(cwhub.SCENARIOS, bucketFactory.Filename)
			if err != nil {
				log.Errorf("scenario %s (%s) couldn't be find in hub (ignore if in unit tests)", bucketFactory.Name, bucketFactory.Filename)
			} else {
				if hubItem != nil {
					bucketFactory.ScenarioVersion = hubItem.LocalVersion
					bucketFactory.hash = hubItem.LocalHash
				} else {
					log.Errorf("scenario %s (%s) couldn't be find in hub (ignore if in unit tests)", bucketFactory.Name, bucketFactory.Filename)
				}
			}

			err = LoadBucket(&bucketFactory)
			if err != nil {
				log.Errorf("Failed to load bucket %s : %v", bucketFactory.Name, err)
				return nil, nil, fmt.Errorf("loading of %s failed : %v", bucketFactory.Name, err)
			}
			ret = append(ret, bucketFactory)
		}
	}
	log.Warningf("Loaded %d scenarios", len(ret))
	return ret, response, nil
}

/* Init recursively process yaml files from a directory and loads them as BucketFactory */
func LoadBucket(bucketFactory *BucketFactory) error {
	var err error
	if bucketFactory.Debug {
		var clog = logrus.New()
		if err := types.ConfigureLogger(clog); err != nil {
			log.Fatalf("While creating bucket-specific logger : %s", err)
		}
		clog.SetLevel(log.DebugLevel)
		bucketFactory.logger = clog.WithFields(log.Fields{
			"cfg":  bucketFactory.BucketName,
			"name": bucketFactory.Name,
			"file": bucketFactory.Filename,
		})
	} else {
		/* else bind it to the default one (might find something more elegant here)*/
		bucketFactory.logger = log.WithFields(log.Fields{
			"cfg":  bucketFactory.BucketName,
			"name": bucketFactory.Name,
			"file": bucketFactory.Filename,
		})
	}

	if bucketFactory.LeakSpeed != "" {
		if bucketFactory.leakspeed, err = time.ParseDuration(bucketFactory.LeakSpeed); err != nil {
			return fmt.Errorf("bad leakspeed '%s' in %s : %v", bucketFactory.LeakSpeed, bucketFactory.Filename, err)
		}
	} else {
		bucketFactory.leakspeed = time.Duration(0)
	}
	if bucketFactory.Duration != "" {
		if bucketFactory.duration, err = time.ParseDuration(bucketFactory.Duration); err != nil {
			return fmt.Errorf("invalid Duration '%s' in %s : %v", bucketFactory.Duration, bucketFactory.Filename, err)
		}
	}

	if bucketFactory.Filter == "" {
		bucketFactory.logger.Warningf("Bucket without filter, abort.")
		return fmt.Errorf("bucket without filter directive")
	}
	bucketFactory.RunTimeFilter, err = expr.Compile(bucketFactory.Filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
	if err != nil {
		return fmt.Errorf("invalid filter '%s' in %s : %v", bucketFactory.Filter, bucketFactory.Filename, err)
	}
	if bucketFactory.Debug {
		bucketFactory.ExprDebugger, err = exprhelpers.NewDebugger(bucketFactory.Filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
		if err != nil {
			log.Errorf("unable to build debug filter for '%s' : %s", bucketFactory.Filter, err)
		}
	}

	if bucketFactory.GroupBy != "" {
		bucketFactory.RunTimeGroupBy, err = expr.Compile(bucketFactory.GroupBy, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
		if err != nil {
			return fmt.Errorf("invalid groupby '%s' in %s : %v", bucketFactory.GroupBy, bucketFactory.Filename, err)
		}
	}

	bucketFactory.logger.Infof("Adding %s bucket", bucketFactory.Type)
	//return the Holder correponding to the type of bucket
	bucketFactory.processors = []Processor{}
	switch bucketFactory.Type {
	case "leaky":
		bucketFactory.processors = append(bucketFactory.processors, &DumbProcessor{})
	case "trigger":
		bucketFactory.processors = append(bucketFactory.processors, &Trigger{})
	case "counter":
		bucketFactory.processors = append(bucketFactory.processors, &DumbProcessor{})
	default:
		return fmt.Errorf("invalid type '%s' in %s : %v", bucketFactory.Type, bucketFactory.Filename, err)
	}

	if bucketFactory.Distinct != "" {
		bucketFactory.logger.Tracef("Adding a non duplicate filter on %s.", bucketFactory.Name)
		bucketFactory.processors = append(bucketFactory.processors, &Uniq{})
	}

	if bucketFactory.OverflowFilter != "" {
		bucketFactory.logger.Tracef("Adding an overflow filter")
		filovflw, err := NewOverflowFilter(bucketFactory)
		if err != nil {
			bucketFactory.logger.Errorf("Error creating overflow_filter : %s", err)
			return fmt.Errorf("error creating overflow_filter : %s", err)
		}
		bucketFactory.processors = append(bucketFactory.processors, filovflw)
	}

	if bucketFactory.Blackhole != "" {
		bucketFactory.logger.Tracef("Adding blackhole.")
		blackhole, err := NewBlackhole(bucketFactory)
		if err != nil {
			bucketFactory.logger.Errorf("Error creating blackhole : %s", err)
			return fmt.Errorf("error creating blackhole : %s", err)
		}
		bucketFactory.processors = append(bucketFactory.processors, blackhole)
	}

	if len(bucketFactory.Data) > 0 {
		for _, data := range bucketFactory.Data {
			if data.DestPath == "" {
				bucketFactory.logger.Errorf("no dest_file provided for '%s'", bucketFactory.Name)
				continue
			}
			err = exprhelpers.FileInit(bucketFactory.DataDir, data.DestPath, data.Type)
			if err != nil {
				bucketFactory.logger.Errorf("unable to init data for file '%s': %s", data.DestPath, err.Error())
			}
		}
	}

	bucketFactory.output = false
	if err := ValidateFactory(bucketFactory); err != nil {
		return fmt.Errorf("invalid bucket from %s : %v", bucketFactory.Filename, err)
	}
	return nil

}

func LoadBucketsState(file string, buckets *Buckets, bucketFactories []BucketFactory) error {
	var state map[string]Leaky
	body, err := ioutil.ReadFile(file)
	if err != nil {
		return fmt.Errorf("can't state file %s : %s", file, err)
	}
	if err := json.Unmarshal(body, &state); err != nil {
		return fmt.Errorf("can't unmarshal state file %s : %s", file, err)
	}
	for k, v := range state {
		var tbucket *Leaky
		log.Debugf("Reloading bucket %s", k)
		val, ok := buckets.Bucket_map.Load(k)
		if ok {
			log.Fatalf("key %s already exists : %+v", k, val)
		}
		//find back our holder
		found := false
		for _, h := range bucketFactories {
			if h.Name == v.Name {
				log.Debugf("found factory %s/%s -> %s", h.Author, h.Name, h.Description)
				//check in which mode the bucket was
				if v.Mode == TIMEMACHINE {
					tbucket = NewTimeMachine(h)
				} else if v.Mode == LIVE {
					tbucket = NewLeaky(h)
				} else {
					log.Errorf("Unknown bucket type : %d", v.Mode)
				}
				/*Trying to restore queue state*/
				tbucket.Queue = v.Queue
				/*Trying to set the limiter to the saved values*/
				tbucket.Limiter.Load(v.SerializedState)
				tbucket.In = make(chan types.Event)
				tbucket.Mapkey = k
				tbucket.Signal = make(chan bool, 1)
				tbucket.KillSwitch = make(chan bool, 1)
				tbucket.First_ts = v.First_ts
				tbucket.Last_ts = v.Last_ts
				tbucket.Ovflw_ts = v.Ovflw_ts
				tbucket.Total_count = v.Total_count
				buckets.Bucket_map.Store(k, tbucket)
				go LeakRoutine(tbucket)
				<-tbucket.Signal
				found = true
				break
			}
		}
		if !found {
			log.Fatalf("Unable to find holder for bucket %s : %s", k, spew.Sdump(v))
		}
	}

	log.Infof("Restored %d buckets from dump", len(state))
	return nil

}
