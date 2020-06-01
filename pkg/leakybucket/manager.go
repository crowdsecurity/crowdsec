package leakybucket

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/types"

	"github.com/davecgh/go-spew/spew"
	"github.com/prometheus/client_golang/prometheus"
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
	FormatVersion  string              `yaml:"format"`
	Author         string              `yaml:"author"`
	Description    string              `yaml:"description"`
	References     []string            `yaml:"references"`
	Type           string              `yaml:"type"`                //Type can be : leaky, counter, trigger. It determines the main bucket characteristics
	Name           string              `yaml:"name"`                //Name of the bucket, used later in log and user-messages. Should be unique
	Capacity       int                 `yaml:"capacity"`            //Capacity is applicable to leaky buckets and determines the "burst" capacity
	LeakSpeed      string              `yaml:"leakspeed"`           //Leakspeed is a float representing how many events per second leak out of the bucket
	Duration       string              `yaml:"duration"`            //Duration allows 'counter' buckets to have a fixed life-time
	Filter         string              `yaml:"filter"`              //Filter is an expr that determines if an event is elligible for said bucket. Filter is evaluated against the Event struct
	GroupBy        string              `yaml:"groupby,omitempty"`   //groupy is an expr that allows to determine the partitions of the bucket. A common example is the source_ip
	Distinct       string              `yaml:"distinct"`            //Distinct, when present, adds a `Pour()` processor that will only pour uniq items (based on uniq_filter expr result)
	Debug          bool                `yaml:"debug"`               //Debug, when set to true, will enable debugging for _this_ scenario specifically
	Labels         map[string]string   `yaml:"labels"`              //Labels is K:V list aiming at providing context the overflow
	Blackhole      string              `yaml:"blackhole,omitempty"` //Blackhole is a duration that, if present, will prevent same bucket partition to overflow more often than $duration
	logger         *log.Entry          `yaml:"-"`                   //logger is bucket-specific logger (used by Debug as well)
	Reprocess      bool                `yaml:"reprocess"`           //Reprocess, if true, will for the bucket to be re-injected into processing chain
	CacheSize      int                 `yaml:"cache_size"`          //CacheSize, if > 0, limits the size of in-memory cache of the bucket
	Profiling      bool                `yaml:"profiling"`           //Profiling, if true, will make the bucket record pours/overflows/etc.
	OverflowFilter string              `yaml:"overflow_filter"`     //OverflowFilter if present, is a filter that must return true for the overflow to go through
	BucketName     string              `yaml:"-"`
	Filename       string              `yaml:"-"`
	RunTimeFilter  *vm.Program         `json:"-"`
	RunTimeGroupBy *vm.Program         `json:"-"`
	Data           []*types.DataSource `yaml:"data,omitempty"`
	leakspeed      time.Duration       //internal representation of `Leakspeed`
	duration       time.Duration       //internal representation of `Duration`
	ret            chan types.Event    //the bucket-specific output chan for overflows
	processors     []Processor         //processors is the list of hooks for pour/overflow/create (cf. uniq, blackhole etc.)
	output         bool                //??
}

func ValidateFactory(b *BucketFactory) error {
	if b.Name == "" {
		return fmt.Errorf("bucket must have name")
	}
	if b.Description == "" {
		return fmt.Errorf("description is mandatory")
	}
	if b.Type == "leaky" {
		if b.Capacity <= 0 { //capacity must be a positive int
			return fmt.Errorf("bad capacity for leaky '%d'", b.Capacity)
		}
		if b.LeakSpeed == "" {
			return fmt.Errorf("leakspeed can't be empty for leaky")
		}
		if b.leakspeed == 0 {
			return fmt.Errorf("bad leakspeed for leaky '%s'", b.LeakSpeed)
		}
	} else if b.Type == "counter" {
		if b.Duration == "" {
			return fmt.Errorf("duration ca't be empty for counter")
		}
		if b.duration == 0 {
			return fmt.Errorf("bad duration for counter bucket '%d'", b.duration)
		}
		if b.Capacity != -1 {
			return fmt.Errorf("counter bucket must have -1 capacity")
		}
	} else if b.Type == "trigger" {
		if b.Capacity != 0 {
			return fmt.Errorf("trigger bucket must have 0 capacity")
		}
	} else {
		return fmt.Errorf("unknown bucket type '%s'", b.Type)
	}
	return nil
}

/* Init recursively process yaml files from a directory and loads them as BucketFactory */
func Init(cfg map[string]string) ([]BucketFactory, chan types.Event, error) {
	return LoadBucketDir(cfg["patterns"], cfg["data"])
}

func LoadBuckets(files []string, dataFolder string) ([]BucketFactory, chan types.Event, error) {
	var (
		ret      []BucketFactory = []BucketFactory{}
		response chan types.Event
	)

	var seed namegenerator.Generator = namegenerator.NewNameGenerator(time.Now().UTC().UnixNano())
	err := exprhelpers.Init()
	if err != nil {
		return nil, nil, err
	}

	response = make(chan types.Event, 1)
	for _, f := range files {
		log.Debugf("Loading %s", f)
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
			g := BucketFactory{}
			err = dec.Decode(&g)
			if err != nil {
				if err == io.EOF {
					log.Tracef("End of yaml file")
					break
				} else {
					log.Errorf("Bad yaml in %s : %v", f, err)
					return nil, nil, fmt.Errorf("bad yaml in %s : %v", f, err)
				}
			}
			//check empty
			if g.Name == "" {
				log.Errorf("Won't load nameless bucket")
				return nil, nil, fmt.Errorf("nameless bucket")
			}
			//check compat
			if g.FormatVersion == "" {
				log.Debugf("no version in %s : %s, assuming '1.0'", g.Name, f)
				g.FormatVersion = "1.0"
			}
			ok, err := cwversion.Statisfies(g.FormatVersion, cwversion.Constraint_scenario)
			if err != nil {
				log.Fatalf("Failed to check version : %s", err)
			}
			if !ok {
				log.Errorf("can't load %s : %s doesn't satisfy scenario format %s, skip", g.Name, g.FormatVersion, cwversion.Constraint_scenario)
				continue
			}
			g.Filename = filepath.Clean(f)
			g.BucketName = seed.Generate()
			g.ret = response
			err = LoadBucket(&g, dataFolder)
			if err != nil {
				log.Errorf("Failed to load bucket %s : %v", g.Name, err)
				return nil, nil, fmt.Errorf("loading of %s failed : %v", g.Name, err)
			}
			ret = append(ret, g)
		}
	}
	log.Warningf("Loaded %d scenarios", len(ret))
	return ret, response, nil
}

func LoadBucketDir(dir string, dataFolder string) ([]BucketFactory, chan types.Event, error) {
	var (
		filenames []string
	)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range files {
		filenames = append(filenames, dir+f.Name())
	}
	return LoadBuckets(filenames, dataFolder)
}

/* Init recursively process yaml files from a directory and loads them as BucketFactory */
func LoadBucket(g *BucketFactory, dataFolder string) error {
	var err error
	if g.Debug {
		var clog = logrus.New()
		if err := types.ConfigureLogger(clog); err != nil {
			log.Fatalf("While creating bucket-specific logger : %s", err)
		}
		clog.SetLevel(log.DebugLevel)
		g.logger = clog.WithFields(log.Fields{
			"cfg":  g.BucketName,
			"name": g.Name,
			"file": g.Filename,
		})
	} else {
		/* else bind it to the default one (might find something more elegant here)*/
		g.logger = log.WithFields(log.Fields{
			"cfg":  g.BucketName,
			"name": g.Name,
			"file": g.Filename,
		})
	}

	if g.LeakSpeed != "" {
		if g.leakspeed, err = time.ParseDuration(g.LeakSpeed); err != nil {
			return fmt.Errorf("bad leakspeed '%s' in %s : %v", g.LeakSpeed, g.Filename, err)
		}
	} else {
		g.leakspeed = time.Duration(0)
	}
	if g.Duration != "" {
		if g.duration, err = time.ParseDuration(g.Duration); err != nil {
			return fmt.Errorf("invalid Duration '%s' in %s : %v", g.Duration, g.Filename, err)
		}
	}

	if g.Filter == "" {
		g.logger.Warningf("Bucket without filter, abort.")
		return fmt.Errorf("bucket without filter directive")
	}
	g.RunTimeFilter, err = expr.Compile(g.Filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
	if err != nil {
		return fmt.Errorf("invalid filter '%s' in %s : %v", g.Filter, g.Filename, err)
	}

	if g.GroupBy != "" {
		g.RunTimeGroupBy, err = expr.Compile(g.GroupBy, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
		if err != nil {
			return fmt.Errorf("invalid groupby '%s' in %s : %v", g.GroupBy, g.Filename, err)
		}
	}

	g.logger.Infof("Adding %s bucket", g.Type)
	//return the Holder correponding to the type of bucket
	g.processors = []Processor{}
	switch g.Type {
	case "leaky":
		g.processors = append(g.processors, &DumbProcessor{})
	case "trigger":
		g.processors = append(g.processors, &Trigger{})
	case "counter":
		g.processors = append(g.processors, &DumbProcessor{})
	default:
		return fmt.Errorf("invalid type '%s' in %s : %v", g.Type, g.Filename, err)
	}

	if g.Distinct != "" {
		g.logger.Debugf("Adding a non duplicate filter on %s.", g.Name)
		g.processors = append(g.processors, &Uniq{})
	}

	if g.OverflowFilter != "" {
		g.logger.Debugf("Adding an overflow filter")
		filovflw, err := NewOverflowFilter(g)
		if err != nil {
			g.logger.Errorf("Error creating overflow_filter : %s", err)
			return fmt.Errorf("error creating overflow_filter : %s", err)
		}
		g.processors = append(g.processors, filovflw)
	}

	if g.Blackhole != "" {
		g.logger.Debugf("Adding blackhole.")
		blackhole, err := NewBlackhole(g)
		if err != nil {
			g.logger.Errorf("Error creating blackhole : %s", err)
			return fmt.Errorf("error creating blackhole : %s", err)
		}
		g.processors = append(g.processors, blackhole)
	}

	if len(g.Data) > 0 {
		for _, data := range g.Data {
			err = exprhelpers.FileInit(dataFolder, data.DestPath, data.Type)
			if err != nil {
				g.logger.Errorf("unable to init data for file '%s': %s", data.DestPath, err.Error())
			}
		}
	}

	g.output = false
	if err := ValidateFactory(g); err != nil {
		return fmt.Errorf("invalid bucket from %s : %v", g.Filename, err)
	}
	return nil

}

func LoadBucketsState(file string, buckets *Buckets, holders []BucketFactory) error {
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
		for _, h := range holders {
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

var serialized map[string]Leaky

/*The leaky routines lifecycle are based on "real" time.
But when we are running in time-machine mode, the reference time is in logs and not "real" time.
Thus we need to garbage collect them to avoid a skyrocketing memory usage.*/
func GarbageCollectBuckets(deadline time.Time, buckets *Buckets) error {
	total := 0
	discard := 0
	toflush := []string{}
	buckets.Bucket_map.Range(func(rkey, rvalue interface{}) bool {
		key := rkey.(string)
		val := rvalue.(*Leaky)
		total += 1
		if !val.Ovflw_ts.IsZero() {
			discard += 1
			val.logger.Debugf("overflowed at %s.", val.Ovflw_ts)
			toflush = append(toflush, key)
			val.KillSwitch <- true
			return true
		}
		/*FIXME : sometimes the gettokenscountat has some rounding issues when we try to
		match it with bucket capacity, even if the bucket has long due underflow. Round to 2 decimals*/
		tokat := val.Limiter.GetTokensCountAt(deadline)
		tokcapa := float64(val.Capacity)
		tokat = math.Round(tokat*100) / 100
		tokcapa = math.Round(tokcapa*100) / 100
		if tokat >= tokcapa {
			BucketsUnderflow.With(prometheus.Labels{"name": val.Name}).Inc()
			val.logger.Debugf("UNDERFLOW : first_ts:%s tokens_at:%f capcity:%f", val.First_ts, tokat, tokcapa)
			toflush = append(toflush, key)
			val.KillSwitch <- true
			return true
		} else {
			val.logger.Debugf("(%s) not dead, count:%f capacity:%f", val.First_ts, tokat, tokcapa)
		}
		if _, ok := serialized[key]; ok {
			log.Errorf("entry %s already exists", key)
			return false
		} else {
			log.Debugf("serialize %s of %s : %s", val.Name, val.Uuid, val.Mapkey)
		}
		return true
	})
	log.Infof("Cleaned %d buckets", len(toflush))
	for _, flushkey := range toflush {
		buckets.Bucket_map.Delete(flushkey)
	}
	return nil
}

func DumpBucketsStateAt(file string, deadline time.Time, buckets *Buckets) error {
	serialized = make(map[string]Leaky)
	log.Printf("Dumping buckets state at %s", deadline)
	total := 0
	discard := 0
	buckets.Bucket_map.Range(func(rkey, rvalue interface{}) bool {
		key := rkey.(string)
		val := rvalue.(*Leaky)
		total += 1
		if !val.Ovflw_ts.IsZero() {
			discard += 1
			val.logger.Debugf("overflowed at %s.", val.Ovflw_ts)
			return true
		}
		/*FIXME : sometimes the gettokenscountat has some rounding issues when we try to
		match it with bucket capacity, even if the bucket has long due underflow. Round to 2 decimals*/
		tokat := val.Limiter.GetTokensCountAt(deadline)
		tokcapa := float64(val.Capacity)
		tokat = math.Round(tokat*100) / 100
		tokcapa = math.Round(tokcapa*100) / 100

		if tokat >= tokcapa {
			BucketsUnderflow.With(prometheus.Labels{"name": val.Name}).Inc()
			val.logger.Debugf("UNDERFLOW : first_ts:%s tokens_at:%f capcity:%f", val.First_ts, tokat, tokcapa)
			discard += 1
			return true
		} else {
			val.logger.Debugf("(%s) not dead, count:%f capacity:%f", val.First_ts, tokat, tokcapa)
		}
		if _, ok := serialized[key]; ok {
			log.Errorf("entry %s already exists", key)
			return false
		} else {
			log.Debugf("serialize %s of %s : %s", val.Name, val.Uuid, val.Mapkey)
		}
		val.SerializedState = val.Limiter.Dump()
		serialized[key] = *val
		return true
	})
	bbuckets, err := json.MarshalIndent(serialized, "", " ")
	if err != nil {
		log.Fatalf("Failed to unmarshal buckets : %s", err)
	}
	err = ioutil.WriteFile(file, bbuckets, 0644)
	if err != nil {
		log.Fatalf("Failed to write buckets state %s", err)
	}
	log.Warningf("Serialized %d live buckets state, %d total with %d expired to %s", len(serialized), total, discard, file)
	return nil
}

func PourItemToHolders(parsed types.Event, holders []BucketFactory, buckets *Buckets) (bool, error) {
	var (
		ok, condition, sent bool
		err                 error
	)

	for idx, holder := range holders {

		if holder.RunTimeFilter != nil {
			log.Debugf("event against holder %d/%d", idx, len(holders))
			output, err := expr.Run(holder.RunTimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &parsed}))
			if err != nil {
				holder.logger.Errorf("failed parsing : %v", err)
				return false, fmt.Errorf("leaky failed : %s", err)
			}
			// we assume we a bool should add type check here
			if condition, ok = output.(bool); !ok {
				holder.logger.Errorf("unexpected non-bool return : %T", output)
				log.Fatalf("Filter issue")
			}
			if !condition {
				holder.logger.Debugf("eval(FALSE) %s", holder.Filter)
				//log.Debugf("%s -> FALSE", holder.Filter)
				//holder.logger.Debugf("Filter eval failed")
				continue
			} else {
				holder.logger.Debugf("eval(TRUE) %s", holder.Filter)
			}
		}

		sent = false
		var groupby string
		if holder.RunTimeGroupBy != nil {
			tmpGroupBy, err := expr.Run(holder.RunTimeGroupBy, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &parsed}))
			if err != nil {
				log.Errorf("failed groupby : %v", err)
				return false, errors.New("leaky failed :/")
			}

			if groupby, ok = tmpGroupBy.(string); !ok {
				log.Fatalf("failed groupby type : %v", err)
				return false, errors.New("groupby wrong type")
			}
		}
		buckey := GetKey(holder, groupby)

		sigclosed := 0
		keymiss := 0
		failed_sent := 0
		attempts := 0
		start := time.Now()
		for !sent {
			attempts += 1
			/* Warn the user if we used more than a 100 ms to pour an event, it's at least an half lock*/
			if attempts%100000 == 0 && start.Add(100*time.Millisecond).Before(time.Now()) {
				log.Warningf("stuck for %s sending event to %s (sigclosed:%d keymiss:%d failed_sent:%d attempts:%d)", time.Since(start),
					buckey, sigclosed, keymiss, failed_sent, attempts)
			}
			biface, ok := buckets.Bucket_map.Load(buckey)
			//biface, bigout
			/* the bucket doesn't exist, create it !*/
			if !ok {
				/*
					not found in map
				*/

				log.Debugf("Creating bucket %s", buckey)
				keymiss += 1
				var fresh_bucket *Leaky

				switch parsed.ExpectMode {
				case TIMEMACHINE:
					fresh_bucket = NewTimeMachine(holder)
					holder.logger.Debugf("Creating TimeMachine bucket")
				case LIVE:
					fresh_bucket = NewLeaky(holder)
					holder.logger.Debugf("Creating Live bucket")
				default:
					log.Fatalf("input event has no expected mode, malformed : %+v", parsed)
				}
				fresh_bucket.In = make(chan types.Event)
				fresh_bucket.Mapkey = buckey
				fresh_bucket.Signal = make(chan bool, 1)
				fresh_bucket.KillSwitch = make(chan bool, 1)
				buckets.Bucket_map.Store(buckey, fresh_bucket)
				go LeakRoutine(fresh_bucket)
				log.Debugf("Created new bucket %s", buckey)
				//wait for signal to be opened
				<-fresh_bucket.Signal
				continue
			}

			bucket := biface.(*Leaky)
			/* check if leak routine is up */
			select {
			case _, ok := <-bucket.Signal:
				if !ok {
					//it's closed, delete it
					bucket.logger.Debugf("Bucket %s found dead, cleanup the body", buckey)
					buckets.Bucket_map.Delete(buckey)
					sigclosed += 1
					continue
				}
				log.Debugf("Signal exists, try to pour :)")

			default:
				/*nothing to read, but not closed, try to pour */
				log.Debugf("Signal exists but empty, try to pour :)")

			}
			/*let's see if this time-bucket should have expired */
			if bucket.Mode == TIMEMACHINE && !bucket.First_ts.IsZero() {
				var d time.Time
				err = d.UnmarshalText([]byte(parsed.MarshaledTime))
				if err != nil {
					log.Warningf("Failed unmarshaling event time (%s) : %v", parsed.MarshaledTime, err)
				}
				if d.After(bucket.Last_ts.Add(bucket.Duration)) {
					bucket.logger.Debugf("bucket is expired (curr event: %s, bucket deadline: %s), kill", d, bucket.Last_ts.Add(bucket.Duration))
					buckets.Bucket_map.Delete(buckey)
					continue
				}
			}
			/*if we're here, let's try to pour */

			select {
			case bucket.In <- parsed:
				log.Debugf("Successfully sent !")
				//sent was successful !
				sent = true
				continue
			default:
				failed_sent += 1
				log.Debugf("Failed to send, try again")
				continue

			}
		}

		log.Debugf("bucket '%s' is poured", holder.Name)
	}
	return sent, nil
}
