package leakybucket

import (
	"fmt"
	"testing"

	"gopkg.in/tomb.v2"
)

type cfgTest struct {
	cfg      BucketFactory
	loadable bool
	valid    bool
}

func runTest(tests []cfgTest) error {
	var tomb = &tomb.Tomb{}
	for idx, cfg := range tests {
		err := LoadBucket(&cfg.cfg, tomb)
		if cfg.loadable && err != nil {
			return fmt.Errorf("expected loadable result (%d/%d), got: %s", idx+1, len(tests), err)
		}
		if !cfg.loadable && err == nil {
			return fmt.Errorf("expected unloadable result (%d/%d)", idx+1, len(tests))
		}
		err = ValidateFactory(&cfg.cfg)
		if cfg.valid && err != nil {
			return fmt.Errorf("expected valid result (%d/%d), got: %s", idx+1, len(tests), err)
		}
		if !cfg.valid && err == nil {
			return fmt.Errorf("expected invalid result (%d/%d)", idx+1, len(tests))
		}
	}
	return nil
}

func TestBadBucketsConfig(t *testing.T) {
	var CfgTests = []cfgTest{
		//empty
		{BucketFactory{}, false, false},
		//missing description
		{BucketFactory{Name: "test"}, false, false},
		//missing type
		{BucketFactory{Name: "test", Description: "test1"}, false, false},
		//bad type
		{BucketFactory{Name: "test", Description: "test1", Type: "ratata"}, false, false},
	}
	if err := runTest(CfgTests); err != nil {
		t.Fatalf("%s", err)
	}
}

func TestLeakyBucketsConfig(t *testing.T) {
	var CfgTests = []cfgTest{
		//leaky with bad capacity
		{BucketFactory{Name: "test", Description: "test1", Type: "leaky", Capacity: 0}, false, false},
		//leaky with empty leakspeed
		{BucketFactory{Name: "test", Description: "test1", Type: "leaky", Capacity: 1}, false, false},
		//leaky with missing filter
		{BucketFactory{Name: "test", Description: "test1", Type: "leaky", Capacity: 1, LeakSpeed: "1s"}, false, true},
		//leaky with invalid leakspeed
		{BucketFactory{Name: "test", Description: "test1", Type: "leaky", Capacity: 1, LeakSpeed: "abs", Filter: "true"}, false, false},
		//leaky with valid filter
		{BucketFactory{Name: "test", Description: "test1", Type: "leaky", Capacity: 1, LeakSpeed: "1s", Filter: "true"}, true, true},
		//leaky with invalid filter
		{BucketFactory{Name: "test", Description: "test1", Type: "leaky", Capacity: 1, LeakSpeed: "1s", Filter: "xu"}, false, true},
		//leaky with valid filter
		{BucketFactory{Name: "test", Description: "test1", Type: "leaky", Capacity: 1, LeakSpeed: "1s", Filter: "true"}, true, true},
		//leaky with bad overflow filter
		{BucketFactory{Name: "test", Description: "test1", Type: "leaky", Capacity: 1, LeakSpeed: "1s", Filter: "true", OverflowFilter: "xu"}, false, true},
	}

	if err := runTest(CfgTests); err != nil {
		t.Fatalf("%s", err)
	}

}

func TestBlackholeConfig(t *testing.T) {
	var CfgTests = []cfgTest{
		//basic bh
		{BucketFactory{Name: "test", Description: "test1", Type: "trigger", Filter: "true", Blackhole: "15s"}, true, true},
		//bad bh
		{BucketFactory{Name: "test", Description: "test1", Type: "trigger", Filter: "true", Blackhole: "abc"}, false, true},
	}

	if err := runTest(CfgTests); err != nil {
		t.Fatalf("%s", err)
	}

}

func TestTriggerBucketsConfig(t *testing.T) {
	var CfgTests = []cfgTest{
		//basic valid counter
		{BucketFactory{Name: "test", Description: "test1", Type: "trigger", Filter: "true"}, true, true},
	}

	if err := runTest(CfgTests); err != nil {
		t.Fatalf("%s", err)
	}

}

func TestCounterBucketsConfig(t *testing.T) {
	var CfgTests = []cfgTest{

		//basic valid counter
		{BucketFactory{Name: "test", Description: "test1", Type: "counter", Capacity: -1, Duration: "5s", Filter: "true"}, true, true},
		//missing duration
		{BucketFactory{Name: "test", Description: "test1", Type: "counter", Capacity: -1, Filter: "true"}, false, false},
		//bad duration
		{BucketFactory{Name: "test", Description: "test1", Type: "counter", Capacity: -1, Duration: "abc", Filter: "true"}, false, false},
		//capacity must be -1
		{BucketFactory{Name: "test", Description: "test1", Type: "counter", Capacity: 0, Duration: "5s", Filter: "true"}, false, false},
	}
	if err := runTest(CfgTests); err != nil {
		t.Fatalf("%s", err)
	}

}

func TestBayesianBucketsConfig(t *testing.T) {
	var CfgTests = []cfgTest{

		//basic valid counter
		{BucketFactory{Name: "test", Description: "test1", Type: "bayesian", Capacity: -1, Filter: "true", BayesianPrior: 0.5, BayesianThreshold: 0.5, BayesianConditions: []RawBayesianCondition{{ConditionalFilterName: "true", ProbGivenEvil: 0.5, ProbGivenBenign: 0.5}}}, true, true},
		//bad capacity
		{BucketFactory{Name: "test", Description: "test1", Type: "bayesian", Capacity: 1, Filter: "true", BayesianPrior: 0.5, BayesianThreshold: 0.5, BayesianConditions: []RawBayesianCondition{{ConditionalFilterName: "true", ProbGivenEvil: 0.5, ProbGivenBenign: 0.5}}}, false, false},
		//missing prior
		{BucketFactory{Name: "test", Description: "test1", Type: "bayesian", Capacity: -1, Filter: "true", BayesianThreshold: 0.5, BayesianConditions: []RawBayesianCondition{{ConditionalFilterName: "true", ProbGivenEvil: 0.5, ProbGivenBenign: 0.5}}}, false, false},
		//missing threshold
		{BucketFactory{Name: "test", Description: "test1", Type: "bayesian", Capacity: -1, Filter: "true", BayesianPrior: 0.5, BayesianConditions: []RawBayesianCondition{{ConditionalFilterName: "true", ProbGivenEvil: 0.5, ProbGivenBenign: 0.5}}}, false, false},
		//bad prior
		{BucketFactory{Name: "test", Description: "test1", Type: "bayesian", Capacity: -1, Filter: "true", BayesianPrior: 1.5, BayesianThreshold: 0.5, BayesianConditions: []RawBayesianCondition{{ConditionalFilterName: "true", ProbGivenEvil: 0.5, ProbGivenBenign: 0.5}}}, false, false},
		//bad threshold
		{BucketFactory{Name: "test", Description: "test1", Type: "bayesian", Capacity: -1, Filter: "true", BayesianPrior: 0.5, BayesianThreshold: 1.5, BayesianConditions: []RawBayesianCondition{{ConditionalFilterName: "true", ProbGivenEvil: 0.5, ProbGivenBenign: 0.5}}}, false, false},
	}
	if err := runTest(CfgTests); err != nil {
		t.Fatalf("%s", err)
	}

}
