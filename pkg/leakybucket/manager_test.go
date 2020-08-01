package leakybucket

import "testing"

func TestBadBucketsConfig(t *testing.T) {
	var CfgTests = []struct {
		cfg      BucketFactory
		loadable bool
		valid    bool
	}{
		//empty
		{BucketFactory{}, false, false},
		// //missing description
		{BucketFactory{Name: "test"}, false, false},
		// //missing type
		{BucketFactory{Name: "test", Description: "test1"}, false, false},
		//bad type
		{BucketFactory{Name: "test", Description: "test1", Type: "ratata"}, false, false},
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
	}
	for idx, cfg := range CfgTests {
		err := LoadBucket(&cfg.cfg, ".")
		if cfg.loadable && err != nil {
			t.Fatalf("expected loadable result (%d/%d), got: %s", idx+1, len(CfgTests), err)
		}
		if !cfg.loadable && err == nil {
			t.Fatalf("expected unloadable result (%d/%d)", idx+1, len(CfgTests))
		}
		err = ValidateFactory(&cfg.cfg)
		if cfg.valid && err != nil {
			t.Fatalf("expected valid result (%d/%d), got: %s", idx+1, len(CfgTests), err)
		}
		if !cfg.valid && err == nil {
			t.Fatalf("expected invalid result (%d/%d)", idx+1, len(CfgTests))
		}
	}
}
