package leakybucket

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBucketTypes_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		typ     BucketType
		f       BucketFactory
		wantErr string
	}{
		// --- Leaky ---
		{
			name: "leaky/ok",
			typ:  LeakyType{},
			f: BucketFactory{
				Spec:      BucketSpec{Capacity: 10, LeakSpeed: "1s"},
				leakspeed: time.Second,
			},
		},
		{
			name: "leaky/invalid capacity",
			typ:  LeakyType{},
			f: BucketFactory{
				Spec:      BucketSpec{Capacity: 0, LeakSpeed: "1s"},
				leakspeed: time.Second,
			},
			wantErr: "invalid capacity '0': must be > 0",
		},
		{
			name: "leaky/missing leakspeed",
			typ:  LeakyType{},
			f: BucketFactory{
				Spec:      BucketSpec{Capacity: 10, LeakSpeed: ""},
				leakspeed: time.Second,
			},
			wantErr: "leakspeed is required",
		},
		{
			name: "leaky/invalid parsed leakspeed (<= 0)",
			typ:  LeakyType{},
			f: BucketFactory{
				Spec:      BucketSpec{Capacity: 10, LeakSpeed: "1s"},
				leakspeed: 0,
			},
			wantErr: "invalid leakspeed '1s': must be > 0",
		},

		// --- Trigger ---
		{
			name: "trigger/ok",
			typ:  TriggerType{},
			f: BucketFactory{
				Spec: BucketSpec{Capacity: 0},
			},
		},
		{
			name: "trigger/invalid capacity must be 0",
			typ:  TriggerType{},
			f: BucketFactory{
				Spec: BucketSpec{Capacity: 1},
			},
			wantErr: "invalid capacity '1': must be 0",
		},

		// --- Counter ---
		{
			name: "counter/ok",
			typ:  CounterType{},
			f: BucketFactory{
				Spec:     BucketSpec{Capacity: -1, Duration: "10s"},
				duration: 10 * time.Second,
			},
		},
		{
			name: "counter/invalid capacity must be -1",
			typ:  CounterType{},
			f: BucketFactory{
				Spec:     BucketSpec{Capacity: 0, Duration: "10s"},
				duration: 10 * time.Second,
			},
			wantErr: "invalid capacity '0': must be -1",
		},
		{
			name: "counter/missing duration",
			typ:  CounterType{},
			f: BucketFactory{
				Spec:     BucketSpec{Capacity: -1, Duration: ""},
				duration: 10 * time.Second,
			},
			wantErr: "duration is required",
		},
		{
			name: "counter/invalid parsed duration (<= 0)",
			typ:  CounterType{},
			f: BucketFactory{
				Spec:     BucketSpec{Capacity: -1, Duration: "10s"},
				duration: 0,
			},
			wantErr: "invalid duration '0': must be > 0",
		},

		// --- Conditional ---
		{
			name: "conditional/ok",
			typ:  ConditionalType{},
			f: BucketFactory{
				Spec:      BucketSpec{Capacity: -1, ConditionalOverflow: "evt.Meta.foo == 'bar'", LeakSpeed: "1s"},
				leakspeed: time.Second,
			},
		},
		{
			name: "conditional/missing condition",
			typ:  ConditionalType{},
			f: BucketFactory{
				Spec:      BucketSpec{Capacity: -1, ConditionalOverflow: "", LeakSpeed: "1s"},
				leakspeed: time.Second,
			},
			wantErr: "a condition is required",
		},
		{
			name: "conditional/missing leakspeed",
			typ:  ConditionalType{},
			f: BucketFactory{
				Spec:      BucketSpec{Capacity: -1, ConditionalOverflow: "x", LeakSpeed: ""},
				leakspeed: time.Second,
			},
			wantErr: "leakspeed is required",
		},
		{
			name: "conditional/invalid parsed leakspeed (<= 0)",
			typ:  ConditionalType{},
			f: BucketFactory{
				Spec:      BucketSpec{Capacity: -1, ConditionalOverflow: "x", LeakSpeed: "1s"},
				leakspeed: 0,
			},
			wantErr: "invalid leakspeed '1s': must be > 0",
		},

		// --- Bayesian ---
		{
			name: "bayesian/ok",
			typ:  BayesianType{},
			f: BucketFactory{
				Spec: BucketSpec{BayesianConditions: []RawBayesianCondition{{}}, BayesianPrior: 0.5, BayesianThreshold: 0.8, Capacity: -1},
			},
		},
		{
			name: "bayesian/missing conditions (nil)",
			typ:  BayesianType{},
			f: BucketFactory{
				Spec: BucketSpec{BayesianConditions: nil, BayesianPrior: 0.5, BayesianThreshold: 0.8, Capacity: -1},
			},
			wantErr: "bayesian conditions are required",
		},
		{
			name: "bayesian/missing conditions (empty slice)",
			typ:  BayesianType{},
			f: BucketFactory{
				Spec: BucketSpec{
					BayesianConditions: []RawBayesianCondition{}, BayesianPrior: 0.5, BayesianThreshold: 0.8, Capacity: -1},
			},
			wantErr: "bayesian conditions are required",
		},
		{
			name: "bayesian/invalid prior <= 0",
			typ:  BayesianType{},
			f: BucketFactory{
				Spec: BucketSpec{
					BayesianConditions: []RawBayesianCondition{{}}, BayesianPrior: 0, BayesianThreshold: 0.8, Capacity: -1},
			},
			wantErr: "invalid prior: must be > 0 and <= 1",
		},
		{
			name: "bayesian/invalid prior > 1",
			typ:  BayesianType{},
			f: BucketFactory{
				Spec: BucketSpec{
					BayesianConditions: []RawBayesianCondition{{}}, BayesianPrior: 1.01, BayesianThreshold: 0.8, Capacity: -1},
			},
			wantErr: "invalid prior: must be > 0 and <= 1",
		},
		{
			name: "bayesian/invalid threshold == 0",
			typ:  BayesianType{},
			f: BucketFactory{
				Spec: BucketSpec{
					BayesianConditions: []RawBayesianCondition{{}}, BayesianPrior: 0.5, BayesianThreshold: 0, Capacity: -1},
			},
			wantErr: "invalid threshold: must be > 0 and <= 1",
		},
		{
			name: "bayesian/invalid threshold > 1",
			typ:  BayesianType{},
			f: BucketFactory{
				Spec: BucketSpec{
					BayesianConditions: []RawBayesianCondition{{}}, BayesianPrior: 0.5, BayesianThreshold: 1.01, Capacity: -1},
			},
			wantErr: "invalid threshold: must be > 0 and <= 1",
		},
		{
			name: "bayesian/capacity must be -1",
			typ:  BayesianType{},
			f: BucketFactory{
				Spec: BucketSpec{
					BayesianConditions: []RawBayesianCondition{{}}, BayesianPrior: 0.5, BayesianThreshold: 0.8, Capacity: 0},
			},
			wantErr: "capacity must be -1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.typ.Validate(&tc.f)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			require.Equal(t, tc.wantErr, err.Error())
		})
	}
}
