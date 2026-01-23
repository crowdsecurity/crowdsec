package leakybucket

import (
	"errors"
	"fmt"
)

type BucketType interface {
	Validate(f *BucketFactory) error
	BuildProcessors(f *BucketFactory) []Processor
}

var bucketTypes = map[string]BucketType{
	"leaky":       LeakyType{},
	"trigger":     TriggerType{},
	"counter":     CounterType{},
	"conditional": ConditionalType{},
	"bayesian":    BayesianType{},
}

type LeakyType struct{}

func (LeakyType) Validate(f *BucketFactory) error {
	if f.Capacity <= 0 { // capacity must be a positive int
		return fmt.Errorf("bad capacity for leaky '%d'", f.Capacity)
	}

	if f.LeakSpeed == "" {
		return errors.New("leakspeed can't be empty for leaky")
	}

	if f.leakspeed == 0 {
		return fmt.Errorf("bad leakspeed for leaky '%s'", f.LeakSpeed)
	}

	return nil
}

func (LeakyType) BuildProcessors(_ *BucketFactory) []Processor {
	return []Processor{&DumbProcessor{}}
}

type TriggerType struct{}

func (TriggerType) Validate(f *BucketFactory) error {
	if f.Capacity != 0 {
		return errors.New("trigger bucket must have 0 capacity")
	}

	return nil
}

func (TriggerType) BuildProcessors(_ *BucketFactory) []Processor {
	return []Processor{&TriggerProcessor{}}
}

type CounterType struct{}

func (CounterType) Validate(f *BucketFactory) error {
	if f.Duration == "" {
		return errors.New("duration can't be empty for counter")
	}

	if f.duration == 0 {
		return fmt.Errorf("bad duration for counter bucket '%d'", f.duration)
	}

	if f.Capacity != -1 {
		return errors.New("counter bucket must have -1 capacity")
	}

	return nil
}

func (CounterType) BuildProcessors(_ *BucketFactory) []Processor {
	return []Processor{&DumbProcessor{}}
}

type ConditionalType struct{}

func (ConditionalType) Validate(f *BucketFactory) error {
	if f.ConditionalOverflow == "" {
		return errors.New("conditional bucket must have a condition")
	}

	if f.Capacity != -1 {
		f.logger.Warnf("Using a value different than -1 as capacity for conditional bucket, this may lead to unexpected overflows")
	}

	if f.LeakSpeed == "" {
		return errors.New("leakspeed can't be empty for conditional bucket")
	}

	if f.leakspeed == 0 {
		return fmt.Errorf("bad leakspeed for conditional bucket '%s'", f.LeakSpeed)
	}

	return nil
}

func (ConditionalType) BuildProcessors(_ *BucketFactory) []Processor {
	return []Processor{&DumbProcessor{}}
}

type BayesianType struct{}

func (BayesianType) Validate(f *BucketFactory) error {
	if f.BayesianConditions == nil {
		return errors.New("bayesian bucket must have bayesian conditions")
	}

	if f.BayesianPrior == 0 {
		return errors.New("bayesian bucket must have a valid, non-zero prior")
	}

	if f.BayesianThreshold == 0 {
		return errors.New("bayesian bucket must have a valid, non-zero threshold")
	}

	if f.BayesianPrior > 1 {
		return errors.New("bayesian bucket must have a valid, non-zero prior")
	}

	if f.BayesianThreshold > 1 {
		return errors.New("bayesian bucket must have a valid, non-zero threshold")
	}

	if f.Capacity != -1 {
		return errors.New("bayesian bucket must have capacity -1")
	}

	return nil
}

func (BayesianType) BuildProcessors(_ *BucketFactory) []Processor {
	return []Processor{&DumbProcessor{}}
}
