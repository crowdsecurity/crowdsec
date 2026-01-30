package leakybucket

import (
	"errors"
	"fmt"
)

type ProcessorFactory func (*BucketFactory) (Processor, error)

// generic function to avoid returning interfaces from the constructors
func asFactory[T Processor](fn func(*BucketFactory) (T, error)) ProcessorFactory {
	return func(f *BucketFactory) (Processor, error) { return fn(f) }
}

type BucketType interface {
	Validate(f *BucketFactory) error
	CoreProcessors(f *BucketFactory) []ProcessorFactory
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
	if f.Spec.Capacity <= 0 {
		return fmt.Errorf("invalid capacity '%d': must be > 0", f.Spec.Capacity)
	}

	if f.Spec.LeakSpeed == "" {
		return errors.New("leakspeed is required")
	}

	if f.leakspeed <= 0 {
		return fmt.Errorf("invalid leakspeed '%s': must be > 0", f.Spec.LeakSpeed)
	}

	return nil
}

func (LeakyType) CoreProcessors(_ *BucketFactory) []ProcessorFactory {
	return []ProcessorFactory{asFactory(NewDumbProcessor)}
}

type TriggerType struct{}

func (TriggerType) Validate(f *BucketFactory) error {
	if f.Spec.Capacity != 0 {
		return fmt.Errorf("invalid capacity '%d': must be 0", f.Spec.Capacity)
	}

	return nil
}

func (TriggerType) CoreProcessors(_ *BucketFactory) []ProcessorFactory {
	return []ProcessorFactory{asFactory(NewDumbProcessor)}
}

type CounterType struct{}

func (CounterType) Validate(f *BucketFactory) error {
	if f.Spec.Capacity != -1 {
		return fmt.Errorf("invalid capacity '%d': must be -1", f.Spec.Capacity)
	}

	if f.Spec.Duration == "" {
		return errors.New("duration is required")
	}

	if f.duration <= 0 {
		return fmt.Errorf("invalid duration '%d': must be > 0", f.duration)
	}

	return nil
}

func (CounterType) CoreProcessors(_ *BucketFactory) []ProcessorFactory {
	return []ProcessorFactory{asFactory(NewDumbProcessor)}
}

type ConditionalType struct{}

func (ConditionalType) Validate(f *BucketFactory) error {
	if f.Spec.Capacity != -1 {
		f.logger.Warnf("Using a value different than -1 as capacity for conditional bucket, this may lead to unexpected overflows")
	}

	if f.Spec.Condition == "" {
		return errors.New("a condition is required")
	}

	if f.Spec.LeakSpeed == "" {
		return errors.New("leakspeed is required")
	}

	if f.leakspeed <= 0 {
		return fmt.Errorf("invalid leakspeed '%s': must be > 0", f.Spec.LeakSpeed)
	}

	return nil
}

func (ConditionalType) CoreProcessors(_ *BucketFactory) []ProcessorFactory {
	return []ProcessorFactory{asFactory(NewDumbProcessor)}
}

type BayesianType struct{}

func (BayesianType) Validate(f *BucketFactory) error {
	if len(f.Spec.BayesianConditions) == 0 {
		return errors.New("bayesian conditions are required")
	}

	if f.Spec.BayesianPrior <= 0 || f.Spec.BayesianPrior > 1 {
		return errors.New("invalid prior: must be > 0 and <= 1")
	}

	if f.Spec.BayesianThreshold == 0 || f.Spec.BayesianThreshold > 1 {
		return errors.New("invalid threshold: must be > 0 and <= 1")
	}

	if f.Spec.Capacity != -1 {
		return errors.New("capacity must be -1")
	}

	return nil
}

func (BayesianType) CoreProcessors(_ *BucketFactory) []ProcessorFactory {
	return []ProcessorFactory{asFactory(NewDumbProcessor)}
}
