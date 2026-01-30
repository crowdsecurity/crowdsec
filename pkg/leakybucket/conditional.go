package leakybucket

import (
	"github.com/expr-lang/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type ConditionalProcessor struct {
	Condition        string
	ConditionRuntime *vm.Program
	DumbProcessor
}

func NewConditionalProcessor(f *BucketFactory) (*ConditionalProcessor, error) {
	p := ConditionalProcessor{}
	p.ConditionRuntime = f.RunTimeCondition
	return &p, nil
}

func (p *ConditionalProcessor) AfterBucketPour(f *BucketFactory, msg pipeline.Event, l *Leaky) *pipeline.Event {
	var condition, ok bool

	if p.ConditionRuntime != nil {
		l.logger.Debugf("Running condition expression : %s", p.Condition)

		ret, err := exprhelpers.Run(p.ConditionRuntime,
			map[string]any{"evt": &msg, "queue": l.Queue, "leaky": l},
			l.logger, f.Spec.Debug)
		if err != nil {
			l.logger.Errorf("unable to run conditional filter : %s", err)
			return &msg
		}

		l.logger.Debugf("Conditional bucket expression returned : %v", ret)

		if condition, ok = ret.(bool); !ok {
			l.logger.Warningf("overflow condition, unexpected non-bool return : %T", ret)
			return &msg
		}

		if condition {
			l.logger.Debugf("Conditional bucket overflow")
			l.Ovflw_ts = l.Last_ts
			l.Out <- l.Queue
			return nil
		}
	}

	return &msg
}
