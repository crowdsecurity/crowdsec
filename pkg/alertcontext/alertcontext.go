package alertcontext

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strconv"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const MaxContextValueLen = 4000

var alertContext = Context{}

type Context struct {
	ContextToSend         map[string][]string
	ContextValueLen       int
	ContextToSendCompiled map[string][]*vm.Program
	Log                   *log.Logger
}

func ValidateContextExpr(key string, expressions []string) error {
	for _, expression := range expressions {
		_, err := expr.Compile(expression, exprhelpers.GetExprOptions(map[string]interface{}{
			"evt":   &types.Event{},
			"match": &types.MatchedRule{},
			"req":   &http.Request{},
		})...)
		if err != nil {
			return fmt.Errorf("compilation of '%s' failed: %w", expression, err)
		}
	}

	return nil
}

func NewAlertContext(contextToSend map[string][]string, valueLength int) error {
	clog := log.New()
	if err := types.ConfigureLogger(clog); err != nil {
		return fmt.Errorf("couldn't create logger for alert context: %w", err)
	}

	if valueLength == 0 {
		clog.Debugf("No console context value length provided, using default: %d", MaxContextValueLen)
		valueLength = MaxContextValueLen
	}

	if valueLength > MaxContextValueLen {
		clog.Debugf("Provided console context value length (%d) is higher than the maximum, using default: %d", valueLength, MaxContextValueLen)
		valueLength = MaxContextValueLen
	}

	alertContext = Context{
		ContextToSend:         contextToSend,
		ContextValueLen:       valueLength,
		Log:                   clog,
		ContextToSendCompiled: make(map[string][]*vm.Program),
	}

	for key, values := range contextToSend {
		if _, ok := alertContext.ContextToSend[key]; !ok {
			alertContext.ContextToSend[key] = make([]string, 0)
		}

		if _, ok := alertContext.ContextToSendCompiled[key]; !ok {
			alertContext.ContextToSendCompiled[key] = make([]*vm.Program, 0)
		}

		for _, value := range values {
			valueCompiled, err := expr.Compile(value, exprhelpers.GetExprOptions(map[string]interface{}{
				"evt":   &types.Event{},
				"match": &types.MatchedRule{},
				"req":   &http.Request{},
			})...)
			if err != nil {
				return fmt.Errorf("compilation of '%s' context value failed: %w", value, err)
			}

			alertContext.ContextToSendCompiled[key] = append(alertContext.ContextToSendCompiled[key], valueCompiled)
			alertContext.ContextToSend[key] = append(alertContext.ContextToSend[key], value)
		}
	}

	return nil
}

// Truncate the context map to fit in the context value length
func TruncateContextMap(contextMap map[string][]string, contextValueLen int) ([]*models.MetaItems0, []error) {
	metas := make([]*models.MetaItems0, 0)
	errors := make([]error, 0)

	for key, values := range contextMap {
		if len(values) == 0 {
			continue
		}

		valueStr, err := TruncateContext(values, alertContext.ContextValueLen)
		if err != nil {
			errors = append(errors, fmt.Errorf("error truncating content for %s: %w", key, err))
			continue
		}

		meta := models.MetaItems0{
			Key:   key,
			Value: valueStr,
		}
		metas = append(metas, &meta)
	}

	return metas, errors
}

// Truncate an individual []string to fit in the context value length
func TruncateContext(values []string, contextValueLen int) (string, error) {
	valueByte, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("unable to dump metas: %w", err)
	}

	ret := string(valueByte)
	for len(ret) > contextValueLen {
		// if there is only 1 value left and that the size is too big, truncate it
		if len(values) == 1 {
			valueToTruncate := values[0]
			half := len(valueToTruncate) / 2
			lastValueTruncated := valueToTruncate[:half] + "..."
			values = values[:len(values)-1]
			values = append(values, lastValueTruncated)
		} else {
			// if there is multiple value inside, just remove the last one
			values = values[:len(values)-1]
		}

		valueByte, err = json.Marshal(values)
		if err != nil {
			return "", fmt.Errorf("unable to dump metas: %w", err)
		}

		ret = string(valueByte)
	}

	return ret, nil
}

func EvalAlertContextRules(evt types.Event, match *types.MatchedRule, request *http.Request, tmpContext map[string][]string) []error {
	var errors []error

	// if we're evaluating context for appsec event, match and request will be present.
	// otherwise, only evt will be.
	if match == nil {
		match = types.NewMatchedRule()
	}

	if request == nil {
		request = &http.Request{}
	}

	for key, values := range alertContext.ContextToSendCompiled {
		if _, ok := tmpContext[key]; !ok {
			tmpContext[key] = make([]string, 0)
		}

		for _, value := range values {
			var val string

			output, err := expr.Run(value, map[string]interface{}{"match": match, "evt": evt, "req": request})
			if err != nil {
				errors = append(errors, fmt.Errorf("failed to get value for %s: %w", key, err))
				continue
			}

			switch out := output.(type) {
			case string:
				val = out
				if val != "" && !slices.Contains(tmpContext[key], val) {
					tmpContext[key] = append(tmpContext[key], val)
				}
			case []string:
				for _, v := range out {
					if v != "" && !slices.Contains(tmpContext[key], v) {
						tmpContext[key] = append(tmpContext[key], v)
					}
				}
			case int:
				val = strconv.Itoa(out)
				if val != "" && !slices.Contains(tmpContext[key], val) {
					tmpContext[key] = append(tmpContext[key], val)
				}
			case []int:
				for _, v := range out {
					val = strconv.Itoa(v)
					if val != "" && !slices.Contains(tmpContext[key], val) {
						tmpContext[key] = append(tmpContext[key], val)
					}
				}
			default:
				r := reflect.ValueOf(output)
				if r.IsZero() || r.IsNil() {
					continue
				}
				val := fmt.Sprintf("%v", output)
				if val != "" && !slices.Contains(tmpContext[key], val) {
					tmpContext[key] = append(tmpContext[key], val)
				}
			}
		}
	}

	return errors
}

// Iterate over the individual appsec matched rules to create the needed alert context.
func AppsecEventToContext(event types.AppsecEvent, request *http.Request) (models.Meta, []error) {
	var errors []error

	tmpContext := make(map[string][]string)

	evt := types.MakeEvent(false, types.LOG, false)
	for _, matched_rule := range event.MatchedRules {
		tmpErrors := EvalAlertContextRules(evt, &matched_rule, request, tmpContext)
		errors = append(errors, tmpErrors...)
	}

	metas, truncErrors := TruncateContextMap(tmpContext, alertContext.ContextValueLen)
	errors = append(errors, truncErrors...)

	ret := models.Meta(metas)

	return ret, errors
}

// Iterate over the individual events to create the needed alert context.
func EventToContext(events []types.Event) (models.Meta, []error) {
	var errors []error

	tmpContext := make(map[string][]string)

	for i := range events {
		tmpErrors := EvalAlertContextRules(events[i], nil, nil, tmpContext)
		errors = append(errors, tmpErrors...)
	}

	metas, truncErrors := TruncateContextMap(tmpContext, alertContext.ContextValueLen)
	errors = append(errors, truncErrors...)

	ret := models.Meta(metas)

	return ret, errors
}
