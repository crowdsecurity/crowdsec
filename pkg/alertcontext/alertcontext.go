package alertcontext

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	maxContextValueLen = 4000
)

var (
	alertContext = Context{}
)

type Context struct {
	ContextToSend         map[string][]string
	ContextValueLen       int
	ContextToSendCompiled map[string][]*vm.Program
	Log                   *log.Logger
}

func ValidateContextExpr(key string, expressions []string) error {
	for _, expression := range expressions {
		_, err := expr.Compile(expression, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
		if err != nil {
			return fmt.Errorf("compilation of '%s' failed: %v", expression, err)
		}
	}
	return nil
}

func NewAlertContext(contextToSend map[string][]string, valueLength int) error {
	var clog = log.New()
	if err := types.ConfigureLogger(clog); err != nil {
		return fmt.Errorf("couldn't create logger for alert context: %s", err)
	}

	if valueLength == 0 {
		clog.Debugf("No console context value length provided, using default: %d", maxContextValueLen)
		valueLength = maxContextValueLen
	}
	if valueLength > maxContextValueLen {
		clog.Debugf("Provided console context value length (%d) is higher than the maximum, using default: %d", valueLength, maxContextValueLen)
		valueLength = maxContextValueLen
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
			valueCompiled, err := expr.Compile(value, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
			if err != nil {
				return fmt.Errorf("compilation of '%s' context value failed: %v", value, err)
			}
			alertContext.ContextToSendCompiled[key] = append(alertContext.ContextToSendCompiled[key], valueCompiled)
			alertContext.ContextToSend[key] = append(alertContext.ContextToSend[key], value)
		}
	}

	return nil
}

func truncate(values []string, contextValueLen int) (string, error) {
	var ret string
	valueByte, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("unable to dump metas: %s", err)
	}
	ret = string(valueByte)
	for {
		if len(ret) <= contextValueLen {
			break
		}
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
			return "", fmt.Errorf("unable to dump metas: %s", err)
		}
		ret = string(valueByte)
	}
	return ret, nil
}

func EventToContext(events []types.Event) (models.Meta, []error) {
	var errors []error

	metas := make([]*models.MetaItems0, 0)
	tmpContext := make(map[string][]string)
	for _, evt := range events {
		for key, values := range alertContext.ContextToSendCompiled {
			if _, ok := tmpContext[key]; !ok {
				tmpContext[key] = make([]string, 0)
			}
			for _, value := range values {
				var val string
				output, err := expr.Run(value, map[string]interface{}{"evt": evt})
				if err != nil {
					errors = append(errors, fmt.Errorf("failed to get value for %s : %v", key, err))
					continue
				}
				switch out := output.(type) {
				case string:
					val = out
				case int:
					val = strconv.Itoa(out)
				default:
					errors = append(errors, fmt.Errorf("unexpected return type for %s : %T", key, output))
					continue
				}
				if val != "" && !slices.Contains(tmpContext[key], val) {
					tmpContext[key] = append(tmpContext[key], val)
				}
			}
		}
	}
	for key, values := range tmpContext {
		if len(values) == 0 {
			continue
		}
		valueStr, err := truncate(values, alertContext.ContextValueLen)
		if err != nil {
			log.Warningf(err.Error())
		}
		meta := models.MetaItems0{
			Key:   key,
			Value: valueStr,
		}
		metas = append(metas, &meta)
	}

	ret := models.Meta(metas)
	return ret, errors
}
