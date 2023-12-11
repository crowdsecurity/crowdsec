package appsecacquisition

import (
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/crowdsecurity/coraza/v3/experimental/plugins"
	"github.com/crowdsecurity/coraza/v3/experimental/plugins/plugintypes"
	"github.com/wasilibs/go-re2"
	"github.com/wasilibs/go-re2/experimental"
)

type rx struct {
	re *re2.Regexp
}

var _ plugintypes.Operator = (*rx)(nil)

func newRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	// (?sm) enables multiline mode which makes 942522-7 work, see
	// - https://stackoverflow.com/a/27680233
	// - https://groups.google.com/g/golang-nuts/c/jiVdamGFU9E
	data := fmt.Sprintf("(?sm)%s", options.Arguments)

	var re *re2.Regexp
	var err error

	if matchesArbitraryBytes(data) {
		re, err = experimental.CompileLatin1(data)
	} else {
		re, err = re2.Compile(data)
	}
	if err != nil {
		return nil, err
	}
	return &rx{re: re}, nil
}

func (o *rx) Evaluate(tx plugintypes.TransactionState, value string) bool {
	if tx.Capturing() {
		match := o.re.FindStringSubmatch(value)
		if len(match) == 0 {
			return false
		}
		for i, c := range match {
			if i == 9 {
				return true
			}
			tx.CaptureField(i, c)
		}
		return true
	} else {
		return o.re.MatchString(value)
	}
}

// RegisterRX registers the rx operator using a WASI implementation instead of Go.
func RegisterRX() {
	plugins.RegisterOperator("rx", newRX)
}

// matchesArbitraryBytes checks for control sequences for byte matches in the expression.
// If the sequences are not valid utf8, it returns true.
func matchesArbitraryBytes(expr string) bool {
	decoded := make([]byte, 0, len(expr))
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c != '\\' {
			decoded = append(decoded, c)
			continue
		}
		if i+3 >= len(expr) {
			decoded = append(decoded, expr[i:]...)
			break
		}
		if expr[i+1] != 'x' {
			decoded = append(decoded, expr[i])
			continue
		}

		v, mb, _, err := strconv.UnquoteChar(expr[i:], 0)
		if err != nil || mb {
			// Wasn't a byte escape sequence, shouldn't happen in practice.
			decoded = append(decoded, expr[i])
			continue
		}

		decoded = append(decoded, byte(v))
		i += 3
	}

	return !utf8.Valid(decoded)
}
