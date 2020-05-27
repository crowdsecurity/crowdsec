package exprhelpers

import (
	"log"
	"testing"

	"github.com/antonmedv/expr"
	"gotest.tools/assert"
)

var (
	TestFolder = "tests"
)

func TestRegexpInFile(t *testing.T) {
	if err := Init(); err != nil {
		log.Fatalf(err.Error())
	}

	err := FileInit(TestFolder, "test_data_re.txt", "regex")
	if err != nil {
		log.Fatalf(err.Error())
	}

	tests := []struct {
		filter string
		result bool
		err    error
	}{
		{
			filter: "RegexpInFile('crowdsec', 'test_data_re.txt')",
			result: false,
			err:    nil,
		},
		{
			filter: "RegexpInFile('Crowdsec', 'test_data_re.txt')",
			result: true,
			err:    nil,
		},
		{
			filter: "RegexpInFile('test Crowdsec', 'test_data_re.txt')",
			result: true,
			err:    nil,
		},
		{
			filter: "RegexpInFile('test CrowdSec', 'test_data_re.txt')",
			result: true,
			err:    nil,
		},
	}

	for _, test := range tests {
		compiledFilter, err := expr.Compile(test.filter, expr.Env(GetExprEnv(map[string]interface{}{})))
		if err != nil {
			log.Fatalf(err.Error())
		}
		log.Printf("Running filter : %s", test.filter)
		result, err := expr.Run(compiledFilter, GetExprEnv(map[string]interface{}{}))
		if err != nil {
			log.Fatalf(err.Error())
		}
		assert.Equal(t, test.result, result)
	}
}

func TestFile(t *testing.T) {
	if err := Init(); err != nil {
		log.Fatalf(err.Error())
	}

	err := FileInit(TestFolder, "test_data.txt", "")
	if err != nil {
		log.Fatalf(err.Error())
	}

	tests := []struct {
		filter string
		result bool
		err    error
	}{
		{
			filter: "'Crowdsec' in File('test_data.txt')",
			result: true,
			err:    nil,
		},
		{
			filter: "'CrowdSecurity' in File('test_data.txt')",
			result: false,
			err:    nil,
		},
		{
			filter: "'Crowdsecurity' in File('test_data.txt')",
			result: true,
			err:    nil,
		},
		{
			filter: "'test' in File('test_data.txt')",
			result: false,
			err:    nil,
		},
	}

	for _, test := range tests {
		compiledFilter, err := expr.Compile(test.filter, expr.Env(GetExprEnv(map[string]interface{}{})))
		if err != nil {
			log.Fatalf(err.Error())
		}
		log.Printf("Running filter : %s", test.filter)
		result, err := expr.Run(compiledFilter, GetExprEnv(map[string]interface{}{}))
		if err != nil {
			log.Fatalf(err.Error())
		}
		assert.Equal(t, test.result, result)
	}
}
