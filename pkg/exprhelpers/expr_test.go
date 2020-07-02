package exprhelpers

import (
	"log"
	"testing"

	"github.com/antonmedv/expr"
	"github.com/stretchr/testify/require"
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

func TestIpRangeContains(t *testing.T) {
	env := map[string]interface{}{
		"ip":              "192.168.0.1",
		"ipRange":         "192.168.0.0/24",
		"IpRangeContains": IpRangeContains,
	}
	code := "IpRangeContains(ipRange, ip)"
	log.Printf("Running filter : %s", code)

	program, err := expr.Compile(code, expr.Env(env))
	require.NoError(t, err)

	output, err := expr.Run(program, env)
	require.NoError(t, err)

	require.Equal(t, true, output)

}
