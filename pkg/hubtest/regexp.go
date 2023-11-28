package hubtest

import (
	"regexp"
)

var (
	variableRE = regexp.MustCompile(`(?P<variable>[^  =]+) == .*`)
	parserResultRE = regexp.MustCompile(`^results\["[^"]+"\]\["(?P<parser>[^"]+)"\]\[[0-9]+\]\.Evt\..*`)
	scenarioResultRE = regexp.MustCompile(`^results\[[0-9]+\].Overflow.Alert.GetScenario\(\) == "(?P<scenario>[^"]+)"`)
)
