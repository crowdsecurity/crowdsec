package exprhelpers

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
)

type exprCustomFunc struct {
	name      string
	function  func(params ...any) (any, error)
	signature []interface{}
}

var exprFuncs = []exprCustomFunc{
	{
		name:     "CrowdsecCTI",
		function: CrowdsecCTI,
		signature: []interface{}{
			new(func(string) (*cticlient.SmokeItem, error)),
		},
	},
	{
		name:      "Flatten",
		function:  Flatten,
		signature: []interface{}{},
	},
	{
		name:      "Distinct",
		function:  Distinct,
		signature: []interface{}{},
	},
	{
		name:      "FlattenDistinct",
		function:  FlattenDistinct,
		signature: []interface{}{},
	},
	{
		name:     "Distance",
		function: Distance,
		signature: []interface{}{
			new(func(string, string, string, string) (float64, error)),
		},
	},
	{
		name:     "GetFromStash",
		function: GetFromStash,
		signature: []interface{}{
			new(func(string, string) (string, error)),
		},
	},
	{
		name:     "Atof",
		function: Atof,
		signature: []interface{}{
			new(func(string) float64),
		},
	},
	{
		name:     "JsonExtract",
		function: JsonExtract,
		signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		name:     "JsonExtractUnescape",
		function: JsonExtractUnescape,
		signature: []interface{}{
			new(func(string, ...string) string),
		},
	},
	{
		name:     "JsonExtractLib",
		function: JsonExtractLib,
		signature: []interface{}{
			new(func(string, ...string) string),
		},
	},
	{
		name:     "JsonExtractSlice",
		function: JsonExtractSlice,
		signature: []interface{}{
			new(func(string, string) []interface{}),
		},
	},
	{
		name:     "JsonExtractObject",
		function: JsonExtractObject,
		signature: []interface{}{
			new(func(string, string) map[string]interface{}),
		},
	},
	{
		name:     "ToJsonString",
		function: ToJson,
		signature: []interface{}{
			new(func(interface{}) string),
		},
	},
	{
		name:     "File",
		function: File,
		signature: []interface{}{
			new(func(string) []string),
		},
	},
	{
		name:     "RegexpInFile",
		function: RegexpInFile,
		signature: []interface{}{
			new(func(string, string) bool),
		},
	},
	{
		name:     "Upper",
		function: Upper,
		signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		name:     "Lower",
		function: Lower,
		signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		name:     "IpInRange",
		function: IpInRange,
		signature: []interface{}{
			new(func(string, string) bool),
		},
	},
	{
		name:     "TimeNow",
		function: TimeNow,
		signature: []interface{}{
			new(func() string),
		},
	},
	{
		name:     "ParseUri",
		function: ParseUri,
		signature: []interface{}{
			new(func(string) map[string][]string),
		},
	},
	{
		name:     "PathUnescape",
		function: PathUnescape,
		signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		name:     "QueryUnescape",
		function: QueryUnescape,
		signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		name:     "PathEscape",
		function: PathEscape,
		signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		name:     "QueryEscape",
		function: QueryEscape,
		signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		name:     "XMLGetAttributeValue",
		function: XMLGetAttributeValue,
		signature: []interface{}{
			new(func(string, string, string) string),
		},
	},
	{
		name:     "XMLGetNodeValue",
		function: XMLGetNodeValue,
		signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		name:     "IpToRange",
		function: IpToRange,
		signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		name:     "IsIPV6",
		function: IsIPV6,
		signature: []interface{}{
			new(func(string) bool),
		},
	},
	{
		name:     "IsIPV4",
		function: IsIPV4,
		signature: []interface{}{
			new(func(string) bool),
		},
	},
	{
		name:     "IsIP",
		function: IsIP,
		signature: []interface{}{
			new(func(string) bool),
		},
	},
	{
		name:     "LookupHost",
		function: LookupHost,
		signature: []interface{}{
			new(func(string) []string),
		},
	},
	{
		name:     "GetDecisionsCount",
		function: GetDecisionsCount,
		signature: []interface{}{
			new(func(string) int),
		},
	},
	{
		name:     "GetDecisionsSinceCount",
		function: GetDecisionsSinceCount,
		signature: []interface{}{
			new(func(string, string) int),
		},
	},
	{
		name:     "Sprintf",
		function: Sprintf,
		signature: []interface{}{
			new(func(string, ...interface{}) string),
		},
	},
	{
		name:     "ParseUnix",
		function: ParseUnix,
		signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		name:     "SetInStash", //FIXME: signature will probably blow everything up
		function: SetInStash,
		signature: []interface{}{
			new(func(string, string, string, *time.Duration) error),
		},
	},
	{
		name:     "Fields",
		function: Fields,
		signature: []interface{}{
			new(func(string) []string),
		},
	},
	{
		name:     "Index",
		function: Index,
		signature: []interface{}{
			new(func(string, string) int),
		},
	},
	{
		name:     "IndexAny",
		function: IndexAny,
		signature: []interface{}{
			new(func(string, string) int),
		},
	},
	{
		name:     "Join",
		function: Join,
		signature: []interface{}{
			new(func([]string, string) string),
		},
	},
	{
		name:     "Split",
		function: Split,
		signature: []interface{}{
			new(func(string, string) []string),
		},
	},
	{
		name:     "SplitAfter",
		function: SplitAfter,
		signature: []interface{}{
			new(func(string, string) []string),
		},
	},
	{
		name:     "SplitAfterN",
		function: SplitAfterN,
		signature: []interface{}{
			new(func(string, string, int) []string),
		},
	},
	{
		name:     "SplitN",
		function: SplitN,
		signature: []interface{}{
			new(func(string, string, int) []string),
		},
	},
	{
		name:     "Replace",
		function: Replace,
		signature: []interface{}{
			new(func(string, string, string, int) string),
		},
	},
	{
		name:     "ReplaceAll",
		function: ReplaceAll,
		signature: []interface{}{
			new(func(string, string, string) string),
		},
	},
	{
		name:     "Trim",
		function: Trim,
		signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		name:     "TrimLeft",
		function: TrimLeft,
		signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		name:     "TrimRight",
		function: TrimRight,
		signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		name:     "TrimSpace",
		function: TrimSpace,
		signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		name:     "TrimPrefix",
		function: TrimPrefix,
		signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		name:     "TrimSuffix",
		function: TrimSuffix,
		signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		name:     "Get",
		function: Get,
		signature: []interface{}{
			new(func([]string, int) string),
		},
	},
	{
		name:     "ToString",
		function: ToString,
		signature: []interface{}{
			new(func(interface{}) string),
		},
	},
	{
		name:     "Match",
		function: Match,
		signature: []interface{}{
			new(func(string, string) bool),
		},
	},
	{
		name:     "KeyExists",
		function: KeyExists,
		signature: []interface{}{
			new(func(string, map[string]any) bool),
		},
	},
	{
		name:     "LogInfo",
		function: LogInfo,
		signature: []interface{}{
			new(func(string, ...interface{}) bool),
		},
	},
	{
		name:     "B64Decode",
		function: B64Decode,
		signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		name:     "UnmarshalJSON",
		function: UnmarshalJSON,
		signature: []interface{}{
			new(func(string, map[string]interface{}, string) error),
		},
	},
	{
		name:     "ParseKV",
		function: ParseKV,
		signature: []interface{}{
			new(func(string, map[string]interface{}, string) error),
		},
	},
	{
		name:     "Hostname",
		function: Hostname,
		signature: []interface{}{
			new(func() (string, error)),
		},
	},
	{
		name:     "FloatApproxEqual",
		function: FloatApproxEqual,
		signature: []interface{}{
			new(func(float64, float64) bool),
		},
	},
}

//go 1.20 "CutPrefix":              strings.CutPrefix,
//go 1.20 "CutSuffix": strings.CutSuffix,
//"Cut":         strings.Cut, -> returns more than 2 values, not supported  by expr
