package exprhelpers

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
)

type ExprCustomFunc struct {
	Name      string
	Function  func(params ...any) (any, error)
	Signature []interface{}
}

var exprFuncs = []ExprCustomFunc{
	{
		Name:     "CrowdsecCTI",
		Function: CrowdsecCTI,
		Signature: []interface{}{
			new(func(string) (*cticlient.SmokeItem, error)),
		},
	},
	{
		Name:      "Flatten",
		Function:  Flatten,
		Signature: []interface{}{},
	},
	{
		Name:      "Distinct",
		Function:  Distinct,
		Signature: []interface{}{},
	},
	{
		Name:      "FlattenDistinct",
		Function:  FlattenDistinct,
		Signature: []interface{}{},
	},
	{
		Name:     "Distance",
		Function: Distance,
		Signature: []interface{}{
			new(func(string, string, string, string) (float64, error)),
		},
	},
	{
		Name:     "GetFromStash",
		Function: GetFromStash,
		Signature: []interface{}{
			new(func(string, string) (string, error)),
		},
	},
	{
		Name:     "Atof",
		Function: Atof,
		Signature: []interface{}{
			new(func(string) float64),
		},
	},
	{
		Name:     "JsonExtract",
		Function: JsonExtract,
		Signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		Name:     "JsonExtractUnescape",
		Function: JsonExtractUnescape,
		Signature: []interface{}{
			new(func(string, ...string) string),
		},
	},
	{
		Name:     "JsonExtractLib",
		Function: JsonExtractLib,
		Signature: []interface{}{
			new(func(string, ...string) string),
		},
	},
	{
		Name:     "JsonExtractSlice",
		Function: JsonExtractSlice,
		Signature: []interface{}{
			new(func(string, string) []interface{}),
		},
	},
	{
		Name:     "JsonExtractObject",
		Function: JsonExtractObject,
		Signature: []interface{}{
			new(func(string, string) map[string]interface{}),
		},
	},
	{
		Name:     "ToJsonString",
		Function: ToJson,
		Signature: []interface{}{
			new(func(interface{}) string),
		},
	},
	{
		Name:     "File",
		Function: File,
		Signature: []interface{}{
			new(func(string) []string),
		},
	},
	{
		Name:     "RegexpInFile",
		Function: RegexpInFile,
		Signature: []interface{}{
			new(func(string, string) bool),
		},
	},
	{
		Name:     "Upper",
		Function: Upper,
		Signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		Name:     "Lower",
		Function: Lower,
		Signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		Name:     "IpInRange",
		Function: IpInRange,
		Signature: []interface{}{
			new(func(string, string) bool),
		},
	},
	{
		Name:     "TimeNow",
		Function: TimeNow,
		Signature: []interface{}{
			new(func() string),
		},
	},
	{
		Name:     "ParseUri",
		Function: ParseUri,
		Signature: []interface{}{
			new(func(string) map[string][]string),
		},
	},
	{
		Name:     "PathUnescape",
		Function: PathUnescape,
		Signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		Name:     "QueryUnescape",
		Function: QueryUnescape,
		Signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		Name:     "PathEscape",
		Function: PathEscape,
		Signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		Name:     "QueryEscape",
		Function: QueryEscape,
		Signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		Name:     "XMLGetAttributeValue",
		Function: XMLGetAttributeValue,
		Signature: []interface{}{
			new(func(string, string, string) string),
		},
	},
	{
		Name:     "XMLGetNodeValue",
		Function: XMLGetNodeValue,
		Signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		Name:     "IpToRange",
		Function: IpToRange,
		Signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		Name:     "IsIPV6",
		Function: IsIPV6,
		Signature: []interface{}{
			new(func(string) bool),
		},
	},
	{
		Name:     "IsIPV4",
		Function: IsIPV4,
		Signature: []interface{}{
			new(func(string) bool),
		},
	},
	{
		Name:     "IsIP",
		Function: IsIP,
		Signature: []interface{}{
			new(func(string) bool),
		},
	},
	{
		Name:     "LookupHost",
		Function: LookupHost,
		Signature: []interface{}{
			new(func(string) []string),
		},
	},
	{
		Name:     "GetDecisionsCount",
		Function: GetDecisionsCount,
		Signature: []interface{}{
			new(func(string) int),
		},
	},
	{
		Name:     "GetDecisionsSinceCount",
		Function: GetDecisionsSinceCount,
		Signature: []interface{}{
			new(func(string, string) int),
		},
	},
	{
		Name:     "Sprintf",
		Function: Sprintf,
		Signature: []interface{}{
			new(func(string, ...interface{}) string),
		},
	},
	{
		Name:     "ParseUnix",
		Function: ParseUnix,
		Signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		Name:     "SetInStash", //FIXME: signature will probably blow everything up
		Function: SetInStash,
		Signature: []interface{}{
			new(func(string, string, string, *time.Duration) error),
		},
	},
	{
		Name:     "Fields",
		Function: Fields,
		Signature: []interface{}{
			new(func(string) []string),
		},
	},
	{
		Name:     "Index",
		Function: Index,
		Signature: []interface{}{
			new(func(string, string) int),
		},
	},
	{
		Name:     "IndexAny",
		Function: IndexAny,
		Signature: []interface{}{
			new(func(string, string) int),
		},
	},
	{
		Name:     "Join",
		Function: Join,
		Signature: []interface{}{
			new(func([]string, string) string),
		},
	},
	{
		Name:     "Split",
		Function: Split,
		Signature: []interface{}{
			new(func(string, string) []string),
		},
	},
	{
		Name:     "SplitAfter",
		Function: SplitAfter,
		Signature: []interface{}{
			new(func(string, string) []string),
		},
	},
	{
		Name:     "SplitAfterN",
		Function: SplitAfterN,
		Signature: []interface{}{
			new(func(string, string, int) []string),
		},
	},
	{
		Name:     "SplitN",
		Function: SplitN,
		Signature: []interface{}{
			new(func(string, string, int) []string),
		},
	},
	{
		Name:     "Replace",
		Function: Replace,
		Signature: []interface{}{
			new(func(string, string, string, int) string),
		},
	},
	{
		Name:     "ReplaceAll",
		Function: ReplaceAll,
		Signature: []interface{}{
			new(func(string, string, string) string),
		},
	},
	{
		Name:     "Trim",
		Function: Trim,
		Signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		Name:     "TrimLeft",
		Function: TrimLeft,
		Signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		Name:     "TrimRight",
		Function: TrimRight,
		Signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		Name:     "TrimSpace",
		Function: TrimSpace,
		Signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		Name:     "TrimPrefix",
		Function: TrimPrefix,
		Signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		Name:     "TrimSuffix",
		Function: TrimSuffix,
		Signature: []interface{}{
			new(func(string, string) string),
		},
	},
	{
		Name:     "Get",
		Function: Get,
		Signature: []interface{}{
			new(func([]string, int) string),
		},
	},
	{
		Name:     "ToString",
		Function: ToString,
		Signature: []interface{}{
			new(func(interface{}) string),
		},
	},
	{
		Name:     "Match",
		Function: Match,
		Signature: []interface{}{
			new(func(string, string) bool),
		},
	},
	{
		Name:     "KeyExists",
		Function: KeyExists,
		Signature: []interface{}{
			new(func(string, map[string]any) bool),
		},
	},
	{
		Name:     "LogInfo",
		Function: LogInfo,
		Signature: []interface{}{
			new(func(string, ...interface{}) bool),
		},
	},
	{
		Name:     "B64Decode",
		Function: B64Decode,
		Signature: []interface{}{
			new(func(string) string),
		},
	},
	{
		Name:     "UnmarshalJSON",
		Function: UnmarshalJSON,
		Signature: []interface{}{
			new(func(string, map[string]interface{}, string) error),
		},
	},
	{
		Name:     "ParseKV",
		Function: ParseKV,
		Signature: []interface{}{
			new(func(string, map[string]interface{}, string) error),
		},
	},
	{
		Name:     "Hostname",
		Function: Hostname,
		Signature: []interface{}{
			new(func() (string, error)),
		},
	},
	{
		Name:     "FloatApproxEqual",
		Function: FloatApproxEqual,
		Signature: []interface{}{
			new(func(float64, float64) bool),
		},
	},
}

//go 1.20 "CutPrefix":              strings.CutPrefix,
//go 1.20 "CutSuffix": strings.CutSuffix,
//"Cut":         strings.Cut, -> returns more than 2 values, not supported  by expr
