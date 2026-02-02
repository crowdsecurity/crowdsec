package exprhelpers

import (
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/oschwald/geoip2-golang"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
	"github.com/crowdsecurity/crowdsec/pkg/cticlient/ctiexpr"
)

type exprCustomFunc struct {
	name      string
	function  func(params ...any) (any, error)
	signature []any
}

var exprFuncs = []exprCustomFunc{
	{
		name:     "CrowdsecCTI",
		function: ctiexpr.CrowdsecCTI,
		signature: []any{
			new(func(string) (*cticlient.SmokeItem, error)),
		},
	},
	{
		name:      "Flatten",
		function:  Flatten,
		signature: []any{},
	},
	{
		name:      "Distinct",
		function:  Distinct,
		signature: []any{},
	},
	{
		name:      "FlattenDistinct",
		function:  FlattenDistinct,
		signature: []any{},
	},
	{
		name:     "Distance",
		function: Distance,
		signature: []any{
			new(func(string, string, string, string) (float64, error)),
		},
	},
	{
		name:     "GetFromStash",
		function: GetFromStash,
		signature: []any{
			new(func(string, string) (string, error)),
		},
	},
	{
		name:     "Atof",
		function: Atof,
		signature: []any{
			new(func(string) float64),
		},
	},
	{
		name:     "JsonExtract",
		function: JsonExtract,
		signature: []any{
			new(func(string, string) string),
		},
	},
	{
		name:     "JsonExtractUnescape",
		function: JsonExtractUnescape,
		signature: []any{
			new(func(string, ...string) string),
		},
	},
	{
		name:     "JsonExtractLib",
		function: JsonExtractLib,
		signature: []any{
			new(func(string, ...string) string),
		},
	},
	{
		name:     "JsonExtractSlice",
		function: JsonExtractSlice,
		signature: []any{
			new(func(string, string) []any),
		},
	},
	{
		name:     "JsonExtractObject",
		function: JsonExtractObject,
		signature: []any{
			new(func(string, string) map[string]any),
		},
	},
	{
		name:     "ToJsonString",
		function: ToJson,
		signature: []any{
			new(func(any) string),
		},
	},
	{
		name:     "File",
		function: File,
		signature: []any{
			new(func(string) []string),
		},
	},
	{
		name:     "RegexpInFile",
		function: RegexpInFile,
		signature: []any{
			new(func(string, string) bool),
		},
	},
	{
		name:     "Upper",
		function: Upper,
		signature: []any{
			new(func(string) string),
		},
	},
	{
		name:     "Lower",
		function: Lower,
		signature: []any{
			new(func(string) string),
		},
	},
	{
		name:     "IpInRange",
		function: IpInRange,
		signature: []any{
			new(func(string, string) bool),
		},
	},
	{
		name:     "TimeNow",
		function: TimeNow,
		signature: []any{
			new(func() string),
		},
	},
	{
		name:     "ParseUri",
		function: ParseUri,
		signature: []any{
			new(func(string) map[string][]string),
		},
	},
	{
		name:     "ParseQuery",
		function: ExprWrapParseQuery,
		signature: []any{
			new(func(string) url.Values),
		},
	},
	{
		name:     "ExtractQueryParam",
		function: ExprWrapExtractQueryParam,
		signature: []any{
			new(func(string, string) []string),
		},
	},
	{
		name:     "PathUnescape",
		function: PathUnescape,
		signature: []any{
			new(func(string) string),
		},
	},
	{
		name:     "QueryUnescape",
		function: QueryUnescape,
		signature: []any{
			new(func(string) string),
		},
	},
	{
		name:     "PathEscape",
		function: PathEscape,
		signature: []any{
			new(func(string) string),
		},
	},
	{
		name:     "QueryEscape",
		function: QueryEscape,
		signature: []any{
			new(func(string) string),
		},
	},
	{
		name:     "XMLGetAttributeValue",
		function: XMLGetAttributeValue,
		signature: []any{
			new(func(string, string, string) string),
		},
	},
	{
		name:     "XMLGetNodeValue",
		function: XMLGetNodeValue,
		signature: []any{
			new(func(string, string) string),
		},
	},
	{
		name:     "IpToRange",
		function: IpToRange,
		signature: []any{
			new(func(string, string) string),
		},
	},
	{
		name:     "IsIPV6",
		function: IsIPV6,
		signature: []any{
			new(func(string) bool),
		},
	},
	{
		name:     "IsIPV4",
		function: IsIPV4,
		signature: []any{
			new(func(string) bool),
		},
	},
	{
		name:     "IsIP",
		function: IsIP,
		signature: []any{
			new(func(string) bool),
		},
	},
	{
		name:     "LookupHost",
		function: LookupHost,
		signature: []any{
			new(func(string) []string),
		},
	},
	{
		name:     "GetDecisionsCount",
		function: GetDecisionsCount,
		signature: []any{
			new(func(string) int),
		},
	},
	{
		name:     "GetActiveDecisionsCount",
		function: GetActiveDecisionsCount,
		signature: []any{
			new(func(string) int),
		},
	},
	{
		name:     "GetActiveDecisionsTimeLeft",
		function: GetActiveDecisionsTimeLeft,
		signature: []any{
			new(func(string) time.Duration),
		},
	},
	{
		name:     "GetDecisionsSinceCount",
		function: GetDecisionsSinceCount,
		signature: []any{
			new(func(string, string) int),
		},
	},
	{
		name:     "Sprintf",
		function: Sprintf,
		signature: []any{
			new(func(string, ...any) string),
		},
	},
	{
		name:     "ParseUnix",
		function: ParseUnix,
		signature: []any{
			new(func(string) string),
		},
	},
	{
		name:     "SetInStash", // FIXME: signature will probably blow everything up
		function: SetInStash,
		signature: []any{
			new(func(string, string, string, *time.Duration) error),
		},
	},
	{
		name:     "Fields",
		function: Fields,
		signature: []any{
			new(func(string) []string),
		},
	},
	{
		name:     "Index",
		function: Index,
		signature: []any{
			new(func(string, string) int),
		},
	},
	{
		name:     "IndexAny",
		function: IndexAny,
		signature: []any{
			new(func(string, string) int),
		},
	},
	{
		name:     "Join",
		function: Join,
		signature: []any{
			new(func([]string, string) string),
		},
	},
	{
		name:     "Split",
		function: Split,
		signature: []any{
			new(func(string, string) []string),
		},
	},
	{
		name:     "SplitAfter",
		function: SplitAfter,
		signature: []any{
			new(func(string, string) []string),
		},
	},
	{
		name:     "SplitAfterN",
		function: SplitAfterN,
		signature: []any{
			new(func(string, string, int) []string),
		},
	},
	{
		name:     "SplitN",
		function: SplitN,
		signature: []any{
			new(func(string, string, int) []string),
		},
	},
	{
		name:     "Replace",
		function: Replace,
		signature: []any{
			new(func(string, string, string, int) string),
		},
	},
	{
		name:     "ReplaceAll",
		function: ReplaceAll,
		signature: []any{
			new(func(string, string, string) string),
		},
	},
	{
		name:     "Trim",
		function: Trim,
		signature: []any{
			new(func(string, string) string),
		},
	},
	{
		name:     "TrimLeft",
		function: TrimLeft,
		signature: []any{
			new(func(string, string) string),
		},
	},
	{
		name:     "TrimRight",
		function: TrimRight,
		signature: []any{
			new(func(string, string) string),
		},
	},
	{
		name:     "TrimSpace",
		function: TrimSpace,
		signature: []any{
			new(func(string) string),
		},
	},
	{
		name:     "TrimPrefix",
		function: TrimPrefix,
		signature: []any{
			new(func(string, string) string),
		},
	},
	{
		name:     "TrimSuffix",
		function: TrimSuffix,
		signature: []any{
			new(func(string, string) string),
		},
	},
	{
		name:     "Get",
		function: Get,
		signature: []any{
			new(func([]string, int) string),
		},
	},
	{
		name:     "ToString",
		function: ToString,
		signature: []any{
			new(func(any) string),
		},
	},
	{
		name:     "Match",
		function: Match,
		signature: []any{
			new(func(string, string) bool),
		},
	},
	{
		name:     "KeyExists",
		function: KeyExists,
		signature: []any{
			new(func(string, map[string]any) bool),
		},
	},
	{
		name:     "LogInfo",
		function: LogInfo,
		signature: []any{
			new(func(string, ...any) bool),
		},
	},
	{
		name:     "B64Decode",
		function: B64Decode,
		signature: []any{
			new(func(string) string),
		},
	},
	{
		name:     "UnmarshalJSON",
		function: UnmarshalJSON,
		signature: []any{
			new(func(string, map[string]any, string) error),
		},
	},
	{
		name:     "ParseKV",
		function: ParseKV,
		signature: []any{
			new(func(string, map[string]any, string) error),
		},
	},
	{
		name:     "ParseKVLax",
		function: ParseKVLax,
		signature: []any{
			new(func(string, map[string]any, string) error),
		},
	},
	{
		name:     "Hostname",
		function: Hostname,
		signature: []any{
			new(func() (string, error)),
		},
	},
	{
		name:     "FloatApproxEqual",
		function: FloatApproxEqual,
		signature: []any{
			new(func(float64, float64) bool),
		},
	},
	{
		name:     "LibInjectionIsSQLI",
		function: LibInjectionIsSQLI,
		signature: []any{
			new(func(string) bool),
		},
	},
	{
		name:     "LibInjectionIsXSS",
		function: LibInjectionIsXSS,
		signature: []any{
			new(func(string) bool),
		},
	},
	{
		name:     "GeoIPEnrich",
		function: GeoIPEnrich,
		signature: []any{
			new(func(string) *geoip2.City),
		},
	},
	{
		name:     "GeoIPASNEnrich",
		function: GeoIPASNEnrich,
		signature: []any{
			new(func(string) *geoip2.ASN),
		},
	},
	{
		name:     "GeoIPRangeEnrich",
		function: GeoIPRangeEnrich,
		signature: []any{
			new(func(string) *net.IPNet),
		},
	},
	{
		name:     "IsAnomalous",
		function: IsAnomalous,
		signature: []interface{}{
			new(func(string, string) (bool, error)),
		},
	},
	{
		name:     "JA4H",
		function: JA4H,
		signature: []any{
			new(func(*http.Request) string),
		},
	},
	{
		name:     "AverageInterval",
		function: AverageInterval,
		signature: []any{
			new(func([]time.Time) time.Duration),
			new(func([]interface{}) time.Duration),
		},
	},
	{
		name:     "MedianInterval",
		function: MedianInterval,
		signature: []any{
			new(func([]time.Time) time.Duration),
			new(func([]interface{}) time.Duration),
		},
	},
}

//go 1.20 "CutPrefix": strings.CutPrefix,
//go 1.20 "CutSuffix": strings.CutSuffix,
//"Cut":         strings.Cut, -> returns more than 2 values, not supported  by expr
