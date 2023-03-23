package exprhelpers

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bluele/gcache"
	"github.com/c-robinson/iplib"
	"github.com/cespare/xxhash/v2"
	"github.com/davecgh/go-spew/spew"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/umahmood/haversine"

	"github.com/crowdsecurity/crowdsec/pkg/cache"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/types"

	"github.com/wasilibs/go-re2"
)

var dataFile map[string][]string
var dataFileRegex map[string][]*regexp.Regexp
var dataFileRe2 map[string][]*re2.Regexp

// This is used to (optionally) cache regexp results for RegexpInFile operations
var dataFileRegexCache map[string]gcache.Cache = make(map[string]gcache.Cache)

/*prometheus*/
var RegexpCacheMetrics = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cs_regexp_cache_size",
		Help: "Entries per regexp cache.",
	},
	[]string{"name"},
)

var dbClient *database.Client

func Get(arr []string, index int) string {
	if index >= len(arr) {
		return ""
	}
	return arr[index]
}

func Atof(x string) float64 {
	log.Debugf("debug atof %s", x)
	ret, err := strconv.ParseFloat(x, 64)
	if err != nil {
		log.Warningf("Atof : can't convert float '%s' : %v", x, err)
	}
	return ret
}

func Upper(s string) string {
	return strings.ToUpper(s)
}

func Lower(s string) string {
	return strings.ToLower(s)
}

func GetExprEnv(ctx map[string]interface{}) map[string]interface{} {
	var ExprLib = map[string]interface{}{
		"Atof":                   Atof,
		"JsonExtract":            JsonExtract,
		"JsonExtractUnescape":    JsonExtractUnescape,
		"JsonExtractLib":         JsonExtractLib,
		"JsonExtractSlice":       JsonExtractSlice,
		"JsonExtractObject":      JsonExtractObject,
		"ToJsonString":           ToJson,
		"File":                   File,
		"RegexpInFile":           RegexpInFile,
		"Upper":                  Upper,
		"Lower":                  Lower,
		"IpInRange":              IpInRange,
		"TimeNow":                TimeNow,
		"ParseUri":               ParseUri,
		"PathUnescape":           PathUnescape,
		"QueryUnescape":          QueryUnescape,
		"PathEscape":             PathEscape,
		"QueryEscape":            QueryEscape,
		"XMLGetAttributeValue":   XMLGetAttributeValue,
		"XMLGetNodeValue":        XMLGetNodeValue,
		"IpToRange":              IpToRange,
		"IsIPV6":                 IsIPV6,
		"IsIPV4":                 IsIPV4,
		"IsIP":                   IsIP,
		"LookupHost":             LookupHost,
		"GetDecisionsCount":      GetDecisionsCount,
		"GetDecisionsSinceCount": GetDecisionsSinceCount,
		"Sprintf":                fmt.Sprintf,
		"CrowdsecCTI":            CrowdsecCTI,
		"ParseUnix":              ParseUnix,
		"GetFromStash":           cache.GetKey,
		"SetInStash":             cache.SetKey,
		//go 1.20 "CutPrefix":              strings.CutPrefix,
		//go 1.20 "CutSuffix": strings.CutSuffix,
		//"Cut":         strings.Cut, -> returns more than 2 values, not supported  by expr
		"Fields":      strings.Fields,
		"Index":       strings.Index,
		"IndexAny":    strings.IndexAny,
		"Join":        strings.Join,
		"Split":       strings.Split,
		"SplitAfter":  strings.SplitAfter,
		"SplitAfterN": strings.SplitAfterN,
		"SplitN":      strings.SplitN,
		"Replace":     strings.Replace,
		"ReplaceAll":  strings.ReplaceAll,
		"Trim":        strings.Trim,
		"TrimLeft":    strings.TrimLeft,
		"TrimRight":   strings.TrimRight,
		"TrimSpace":   strings.TrimSpace,
		"TrimPrefix":  strings.TrimPrefix,
		"TrimSuffix":  strings.TrimSuffix,
		"Get":         Get,
		"String":      ToString,
		"Distance":    Distance,
		"Match":       Match,
	}
	for k, v := range ctx {
		ExprLib[k] = v
	}
	return ExprLib
}

func Distance(lat1 string, long1 string, lat2 string, long2 string) (float64, error) {
	lat1f, err := strconv.ParseFloat(lat1, 64)
	if err != nil {
		log.Warningf("lat1 is not a float : %v", err)
		return 0, fmt.Errorf("lat1 is not a float : %v", err)
	}
	long1f, err := strconv.ParseFloat(long1, 64)
	if err != nil {
		log.Warningf("long1 is not a float : %v", err)
		return 0, fmt.Errorf("long1 is not a float : %v", err)
	}
	lat2f, err := strconv.ParseFloat(lat2, 64)
	if err != nil {
		log.Warningf("lat2 is not a float : %v", err)

		return 0, fmt.Errorf("lat2 is not a float : %v", err)
	}
	long2f, err := strconv.ParseFloat(long2, 64)
	if err != nil {
		log.Warningf("long2 is not a float : %v", err)

		return 0, fmt.Errorf("long2 is not a float : %v", err)
	}

	//either set of coordinates is 0,0, return 0 to avoid FPs
	if (lat1f == 0.0 && long1f == 0.0) || (lat2f == 0.0 && long2f == 0.0) {
		log.Warningf("one of the coordinates is 0,0, returning 0")
		return 0, nil
	}

	first := haversine.Coord{Lat: lat1f, Lon: long1f}
	second := haversine.Coord{Lat: lat2f, Lon: long2f}

	_, km := haversine.Distance(first, second)
	return km, nil
}

func Init(databaseClient *database.Client) error {
	dataFile = make(map[string][]string)
	dataFileRegex = make(map[string][]*regexp.Regexp)
	dataFileRe2 = make(map[string][]*re2.Regexp)
	dbClient = databaseClient
	return nil
}

func RegexpCacheInit(filename string, CacheCfg types.DataSource) error {

	//cache is explicitly disabled
	if CacheCfg.Cache != nil && !*CacheCfg.Cache {
		return nil
	}
	//cache is implicitly disabled if no cache config is provided
	if CacheCfg.Strategy == nil && CacheCfg.TTL == nil && CacheCfg.Size == nil {
		return nil
	}
	//cache is enabled

	if CacheCfg.Size == nil {
		CacheCfg.Size = types.IntPtr(50)
	}

	gc := gcache.New(*CacheCfg.Size)

	if CacheCfg.Strategy == nil {
		CacheCfg.Strategy = types.StrPtr("LRU")
	}
	switch *CacheCfg.Strategy {
	case "LRU":
		gc = gc.LRU()
	case "LFU":
		gc = gc.LFU()
	case "ARC":
		gc = gc.ARC()
	default:
		return fmt.Errorf("unknown cache strategy '%s'", *CacheCfg.Strategy)
	}

	if CacheCfg.TTL != nil {
		gc.Expiration(*CacheCfg.TTL)
	}
	cache := gc.Build()
	dataFileRegexCache[filename] = cache
	return nil
}

// UpdateCacheMetrics is called directly by the prom handler
func UpdateRegexpCacheMetrics() {
	RegexpCacheMetrics.Reset()
	for name := range dataFileRegexCache {
		RegexpCacheMetrics.With(prometheus.Labels{"name": name}).Set(float64(dataFileRegexCache[name].Len(true)))
	}
}

func FileInit(fileFolder string, filename string, fileType string) error {
	log.Debugf("init (folder:%s) (file:%s) (type:%s)", fileFolder, filename, fileType)
	filepath := path.Join(fileFolder, filename)
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	if fileType == "" {
		log.Debugf("ignored file %s%s because no type specified", fileFolder, filename)
		return nil
	}
	if _, ok := dataFile[filename]; !ok {
		dataFile[filename] = []string{}
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "#") { // allow comments
			continue
		}
		if len(scanner.Text()) == 0 { //skip empty lines
			continue
		}
		switch fileType {
		case "regex", "regexp":
			if fflag.Re2ExprHelperSupport.IsEnabled() {
				dataFileRe2[filename] = append(dataFileRe2[filename], re2.MustCompile(scanner.Text()))
			} else {
				dataFileRegex[filename] = append(dataFileRegex[filename], regexp.MustCompile(scanner.Text()))
			}
		case "string":
			dataFile[filename] = append(dataFile[filename], scanner.Text())
		default:
			return fmt.Errorf("unknown data type '%s' for : '%s'", fileType, filename)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func QueryEscape(s string) string {
	return url.QueryEscape(s)
}

func PathEscape(s string) string {
	return url.PathEscape(s)
}

func PathUnescape(s string) string {
	ret, err := url.PathUnescape(s)
	if err != nil {
		log.Debugf("unable to PathUnescape '%s': %+v", s, err)
		return s
	}
	return ret
}

func QueryUnescape(s string) string {
	ret, err := url.QueryUnescape(s)
	if err != nil {
		log.Debugf("unable to QueryUnescape '%s': %+v", s, err)
		return s
	}
	return ret
}

func File(filename string) []string {
	if _, ok := dataFile[filename]; ok {
		return dataFile[filename]
	}
	log.Errorf("file '%s' (type:string) not found in expr library", filename)
	log.Errorf("expr library : %s", spew.Sdump(dataFile))
	return []string{}
}

func RegexpInFile(data string, filename string) bool {

	var hash uint64
	hasCache := false

	if _, ok := dataFileRegexCache[filename]; ok {
		hasCache = true
		hash = xxhash.Sum64String(data)
		if val, err := dataFileRegexCache[filename].Get(hash); err == nil {
			return val.(bool)
		}
	}

	if _, ok := dataFileRegex[filename]; ok {
		switch fflag.Re2ExprHelperSupport.IsEnabled() {
		case true:
			for _, re := range dataFileRe2[filename] {
				if re.MatchString(data) {
					if hasCache {
						dataFileRegexCache[filename].Set(hash, true)
					}
					return true
				}
			}
		case false:
			for _, re := range dataFileRegex[filename] {
				if re.Match([]byte(data)) {
					if hasCache {
						dataFileRegexCache[filename].Set(hash, true)
					}
					return true
				}
			}
		}
	} else {
		log.Errorf("file '%s' (type:regexp) not found in expr library", filename)
		log.Errorf("expr library : %s", spew.Sdump(dataFileRegex))
	}
	if hasCache {
		dataFileRegexCache[filename].Set(hash, false)
	}
	return false
}

func IpInRange(ip string, ipRange string) bool {
	var err error
	var ipParsed net.IP
	var ipRangeParsed *net.IPNet

	ipParsed = net.ParseIP(ip)
	if ipParsed == nil {
		log.Debugf("'%s' is not a valid IP", ip)
		return false
	}
	if _, ipRangeParsed, err = net.ParseCIDR(ipRange); err != nil {
		log.Debugf("'%s' is not a valid IP Range", ipRange)
		return false
	}
	if ipRangeParsed.Contains(ipParsed) {
		return true
	}
	return false
}

func IsIPV6(ip string) bool {
	ipParsed := net.ParseIP(ip)
	if ipParsed == nil {
		log.Debugf("'%s' is not a valid IP", ip)
		return false
	}

	// If it's a valid IP and can't be converted to IPv4 then it is an IPv6
	return ipParsed.To4() == nil
}

func IsIPV4(ip string) bool {
	ipParsed := net.ParseIP(ip)
	if ipParsed == nil {
		log.Debugf("'%s' is not a valid IP", ip)
		return false
	}
	return ipParsed.To4() != nil
}

func IsIP(ip string) bool {
	ipParsed := net.ParseIP(ip)
	if ipParsed == nil {
		log.Debugf("'%s' is not a valid IP", ip)
		return false
	}
	return true
}

func IpToRange(ip string, cidr string) string {
	cidr = strings.TrimPrefix(cidr, "/")
	mask, err := strconv.Atoi(cidr)
	if err != nil {
		log.Errorf("bad cidr '%s': %s", cidr, err)
		return ""
	}

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		log.Errorf("can't parse IP address '%s'", ip)
		return ""
	}
	ipRange := iplib.NewNet(ipAddr, mask)
	if ipRange.IP() == nil {
		log.Errorf("can't get cidr '%s' of '%s'", cidr, ip)
		return ""
	}
	return ipRange.String()
}

func TimeNow() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func ParseUri(uri string) map[string][]string {
	ret := make(map[string][]string)
	u, err := url.Parse(uri)
	if err != nil {
		log.Errorf("Could not parse URI: %s", err)
		return ret
	}
	parsed, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		log.Errorf("Could not parse query uri : %s", err)
		return ret
	}
	for k, v := range parsed {
		ret[k] = v
	}
	return ret
}

func KeyExists(key string, dict map[string]interface{}) bool {
	_, ok := dict[key]
	return ok
}

func GetDecisionsCount(value string) int {
	if dbClient == nil {
		log.Error("No database config to call GetDecisionsCount()")
		return 0

	}
	count, err := dbClient.CountDecisionsByValue(value)
	if err != nil {
		log.Errorf("Failed to get decisions count from value '%s'", value)
		return 0
	}
	return count
}

func GetDecisionsSinceCount(value string, since string) int {
	if dbClient == nil {
		log.Error("No database config to call GetDecisionsCount()")
		return 0
	}
	sinceDuration, err := time.ParseDuration(since)
	if err != nil {
		log.Errorf("Failed to parse since parameter '%s' : %s", since, err)
		return 0
	}
	sinceTime := time.Now().UTC().Add(-sinceDuration)
	count, err := dbClient.CountDecisionsSinceByValue(value, sinceTime)
	if err != nil {
		log.Errorf("Failed to get decisions count from value '%s'", value)
		return 0
	}
	return count
}

func LookupHost(value string) []string {
	addresses, err := net.LookupHost(value)
	if err != nil {
		log.Errorf("Failed to lookup host '%s' : %s", value, err)
		return []string{}
	}
	return addresses
}

func ParseUnixTime(value string) (time.Time, error) {
	//Splitting string here as some unix timestamp may have milliseconds and break ParseInt
	i, err := strconv.ParseInt(strings.Split(value, ".")[0], 10, 64)
	if err != nil || i <= 0 {
		return time.Time{}, fmt.Errorf("unable to parse %s as unix timestamp", value)
	}
	return time.Unix(i, 0), nil
}

func ParseUnix(value string) string {
	t, err := ParseUnixTime(value)
	if err != nil {
		log.Error(err)
		return ""
	}
	return t.Format(time.RFC3339)
}

func ToString(value interface{}) string {
	s, ok := value.(string)
	if !ok {
		return ""
	}
	return s
}

func Match(pattern, name string) bool {
	var matched bool
	if pattern == "" {
		return name == ""
	}
	if name == "" {
		if pattern == "*" || pattern == "" {
			return true
		}
		return false
	}
	if pattern[0] == '*' {
		for i := 0; i <= len(name); i++ {
			if matched = Match(pattern[1:], name[i:]); matched {
				return matched
			}
		}
		return matched
	}
	if pattern[0] == '?' || pattern[0] == name[0] {
		return Match(pattern[1:], name[1:])
	}
	return matched
}
