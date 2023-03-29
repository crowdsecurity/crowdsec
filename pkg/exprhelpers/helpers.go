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

	"github.com/antonmedv/expr"
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

var exprFunctionOptions []expr.Option

func GetExprOptions(ctx map[string]interface{}) []expr.Option {
	ret := []expr.Option{}
	ret = append(ret, exprFunctionOptions...)
	ret = append(ret, expr.Env(ctx))
	return ret
}

func Init(databaseClient *database.Client) error {
	dataFile = make(map[string][]string)
	dataFileRegex = make(map[string][]*regexp.Regexp)
	dataFileRe2 = make(map[string][]*re2.Regexp)
	dbClient = databaseClient

	exprFunctionOptions = []expr.Option{}
	for _, function := range exprFuncs {
		exprFunctionOptions = append(exprFunctionOptions,
			expr.Function(function.name,
				function.function,
				function.signature...,
			))
	}

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
			if fflag.Re2RegexpInfileSupport.IsEnabled() {
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

//Expr helpers

// func Get(arr []string, index int) string {
func Get(params ...any) (any, error) {
	arr := params[0].([]string)
	index := params[1].(int)
	if index >= len(arr) {
		return "", nil
	}
	return arr[index], nil
}

// func Atof(x string) float64 {
func Atof(params ...any) (any, error) {
	x := params[0].(string)
	log.Debugf("debug atof %s", x)
	ret, err := strconv.ParseFloat(x, 64)
	if err != nil {
		log.Warningf("Atof : can't convert float '%s' : %v", x, err)
	}
	return ret, nil
}

// func Upper(s string) string {
func Upper(params ...any) (any, error) {
	s := params[0].(string)
	return strings.ToUpper(s), nil
}

// func Lower(s string) string {
func Lower(params ...any) (any, error) {
	s := params[0].(string)
	return strings.ToLower(s), nil
}

// func Distance(lat1 string, long1 string, lat2 string, long2 string) (float64, error) {
func Distance(params ...any) (any, error) {
	lat1 := params[0].(string)
	long1 := params[1].(string)
	lat2 := params[2].(string)
	long2 := params[3].(string)
	lat1f, err := strconv.ParseFloat(lat1, 64)
	if err != nil {
		log.Warningf("lat1 is not a float : %v", err)
		return 0.0, fmt.Errorf("lat1 is not a float : %v", err)
	}
	long1f, err := strconv.ParseFloat(long1, 64)
	if err != nil {
		log.Warningf("long1 is not a float : %v", err)
		return 0.0, fmt.Errorf("long1 is not a float : %v", err)
	}
	lat2f, err := strconv.ParseFloat(lat2, 64)
	if err != nil {
		log.Warningf("lat2 is not a float : %v", err)

		return 0.0, fmt.Errorf("lat2 is not a float : %v", err)
	}
	long2f, err := strconv.ParseFloat(long2, 64)
	if err != nil {
		log.Warningf("long2 is not a float : %v", err)

		return 0.0, fmt.Errorf("long2 is not a float : %v", err)
	}

	//either set of coordinates is 0,0, return 0 to avoid FPs
	if (lat1f == 0.0 && long1f == 0.0) || (lat2f == 0.0 && long2f == 0.0) {
		log.Warningf("one of the coordinates is 0,0, returning 0")
		return 0.0, nil
	}

	first := haversine.Coord{Lat: lat1f, Lon: long1f}
	second := haversine.Coord{Lat: lat2f, Lon: long2f}

	_, km := haversine.Distance(first, second)
	return km, nil
}

// func QueryEscape(s string) string {
func QueryEscape(params ...any) (any, error) {
	s := params[0].(string)
	return url.QueryEscape(s), nil
}

// func PathEscape(s string) string {
func PathEscape(params ...any) (any, error) {
	s := params[0].(string)
	return url.PathEscape(s), nil
}

// func PathUnescape(s string) string {
func PathUnescape(params ...any) (any, error) {
	s := params[0].(string)
	ret, err := url.PathUnescape(s)
	if err != nil {
		log.Debugf("unable to PathUnescape '%s': %+v", s, err)
		return s, nil
	}
	return ret, nil
}

// func QueryUnescape(s string) string {
func QueryUnescape(params ...any) (any, error) {
	s := params[0].(string)
	ret, err := url.QueryUnescape(s)
	if err != nil {
		log.Debugf("unable to QueryUnescape '%s': %+v", s, err)
		return s, nil
	}
	return ret, nil
}

// func File(filename string) []string {
func File(params ...any) (any, error) {
	filename := params[0].(string)
	if _, ok := dataFile[filename]; ok {
		return dataFile[filename], nil
	}
	log.Errorf("file '%s' (type:string) not found in expr library", filename)
	log.Errorf("expr library : %s", spew.Sdump(dataFile))
	return []string{}, nil
}

// func RegexpInFile(data string, filename string) bool {
func RegexpInFile(params ...any) (any, error) {
	data := params[0].(string)
	filename := params[1].(string)
	var hash uint64
	hasCache := false
	matched := false

	if _, ok := dataFileRegexCache[filename]; ok {
		hasCache = true
		hash = xxhash.Sum64String(data)
		if val, err := dataFileRegexCache[filename].Get(hash); err == nil {
			return val.(bool), nil
		}
	}

	switch fflag.Re2RegexpInfileSupport.IsEnabled() {
	case true:
		if _, ok := dataFileRe2[filename]; ok {
			for _, re := range dataFileRe2[filename] {
				if re.MatchString(data) {
					matched = true
					break
				}
			}
		} else {
			log.Errorf("file '%s' (type:regexp) not found in expr library", filename)
			log.Errorf("expr library : %s", spew.Sdump(dataFileRe2))
		}
	case false:
		if _, ok := dataFileRegex[filename]; ok {
			for _, re := range dataFileRegex[filename] {
				if re.MatchString(data) {
					matched = true
					break
				}
			}
		} else {
			log.Errorf("file '%s' (type:regexp) not found in expr library", filename)
			log.Errorf("expr library : %s", spew.Sdump(dataFileRegex))
		}
	}
	if hasCache {
		dataFileRegexCache[filename].Set(hash, matched)
	}
	return matched, nil
}

// func IpInRange(ip string, ipRange string) bool {
func IpInRange(params ...any) (any, error) {
	var err error
	var ipParsed net.IP
	var ipRangeParsed *net.IPNet

	ip := params[0].(string)
	ipRange := params[1].(string)

	ipParsed = net.ParseIP(ip)
	if ipParsed == nil {
		log.Debugf("'%s' is not a valid IP", ip)
		return false, nil
	}
	if _, ipRangeParsed, err = net.ParseCIDR(ipRange); err != nil {
		log.Debugf("'%s' is not a valid IP Range", ipRange)
		return false, nil //nolint:nilerr // This helper did not return an error before the move to expr.Function, we keep this behavior for backward compatibility
	}
	if ipRangeParsed.Contains(ipParsed) {
		return true, nil
	}
	return false, nil
}

// func IsIPV6(ip string) bool {
func IsIPV6(params ...any) (any, error) {
	ip := params[0].(string)
	ipParsed := net.ParseIP(ip)
	if ipParsed == nil {
		log.Debugf("'%s' is not a valid IP", ip)
		return false, nil
	}

	// If it's a valid IP and can't be converted to IPv4 then it is an IPv6
	return ipParsed.To4() == nil, nil
}

// func IsIPV4(ip string) bool {
func IsIPV4(params ...any) (any, error) {
	ip := params[0].(string)
	ipParsed := net.ParseIP(ip)
	if ipParsed == nil {
		log.Debugf("'%s' is not a valid IP", ip)
		return false, nil
	}
	return ipParsed.To4() != nil, nil
}

// func IsIP(ip string) bool {
func IsIP(params ...any) (any, error) {
	ip := params[0].(string)
	ipParsed := net.ParseIP(ip)
	if ipParsed == nil {
		log.Debugf("'%s' is not a valid IP", ip)
		return false, nil
	}
	return true, nil
}

// func IpToRange(ip string, cidr string) string {
func IpToRange(params ...any) (any, error) {
	ip := params[0].(string)
	cidr := params[1].(string)
	cidr = strings.TrimPrefix(cidr, "/")
	mask, err := strconv.Atoi(cidr)
	if err != nil {
		log.Errorf("bad cidr '%s': %s", cidr, err)
		return "", nil
	}

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		log.Errorf("can't parse IP address '%s'", ip)
		return "", nil
	}
	ipRange := iplib.NewNet(ipAddr, mask)
	if ipRange.IP() == nil {
		log.Errorf("can't get cidr '%s' of '%s'", cidr, ip)
		return "", nil
	}
	return ipRange.String(), nil
}

// func TimeNow() string {
func TimeNow(params ...any) (any, error) {
	return time.Now().UTC().Format(time.RFC3339), nil
}

// func ParseUri(uri string) map[string][]string {
func ParseUri(params ...any) (any, error) {
	uri := params[0].(string)
	ret := make(map[string][]string)
	u, err := url.Parse(uri)
	if err != nil {
		log.Errorf("Could not parse URI: %s", err)
		return ret, nil
	}
	parsed, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		log.Errorf("Could not parse query uri : %s", err)
		return ret, nil
	}
	for k, v := range parsed {
		ret[k] = v
	}
	return ret, nil
}

// func KeyExists(key string, dict map[string]interface{}) bool {
func KeyExists(params ...any) (any, error) {
	key := params[0].(string)
	dict := params[1].(map[string]interface{})
	_, ok := dict[key]
	return ok, nil
}

// func GetDecisionsCount(value string) int {
func GetDecisionsCount(params ...any) (any, error) {
	value := params[0].(string)
	if dbClient == nil {
		log.Error("No database config to call GetDecisionsCount()")
		return 0, nil

	}
	count, err := dbClient.CountDecisionsByValue(value)
	if err != nil {
		log.Errorf("Failed to get decisions count from value '%s'", value)
		return 0, nil //nolint:nilerr // This helper did not return an error before the move to expr.Function, we keep this behavior for backward compatibility
	}
	return count, nil
}

// func GetDecisionsSinceCount(value string, since string) int {
func GetDecisionsSinceCount(params ...any) (any, error) {
	value := params[0].(string)
	since := params[1].(string)
	if dbClient == nil {
		log.Error("No database config to call GetDecisionsCount()")
		return 0, nil
	}
	sinceDuration, err := time.ParseDuration(since)
	if err != nil {
		log.Errorf("Failed to parse since parameter '%s' : %s", since, err)
		return 0, nil
	}
	sinceTime := time.Now().UTC().Add(-sinceDuration)
	count, err := dbClient.CountDecisionsSinceByValue(value, sinceTime)
	if err != nil {
		log.Errorf("Failed to get decisions count from value '%s'", value)
		return 0, nil //nolint:nilerr // This helper did not return an error before the move to expr.Function, we keep this behavior for backward compatibility
	}
	return count, nil
}

// func LookupHost(value string) []string {
func LookupHost(params ...any) (any, error) {
	value := params[0].(string)
	addresses, err := net.LookupHost(value)
	if err != nil {
		log.Errorf("Failed to lookup host '%s' : %s", value, err)
		return []string{}, nil
	}
	return addresses, nil
}

// func ParseUnixTime(value string) (time.Time, error) {
func ParseUnixTime(params ...any) (any, error) {
	value := params[0].(string)
	//Splitting string here as some unix timestamp may have milliseconds and break ParseInt
	i, err := strconv.ParseInt(strings.Split(value, ".")[0], 10, 64)
	if err != nil || i <= 0 {
		return time.Time{}, fmt.Errorf("unable to parse %s as unix timestamp", value)
	}
	return time.Unix(i, 0), nil
}

// func ParseUnix(value string) string {
func ParseUnix(params ...any) (any, error) {
	value := params[0].(string)
	t, err := ParseUnixTime(value)
	if err != nil {
		log.Error(err)
		return "", nil
	}
	return t.(time.Time).Format(time.RFC3339), nil
}

// func ToString(value interface{}) string {
func ToString(params ...any) (any, error) {
	value := params[0]
	s, ok := value.(string)
	if !ok {
		return "", nil
	}
	return s, nil
}

// func GetFromStash(cacheName string, key string) (string, error) {
func GetFromStash(params ...any) (any, error) {
	cacheName := params[0].(string)
	key := params[1].(string)
	return cache.GetKey(cacheName, key)
}

// func SetInStash(cacheName string, key string, value string, expiration *time.Duration) any {
func SetInStash(params ...any) (any, error) {
	cacheName := params[0].(string)
	key := params[1].(string)
	value := params[2].(string)
	expiration := params[3].(*time.Duration)
	return cache.SetKey(cacheName, key, value, expiration), nil
}

func Sprintf(params ...any) (any, error) {
	format := params[0].(string)
	return fmt.Sprintf(format, params[1:]...), nil
}

// func Match(pattern, name string) bool {
func Match(params ...any) (any, error) {
	var matched bool

	pattern := params[0].(string)
	name := params[1].(string)

	if pattern == "" {
		return name == "", nil
	}
	if name == "" {
		if pattern == "*" || pattern == "" {
			return true, nil
		}
		return false, nil
	}
	if pattern[0] == '*' {
		for i := 0; i <= len(name); i++ {
			matched, _ := Match(pattern[1:], name[i:])
			if matched.(bool) {
				return matched, nil
			}
		}
		return matched, nil
	}
	if pattern[0] == '?' || pattern[0] == name[0] {
		return Match(pattern[1:], name[1:])
	}
	return matched, nil
}
