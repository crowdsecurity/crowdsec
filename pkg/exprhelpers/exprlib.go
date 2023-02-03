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
	"sync"
	"time"

	"github.com/c-robinson/iplib"

	"github.com/crowdsecurity/crowdsec/pkg/cache"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
)

var dataFile map[string][]string
var dataFileRegex map[string][]*regexp.Regexp
var dataFileRegexMemoized map[string]map[string]bool
var dataFileRegexMemoizedLock sync.Mutex
var dbClient *database.Client

const memoizeLimit = 1000

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
		"LookupHost":             LookupHost,
		"GetDecisionsCount":      GetDecisionsCount,
		"GetDecisionsSinceCount": GetDecisionsSinceCount,
		"Sprintf":                fmt.Sprintf,
		"CrowdsecCTI":            CrowdsecCTI,
		"ParseUnix":              ParseUnix,
		"GetFromStash":           cache.GetKey,
		"SetInStash":             cache.SetKey,
	}
	for k, v := range ctx {
		ExprLib[k] = v
	}
	return ExprLib
}

func Init(databaseClient *database.Client) error {
	dataFile = make(map[string][]string)
	dataFileRegex = make(map[string][]*regexp.Regexp)
	dataFileRegexMemoized = make(map[string]map[string]bool)
	dbClient = databaseClient
	return nil
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
			dataFileRegex[filename] = append(dataFileRegex[filename], regexp.MustCompile(scanner.Text()))
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

func regexpInFile(data string, filename string) bool {
	for _, re := range dataFileRegex[filename] {
		if re.MatchString(data) {
			return true
		}
	}
	return false
}

func RegexpInFile(data string, filename string) bool {
	if _, ok := dataFileRegex[filename]; !ok {
		log.Errorf("file '%s' (type:regexp) not found in expr library", filename)
		log.Errorf("expr library : %s", spew.Sdump(dataFileRegex))
		return false
	}
	dataFileRegexMemoizedLock.Lock()
	defer dataFileRegexMemoizedLock.Unlock()
	if _, ok := dataFileRegexMemoized[filename]; !ok {
		dataFileRegexMemoized[filename] = make(map[string]bool)
	}
	if _, ok := dataFileRegexMemoized[filename][data]; ok {
		return dataFileRegexMemoized[filename][data]
	}
	if len(dataFileRegexMemoized[filename]) > memoizeLimit {
		for k := range dataFileRegexMemoized[filename] {
			delete(dataFileRegexMemoized[filename], k)
			break
		}
	}
	dataFileRegexMemoized[filename][data] = regexpInFile(data, filename)
	return dataFileRegexMemoized[filename][data]
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
