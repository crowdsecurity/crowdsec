package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prom2json"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/texttheater/golang-levenshtein/levenshtein"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/trace"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const MaxDistance = 7

func printHelp(cmd *cobra.Command) {
	err := cmd.Help()
	if err != nil {
		log.Fatalf("unable to print help(): %s", err)
	}
}

func indexOf(s string, slice []string) int {
	for i, elem := range slice {
		if s == elem {
			return i
		}
	}
	return -1
}

func LoadHub() error {
	if err := csConfig.LoadHub(); err != nil {
		log.Fatal(err)
	}
	if csConfig.Hub == nil {
		return fmt.Errorf("unable to load hub")
	}

	if err := cwhub.SetHubBranch(); err != nil {
		log.Warningf("unable to set hub branch (%s), default to master", err)
	}

	if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
		return fmt.Errorf("Failed to get Hub index : '%w'. Run 'sudo cscli hub update' to get the hub index", err)
	}

	return nil
}

func Suggest(itemType string, baseItem string, suggestItem string, score int, ignoreErr bool) {
	errMsg := ""
	if score < MaxDistance {
		errMsg = fmt.Sprintf("unable to find %s '%s', did you mean %s ?", itemType, baseItem, suggestItem)
	} else {
		errMsg = fmt.Sprintf("unable to find %s '%s'", itemType, baseItem)
	}
	if ignoreErr {
		log.Error(errMsg)
	} else {
		log.Fatalf(errMsg)
	}
}

func GetDistance(itemType string, itemName string) (*cwhub.Item, int) {
	allItems := make([]string, 0)
	nearestScore := 100
	nearestItem := &cwhub.Item{}
	hubItems := cwhub.GetHubStatusForItemType(itemType, "", true)
	for _, item := range hubItems {
		allItems = append(allItems, item.Name)
	}

	for _, s := range allItems {
		d := levenshtein.DistanceForStrings([]rune(itemName), []rune(s), levenshtein.DefaultOptions)
		if d < nearestScore {
			nearestScore = d
			nearestItem = cwhub.GetItem(itemType, s)
		}
	}
	return nearestItem, nearestScore
}

func compAllItems(itemType string, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if err := LoadHub(); err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}

	comp := make([]string, 0)
	hubItems := cwhub.GetHubStatusForItemType(itemType, "", true)
	for _, item := range hubItems {
		if !slices.Contains(args, item.Name) && strings.Contains(item.Name, toComplete) {
			comp = append(comp, item.Name)
		}
	}
	cobra.CompDebugln(fmt.Sprintf("%s: %+v", itemType, comp), true)
	return comp, cobra.ShellCompDirectiveNoFileComp
}

func compInstalledItems(itemType string, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if err := LoadHub(); err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}

	var items []string
	var err error
	switch itemType {
	case cwhub.PARSERS:
		items, err = cwhub.GetInstalledParsersAsString()
	case cwhub.SCENARIOS:
		items, err = cwhub.GetInstalledScenariosAsString()
	case cwhub.PARSERS_OVFLW:
		items, err = cwhub.GetInstalledPostOverflowsAsString()
	case cwhub.COLLECTIONS:
		items, err = cwhub.GetInstalledCollectionsAsString()
	default:
		return nil, cobra.ShellCompDirectiveDefault
	}

	if err != nil {
		cobra.CompDebugln(fmt.Sprintf("list installed %s err: %s", itemType, err), true)
		return nil, cobra.ShellCompDirectiveDefault
	}
	comp := make([]string, 0)

	if toComplete != "" {
		for _, item := range items {
			if strings.Contains(item, toComplete) {
				comp = append(comp, item)
			}
		}
	} else {
		comp = items
	}

	cobra.CompDebugln(fmt.Sprintf("%s: %+v", itemType, comp), true)

	return comp, cobra.ShellCompDirectiveNoFileComp
}

func ListItems(out io.Writer, itemTypes []string, args []string, showType bool, showHeader bool, all bool) {
	var hubStatusByItemType = make(map[string][]cwhub.ItemHubStatus)

	for _, itemType := range itemTypes {
		itemName := ""
		if len(args) == 1 {
			itemName = args[0]
		}
		hubStatusByItemType[itemType] = cwhub.GetHubStatusForItemType(itemType, itemName, all)
	}

	if csConfig.Cscli.Output == "human" {
		for _, itemType := range itemTypes {
			var statuses []cwhub.ItemHubStatus
			var ok bool
			if statuses, ok = hubStatusByItemType[itemType]; !ok {
				log.Errorf("unknown item type: %s", itemType)
				continue
			}
			listHubItemTable(out, "\n"+strings.ToUpper(itemType), statuses)
		}
	} else if csConfig.Cscli.Output == "json" {
		x, err := json.MarshalIndent(hubStatusByItemType, "", " ")
		if err != nil {
			log.Fatalf("failed to unmarshal")
		}
		out.Write(x)
	} else if csConfig.Cscli.Output == "raw" {
		csvwriter := csv.NewWriter(out)
		if showHeader {
			header := []string{"name", "status", "version", "description"}
			if showType {
				header = append(header, "type")
			}
			err := csvwriter.Write(header)
			if err != nil {
				log.Fatalf("failed to write header: %s", err)
			}

		}
		for _, itemType := range itemTypes {
			var statuses []cwhub.ItemHubStatus
			var ok bool
			if statuses, ok = hubStatusByItemType[itemType]; !ok {
				log.Errorf("unknown item type: %s", itemType)
				continue
			}
			for _, status := range statuses {
				if status.LocalVersion == "" {
					status.LocalVersion = "n/a"
				}
				row := []string{
					status.Name,
					status.Status,
					status.LocalVersion,
					status.Description,
				}
				if showType {
					row = append(row, itemType)
				}
				err := csvwriter.Write(row)
				if err != nil {
					log.Fatalf("failed to write raw output : %s", err)
				}
			}
		}
		csvwriter.Flush()
	}
}

func InspectItem(name string, objecitemType string) {

	hubItem := cwhub.GetItem(objecitemType, name)
	if hubItem == nil {
		log.Fatalf("unable to retrieve item.")
	}
	var b []byte
	var err error
	switch csConfig.Cscli.Output {
	case "human", "raw":
		b, err = yaml.Marshal(*hubItem)
		if err != nil {
			log.Fatalf("unable to marshal item : %s", err)
		}
	case "json":
		b, err = json.MarshalIndent(*hubItem, "", " ")
		if err != nil {
			log.Fatalf("unable to marshal item : %s", err)
		}
	}
	fmt.Printf("%s", string(b))
	if csConfig.Cscli.Output == "json" || csConfig.Cscli.Output == "raw" {
		return
	}

	if prometheusURL == "" {
		//This is technically wrong to do this, as the prometheus section contains a listen address, not an URL to query prometheus
		//But for ease of use, we will use the listen address as the prometheus URL because it will be 127.0.0.1 in the default case
		listenAddr := csConfig.Prometheus.ListenAddr
		if listenAddr == "" {
			listenAddr = "127.0.0.1"
		}
		listenPort := csConfig.Prometheus.ListenPort
		if listenPort == 0 {
			listenPort = 6060
		}
		prometheusURL = fmt.Sprintf("http://%s:%d/metrics", listenAddr, listenPort)
		log.Debugf("No prometheus URL provided using: %s", prometheusURL)
	}

	fmt.Printf("\nCurrent metrics : \n")
	ShowMetrics(hubItem)
}

func manageCliDecisionAlerts(ip *string, ipRange *string, scope *string, value *string) error {

	/*if a range is provided, change the scope*/
	if *ipRange != "" {
		_, _, err := net.ParseCIDR(*ipRange)
		if err != nil {
			return fmt.Errorf("%s isn't a valid range", *ipRange)
		}
	}
	if *ip != "" {
		ipRepr := net.ParseIP(*ip)
		if ipRepr == nil {
			return fmt.Errorf("%s isn't a valid ip", *ip)
		}
	}

	//avoid confusion on scope (ip vs Ip and range vs Range)
	switch strings.ToLower(*scope) {
	case "ip":
		*scope = types.Ip
	case "range":
		*scope = types.Range
	case "country":
		*scope = types.Country
	case "as":
		*scope = types.AS
	}
	return nil
}

func ShowMetrics(hubItem *cwhub.Item) {
	switch hubItem.Type {
	case cwhub.PARSERS:
		metrics := GetParserMetric(prometheusURL, hubItem.Name)
		parserMetricsTable(color.Output, hubItem.Name, metrics)
	case cwhub.SCENARIOS:
		metrics := GetScenarioMetric(prometheusURL, hubItem.Name)
		scenarioMetricsTable(color.Output, hubItem.Name, metrics)
	case cwhub.COLLECTIONS:
		for _, item := range hubItem.Parsers {
			metrics := GetParserMetric(prometheusURL, item)
			parserMetricsTable(color.Output, item, metrics)
		}
		for _, item := range hubItem.Scenarios {
			metrics := GetScenarioMetric(prometheusURL, item)
			scenarioMetricsTable(color.Output, item, metrics)
		}
		for _, item := range hubItem.Collections {
			hubItem = cwhub.GetItem(cwhub.COLLECTIONS, item)
			if hubItem == nil {
				log.Fatalf("unable to retrieve item '%s' from collection '%s'", item, hubItem.Name)
			}
			ShowMetrics(hubItem)
		}
	default:
		log.Errorf("item of type '%s' is unknown", hubItem.Type)
	}
}

// GetParserMetric is a complete rip from prom2json
func GetParserMetric(url string, itemName string) map[string]map[string]int {
	stats := make(map[string]map[string]int)

	result := GetPrometheusMetric(url)
	for idx, fam := range result {
		if !strings.HasPrefix(fam.Name, "cs_") {
			continue
		}
		log.Tracef("round %d", idx)
		for _, m := range fam.Metrics {
			metric, ok := m.(prom2json.Metric)
			if !ok {
				log.Debugf("failed to convert metric to prom2json.Metric")
				continue
			}
			name, ok := metric.Labels["name"]
			if !ok {
				log.Debugf("no name in Metric %v", metric.Labels)
			}
			if name != itemName {
				continue
			}
			source, ok := metric.Labels["source"]
			if !ok {
				log.Debugf("no source in Metric %v", metric.Labels)
			} else {
				if srctype, ok := metric.Labels["type"]; ok {
					source = srctype + ":" + source
				}
			}
			value := m.(prom2json.Metric).Value
			fval, err := strconv.ParseFloat(value, 32)
			if err != nil {
				log.Errorf("Unexpected int value %s : %s", value, err)
				continue
			}
			ival := int(fval)

			switch fam.Name {
			case "cs_reader_hits_total":
				if _, ok := stats[source]; !ok {
					stats[source] = make(map[string]int)
					stats[source]["parsed"] = 0
					stats[source]["reads"] = 0
					stats[source]["unparsed"] = 0
					stats[source]["hits"] = 0
				}
				stats[source]["reads"] += ival
			case "cs_parser_hits_ok_total":
				if _, ok := stats[source]; !ok {
					stats[source] = make(map[string]int)
				}
				stats[source]["parsed"] += ival
			case "cs_parser_hits_ko_total":
				if _, ok := stats[source]; !ok {
					stats[source] = make(map[string]int)
				}
				stats[source]["unparsed"] += ival
			case "cs_node_hits_total":
				if _, ok := stats[source]; !ok {
					stats[source] = make(map[string]int)
				}
				stats[source]["hits"] += ival
			case "cs_node_hits_ok_total":
				if _, ok := stats[source]; !ok {
					stats[source] = make(map[string]int)
				}
				stats[source]["parsed"] += ival
			case "cs_node_hits_ko_total":
				if _, ok := stats[source]; !ok {
					stats[source] = make(map[string]int)
				}
				stats[source]["unparsed"] += ival
			default:
				continue
			}
		}
	}
	return stats
}

func GetScenarioMetric(url string, itemName string) map[string]int {
	stats := make(map[string]int)

	stats["instantiation"] = 0
	stats["curr_count"] = 0
	stats["overflow"] = 0
	stats["pour"] = 0
	stats["underflow"] = 0

	result := GetPrometheusMetric(url)
	for idx, fam := range result {
		if !strings.HasPrefix(fam.Name, "cs_") {
			continue
		}
		log.Tracef("round %d", idx)
		for _, m := range fam.Metrics {
			metric, ok := m.(prom2json.Metric)
			if !ok {
				log.Debugf("failed to convert metric to prom2json.Metric")
				continue
			}
			name, ok := metric.Labels["name"]
			if !ok {
				log.Debugf("no name in Metric %v", metric.Labels)
			}
			if name != itemName {
				continue
			}
			value := m.(prom2json.Metric).Value
			fval, err := strconv.ParseFloat(value, 32)
			if err != nil {
				log.Errorf("Unexpected int value %s : %s", value, err)
				continue
			}
			ival := int(fval)

			switch fam.Name {
			case "cs_bucket_created_total":
				stats["instantiation"] += ival
			case "cs_buckets":
				stats["curr_count"] += ival
			case "cs_bucket_overflowed_total":
				stats["overflow"] += ival
			case "cs_bucket_poured_total":
				stats["pour"] += ival
			case "cs_bucket_underflowed_total":
				stats["underflow"] += ival
			default:
				continue
			}
		}
	}
	return stats
}

// it's a rip of the cli version, but in silent-mode
func silenceInstallItem(name string, obtype string) (string, error) {
	var item = cwhub.GetItem(obtype, name)
	if item == nil {
		return "", fmt.Errorf("error retrieving item")
	}
	it := *item
	if downloadOnly && it.Downloaded && it.UpToDate {
		return fmt.Sprintf("%s is already downloaded and up-to-date", it.Name), nil
	}
	it, err := cwhub.DownloadLatest(csConfig.Hub, it, forceAction, false)
	if err != nil {
		return "", fmt.Errorf("error while downloading %s : %v", it.Name, err)
	}
	if err := cwhub.AddItem(obtype, it); err != nil {
		return "", err
	}

	if downloadOnly {
		return fmt.Sprintf("Downloaded %s to %s", it.Name, csConfig.Cscli.HubDir+"/"+it.RemotePath), nil
	}
	it, err = cwhub.EnableItem(csConfig.Hub, it)
	if err != nil {
		return "", fmt.Errorf("error while enabling %s : %v", it.Name, err)
	}
	if err := cwhub.AddItem(obtype, it); err != nil {
		return "", err
	}
	return fmt.Sprintf("Enabled %s", it.Name), nil
}

func GetPrometheusMetric(url string) []*prom2json.Family {
	mfChan := make(chan *dto.MetricFamily, 1024)

	// Start with the DefaultTransport for sane defaults.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Conservatively disable HTTP keep-alives as this program will only
	// ever need a single HTTP request.
	transport.DisableKeepAlives = true
	// Timeout early if the server doesn't even return the headers.
	transport.ResponseHeaderTimeout = time.Minute

	go func() {
		defer trace.CatchPanic("crowdsec/GetPrometheusMetric")
		err := prom2json.FetchMetricFamilies(url, mfChan, transport)
		if err != nil {
			log.Fatalf("failed to fetch prometheus metrics : %v", err)
		}
	}()

	result := []*prom2json.Family{}
	for mf := range mfChan {
		result = append(result, prom2json.NewFamily(mf))
	}
	log.Debugf("Finished reading prometheus output, %d entries", len(result))

	return result
}

func RestoreHub(dirPath string) error {
	var err error

	if err := csConfig.LoadHub(); err != nil {
		return err
	}
	if err := cwhub.SetHubBranch(); err != nil {
		return fmt.Errorf("error while setting hub branch: %s", err)
	}

	for _, itype := range cwhub.ItemTypes {
		itemDirectory := fmt.Sprintf("%s/%s/", dirPath, itype)
		if _, err = os.Stat(itemDirectory); err != nil {
			log.Infof("no %s in backup", itype)
			continue
		}
		/*restore the upstream items*/
		upstreamListFN := fmt.Sprintf("%s/upstream-%s.json", itemDirectory, itype)
		file, err := os.ReadFile(upstreamListFN)
		if err != nil {
			return fmt.Errorf("error while opening %s : %s", upstreamListFN, err)
		}
		var upstreamList []string
		err = json.Unmarshal(file, &upstreamList)
		if err != nil {
			return fmt.Errorf("error unmarshaling %s : %s", upstreamListFN, err)
		}
		for _, toinstall := range upstreamList {
			label, err := silenceInstallItem(toinstall, itype)
			if err != nil {
				log.Errorf("Error while installing %s : %s", toinstall, err)
			} else if label != "" {
				log.Infof("Installed %s : %s", toinstall, label)
			} else {
				log.Printf("Installed %s : ok", toinstall)
			}
		}

		/*restore the local and tainted items*/
		files, err := os.ReadDir(itemDirectory)
		if err != nil {
			return fmt.Errorf("failed enumerating files of %s : %s", itemDirectory, err)
		}
		for _, file := range files {
			//this was the upstream data
			if file.Name() == fmt.Sprintf("upstream-%s.json", itype) {
				continue
			}
			if itype == cwhub.PARSERS || itype == cwhub.PARSERS_OVFLW {
				//we expect a stage here
				if !file.IsDir() {
					continue
				}
				stage := file.Name()
				stagedir := fmt.Sprintf("%s/%s/%s/", csConfig.ConfigPaths.ConfigDir, itype, stage)
				log.Debugf("Found stage %s in %s, target directory : %s", stage, itype, stagedir)
				if err = os.MkdirAll(stagedir, os.ModePerm); err != nil {
					return fmt.Errorf("error while creating stage directory %s : %s", stagedir, err)
				}
				/*find items*/
				ifiles, err := os.ReadDir(itemDirectory + "/" + stage + "/")
				if err != nil {
					return fmt.Errorf("failed enumerating files of %s : %s", itemDirectory+"/"+stage, err)
				}
				//finally copy item
				for _, tfile := range ifiles {
					log.Infof("Going to restore local/tainted [%s]", tfile.Name())
					sourceFile := fmt.Sprintf("%s/%s/%s", itemDirectory, stage, tfile.Name())
					destinationFile := fmt.Sprintf("%s%s", stagedir, tfile.Name())
					if err = types.CopyFile(sourceFile, destinationFile); err != nil {
						return fmt.Errorf("failed copy %s %s to %s : %s", itype, sourceFile, destinationFile, err)
					}
					log.Infof("restored %s to %s", sourceFile, destinationFile)
				}
			} else {
				log.Infof("Going to restore local/tainted [%s]", file.Name())
				sourceFile := fmt.Sprintf("%s/%s", itemDirectory, file.Name())
				destinationFile := fmt.Sprintf("%s/%s/%s", csConfig.ConfigPaths.ConfigDir, itype, file.Name())
				if err = types.CopyFile(sourceFile, destinationFile); err != nil {
					return fmt.Errorf("failed copy %s %s to %s : %s", itype, sourceFile, destinationFile, err)
				}
				log.Infof("restored %s to %s", sourceFile, destinationFile)
			}

		}
	}
	return nil
}

func BackupHub(dirPath string) error {
	var err error
	var itemDirectory string
	var upstreamParsers []string

	for _, itemType := range cwhub.ItemTypes {
		clog := log.WithFields(log.Fields{
			"type": itemType,
		})
		itemMap := cwhub.GetItemMap(itemType)
		if itemMap == nil {
			clog.Infof("No %s to backup.", itemType)
			continue
		}
		itemDirectory = fmt.Sprintf("%s/%s/", dirPath, itemType)
		if err := os.MkdirAll(itemDirectory, os.ModePerm); err != nil {
			return fmt.Errorf("error while creating %s : %s", itemDirectory, err)
		}
		upstreamParsers = []string{}
		for k, v := range itemMap {
			clog = clog.WithFields(log.Fields{
				"file": v.Name,
			})
			if !v.Installed { //only backup installed ones
				clog.Debugf("[%s] : not installed", k)
				continue
			}

			//for the local/tainted ones, we backup the full file
			if v.Tainted || v.Local || !v.UpToDate {
				//we need to backup stages for parsers
				if itemType == cwhub.PARSERS || itemType == cwhub.PARSERS_OVFLW {
					fstagedir := fmt.Sprintf("%s%s", itemDirectory, v.Stage)
					if err := os.MkdirAll(fstagedir, os.ModePerm); err != nil {
						return fmt.Errorf("error while creating stage dir %s : %s", fstagedir, err)
					}
				}
				clog.Debugf("[%s] : backuping file (tainted:%t local:%t up-to-date:%t)", k, v.Tainted, v.Local, v.UpToDate)
				tfile := fmt.Sprintf("%s%s/%s", itemDirectory, v.Stage, v.FileName)
				if err = types.CopyFile(v.LocalPath, tfile); err != nil {
					return fmt.Errorf("failed copy %s %s to %s : %s", itemType, v.LocalPath, tfile, err)
				}
				clog.Infof("local/tainted saved %s to %s", v.LocalPath, tfile)
				continue
			}
			clog.Debugf("[%s] : from hub, just backup name (up-to-date:%t)", k, v.UpToDate)
			clog.Infof("saving, version:%s, up-to-date:%t", v.Version, v.UpToDate)
			upstreamParsers = append(upstreamParsers, v.Name)
		}
		//write the upstream items
		upstreamParsersFname := fmt.Sprintf("%s/upstream-%s.json", itemDirectory, itemType)
		upstreamParsersContent, err := json.MarshalIndent(upstreamParsers, "", " ")
		if err != nil {
			return fmt.Errorf("failed marshaling upstream parsers : %s", err)
		}
		err = os.WriteFile(upstreamParsersFname, upstreamParsersContent, 0644)
		if err != nil {
			return fmt.Errorf("unable to write to %s %s : %s", itemType, upstreamParsersFname, err)
		}
		clog.Infof("Wrote %d entries for %s to %s", len(upstreamParsers), itemType, upstreamParsersFname)
	}

	return nil
}

type unit struct {
	value  int64
	symbol string
}

var ranges = []unit{
	{
		value:  1e18,
		symbol: "E",
	},
	{
		value:  1e15,
		symbol: "P",
	},
	{
		value:  1e12,
		symbol: "T",
	},
	{
		value:  1e6,
		symbol: "M",
	},
	{
		value:  1e3,
		symbol: "k",
	},
	{
		value:  1,
		symbol: "",
	},
}

func formatNumber(num int) string {
	goodUnit := unit{}
	for _, u := range ranges {
		if int64(num) >= u.value {
			goodUnit = u
			break
		}
	}

	if goodUnit.value == 1 {
		return fmt.Sprintf("%d%s", num, goodUnit.symbol)
	}

	res := math.Round(float64(num)/float64(goodUnit.value)*100) / 100
	return fmt.Sprintf("%.2f%s", res, goodUnit.symbol)
}

func getDBClient() (*database.Client, error) {
	var err error
	if err := csConfig.LoadAPIServer(); err != nil || csConfig.DisableAPI {
		return nil, err
	}
	ret, err := database.NewClient(csConfig.DbConfig)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func removeFromSlice(val string, slice []string) []string {
	var i int
	var value string

	valueFound := false

	// get the index
	for i, value = range slice {
		if value == val {
			valueFound = true
			break
		}
	}

	if valueFound {
		slice[i] = slice[len(slice)-1]
		slice[len(slice)-1] = ""
		slice = slice[:len(slice)-1]
	}

	return slice

}
