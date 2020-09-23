package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/enescakir/emoji"
	"github.com/olekukonko/tablewriter"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/prom2json"
	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v2"
)

func inSlice(s string, slice []string) bool {
	for _, str := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func indexOf(s string, slice []string) int {
	for i, elem := range slice {
		if s == elem {
			return i
		}
	}
	return -1
}

func setHubBranch() error {
	/*
		if no branch has been specified in flags for the hub, then use the one corresponding to crowdsec version
	*/

	if cwhub.HubBranch == "" {
		latest, err := cwversion.Latest()
		if err != nil {
			cwhub.HubBranch = "master"
			return err
		}

		if cwversion.Version == latest {
			cwhub.HubBranch = "master"
		} else if semver.Compare(cwversion.Version, latest) == 1 { // if current version is greater than the latest we are in pre-release
			log.Debugf("Your current crowdsec version seems to be a pre-release (%s)", cwversion.Version)
			cwhub.HubBranch = "master"
		} else {
			log.Warnf("Crowdsec is not the latest version. Current version is '%s' and latest version is '%s'. Please update it!", cwversion.Version, latest)
			log.Warnf("As a result, you will not be able to use parsers/scenarios/collections added to Crowdsec Hub after CrowdSec %s", latest)
			cwhub.HubBranch = cwversion.Version
		}
		log.Debugf("Using branch '%s' for the hub", cwhub.HubBranch)
	}
	return nil
}

func InstallItem(name string, obtype string) {
	it := cwhub.GetItem(obtype, name)
	if it == nil {
		log.Fatalf("unable to retrive item : %s", name)
	}
	item := *it
	if downloadOnly && item.Downloaded && item.UpToDate {
		log.Warningf("%s is already downloaded and up-to-date", item.Name)
		return
	}
	item, err := cwhub.DownloadLatest(csConfig.Cscli, item, forceInstall)
	if err != nil {
		log.Fatalf("error while downloading %s : %v", item.Name, err)
	}
	cwhub.AddItemMap(obtype, item)
	if downloadOnly {
		log.Infof("Downloaded %s to %s", item.Name, csConfig.Cscli.HubDir+"/"+item.RemotePath)
		return
	}
	item, err = cwhub.EnableItem(csConfig.Cscli, item)
	if err != nil {
		log.Fatalf("error while enabled %s : %v.", item.Name, err)
	}
	cwhub.AddItemMap(obtype, item)
	log.Infof("Enabled %s", item.Name)
	return
	log.Warningf("%s not found in hub index", name)
	/*iterate of pkg index data*/
}

func RemoveMany(ttype string, name string) {
	var err error
	var disabled int
	if name != "" {
		it := cwhub.GetItem(ttype, name)
		if it == nil {
			log.Fatalf("unable to retrieve: %s", name)
		}
		item := *it
		item, err = cwhub.DisableItem(csConfig.Cscli, item, purgeRemove)
		if err != nil {
			log.Fatalf("unable to disable %s : %v", item.Name, err)
		}
		cwhub.AddItemMap(ttype, item)
		return
	} else if name == "" && removeAll {
		for _, v := range cwhub.GetItemMap(ttype) {
			v, err = cwhub.DisableItem(csConfig.Cscli, v, purgeRemove)
			if err != nil {
				log.Fatalf("unable to disable %s : %v", v.Name, err)
			}
			cwhub.AddItemMap(ttype, v)
			disabled++
		}
	}
	if name != "" && !removeAll {
		log.Errorf("%s not found", name)
		return
	}
	log.Infof("Disabled %d items", disabled)
}

func UpgradeConfig(ttype string, name string) {
	var err error
	var updated int
	var found bool

	for _, v := range cwhub.GetItemMap(ttype) {
		if name != "" && name != v.Name {
			continue
		}
		if !v.Installed {
			log.Debugf("skip %s, not installed", v.Name)
			continue
		}
		if !v.Downloaded {
			log.Warningf("%s : not downloaded, please install.", v.Name)
			continue
		}
		found = true
		if v.UpToDate {
			log.Infof("%s : up-to-date", v.Name)
			continue
		}
		v, err = cwhub.DownloadLatest(csConfig.Cscli, v, forceUpgrade)
		if err != nil {
			log.Fatalf("%s : download failed : %v", v.Name, err)
		}
		if !v.UpToDate {
			if v.Tainted {
				log.Infof("%v %s is tainted, --force to overwrite", emoji.Warning, v.Name)
			} else if v.Local {
				log.Infof("%v %s is local", emoji.Prohibited, v.Name)
			}
		} else {
			log.Infof("%v %s : updated", emoji.Package, v.Name)
			updated++
		}
		cwhub.AddItemMap(ttype, v)
	}
	if !found {
		log.Errorf("Didn't find %s", name)
	} else if updated == 0 && found {
		log.Errorf("Nothing to update")
	} else if updated != 0 {
		log.Infof("Upgraded %d items", updated)
	}

}

func InspectItem(name string, objectType string) {

	hubItem := cwhub.GetItem(objectType, name)
	if hubItem == nil {
		log.Fatalf("unable to retrieve item.")
	}
	buff, err := yaml.Marshal(*hubItem)
	if err != nil {
		log.Fatalf("unable to marshal item : %s", err)
	}
	fmt.Printf("%s", string(buff))

	fmt.Printf("\nCurrent metrics : \n\n")
	ShowMetrics(hubItem)

}

func ShowMetrics(hubItem *cwhub.Item) {
	switch hubItem.Type {
	case cwhub.PARSERS:
		metrics := GetParserMetric(prometheusURL, hubItem.Name)
		ShowParserMetric(hubItem.Name, metrics)
	case cwhub.SCENARIOS:
		metrics := GetScenarioMetric(prometheusURL, hubItem.Name)
		ShowScenarioMetric(hubItem.Name, metrics)
	case cwhub.COLLECTIONS:
		for _, item := range hubItem.Parsers {
			metrics := GetParserMetric(prometheusURL, item)
			ShowParserMetric(item, metrics)
		}
		for _, item := range hubItem.Scenarios {
			metrics := GetScenarioMetric(prometheusURL, item)
			ShowScenarioMetric(item, metrics)
		}
		for _, item := range hubItem.Collections {
			hubItem := cwhub.GetItem(cwhub.COLLECTIONS, item)
			if hubItem == nil {
				log.Fatalf("unable to retrieve item '%s' from collection '%s'", item, hubItem.Name)
			}
			ShowMetrics(hubItem)
		}
	default:
		log.Errorf("item of type '%s' is unknown", hubItem.Type)
	}
}

/*This is a complete rip from prom2json*/
func GetParserMetric(url string, itemName string) map[string]map[string]int {
	stats := make(map[string]map[string]int)

	result := GetPrometheusMetric(url)
	for idx, fam := range result {
		if !strings.HasPrefix(fam.Name, "cs_") {
			continue
		}
		log.Debugf("round %d", idx)
		for _, m := range fam.Metrics {
			metric := m.(prom2json.Metric)
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
			}
			value := m.(prom2json.Metric).Value
			fval, err := strconv.ParseFloat(value, 32)
			if err != nil {
				log.Errorf("Unexpected int value %s : %s", value, err)
			}
			ival := int(fval)

			switch fam.Name {
			case "cs_reader_hits_total":
				if _, ok := stats[source]; !ok {
					stats[source] = make(map[string]int)
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

	result := GetPrometheusMetric(url)
	for idx, fam := range result {
		if !strings.HasPrefix(fam.Name, "cs_") {
			continue
		}
		log.Debugf("round %d", idx)
		for _, m := range fam.Metrics {
			metric := m.(prom2json.Metric)
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
			}
			ival := int(fval)

			switch fam.Name {
			case "cs_bucket_created_total":
				stats["instanciation"] += ival
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

func ShowScenarioMetric(itemName string, metrics map[string]int) {
	fmt.Printf(" - (Scenario) %s: \n", itemName)
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Current Count", "Overflows", "Instanciated", "Poured", "Expired"})
	table.Append([]string{fmt.Sprintf("%d", metrics["curr_count"]), fmt.Sprintf("%d", metrics["overflow"]), fmt.Sprintf("%d", metrics["instanciation"]), fmt.Sprintf("%d", metrics["pour"]), fmt.Sprintf("%d", metrics["underflow"])})
	table.Render()
	fmt.Println()
}

func ShowParserMetric(itemName string, metrics map[string]map[string]int) {
	fmt.Printf(" - (Parser) %s: \n", itemName)
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Source", "Lines read", "Lines parsed", "Lines unparsed"})
	for source, stats := range metrics {
		table.Append([]string{source, fmt.Sprintf("%d", stats["read"]), fmt.Sprintf("%d", stats["parsed"]), fmt.Sprintf("%d", stats["unparsed"])})
	}
	table.Render()
	fmt.Println()
}
