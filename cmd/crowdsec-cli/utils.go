package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/types"
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
	}
	return nil
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

func ListItem(itemType string, args []string) {

	var hubStatus []map[string]string

	if len(args) == 1 {
		hubStatus = cwhub.HubStatus(itemType, args[0], listAll)
	} else {
		hubStatus = cwhub.HubStatus(itemType, "", listAll)
	}

	if csConfig.Cscli.Output == "human" {

		table := tablewriter.NewWriter(os.Stdout)
		table.SetCenterSeparator("")
		table.SetColumnSeparator("")

		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetHeader([]string{"Name", fmt.Sprintf("%v Status", emoji.Package), "Version", "Local Path"})
		for _, v := range hubStatus {
			table.Append([]string{v["name"], v["utf8_status"], v["local_version"], v["local_path"]})
		}
		table.Render()
	} else if csConfig.Cscli.Output == "json" {
		x, err := json.MarshalIndent(hubStatus, "", " ")
		if err != nil {
			log.Fatalf("failed to unmarshal")
		}
		fmt.Printf("%s", string(x))
	} else if csConfig.Cscli.Output == "raw" {
		for _, v := range hubStatus {
			fmt.Printf("%s %s\n", v["name"], v["description"])
		}
	}
}

func InstallItem(name string, obtype string, force bool) {
	it := cwhub.GetItem(obtype, name)
	if it == nil {
		log.Fatalf("unable to retrive item : %s", name)
	}
	item := *it
	if downloadOnly && item.Downloaded && item.UpToDate {
		log.Warningf("%s is already downloaded and up-to-date", item.Name)
		if !force {
			return
		}
	}
	item, err := cwhub.DownloadLatest(csConfig.Cscli, item, forceInstall)
	if err != nil {
		log.Fatalf("error while downloading %s : %v", item.Name, err)
	}
	cwhub.AddItem(obtype, item)
	if downloadOnly {
		log.Infof("Downloaded %s to %s", item.Name, csConfig.Cscli.HubDir+"/"+item.RemotePath)
		return
	}
	item, err = cwhub.EnableItem(csConfig.Cscli, item)
	if err != nil {
		log.Fatalf("error while enabled %s : %v.", item.Name, err)
	}
	cwhub.AddItem(obtype, item)
	log.Infof("Enabled %s", item.Name)
	return
}

func RemoveMany(itemType string, name string) {
	var err error
	var disabled int
	if name != "" {
		it := cwhub.GetItem(itemType, name)
		if it == nil {
			log.Fatalf("unable to retrieve: %s", name)
		}
		item := *it
		item, err = cwhub.DisableItem(csConfig.Cscli, item, purgeRemove)
		if err != nil {
			log.Fatalf("unable to disable %s : %v", item.Name, err)
		}
		cwhub.AddItem(itemType, item)
		return
	} else if name == "" && removeAll {
		for _, v := range cwhub.GetItemMap(itemType) {
			v, err = cwhub.DisableItem(csConfig.Cscli, v, purgeRemove)
			if err != nil {
				log.Fatalf("unable to disable %s : %v", v.Name, err)
			}
			cwhub.AddItem(itemType, v)
			disabled++
		}
	}
	if name != "" && !removeAll {
		log.Errorf("%s not found", name)
		return
	}
	log.Infof("Disabled %d items", disabled)
}

func UpgradeConfig(itemType string, name string, force bool) {
	var err error
	var updated int
	var found bool

	for _, v := range cwhub.GetItemMap(itemType) {
		if name != "" && name != v.Name {
			continue
		}
		if !v.Installed {
			log.Tracef("skip %s, not installed", v.Name)
			if !force {
				continue
			}
		}
		if !v.Downloaded {
			log.Warningf("%s : not downloaded, please install.", v.Name)
			if !force {
				continue
			}
		}
		found = true
		if v.UpToDate {
			log.Infof("%s : up-to-date", v.Name)
			if !force {
				continue
			}
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
		cwhub.AddItem(itemType, v)
	}
	if !found {
		log.Errorf("Didn't find %s", name)
	} else if updated == 0 && found {
		log.Errorf("Nothing to update")
	} else if updated != 0 {
		log.Infof("Upgraded %d items", updated)
	}

}

func InspectItem(name string, objecitemType string) {

	hubItem := cwhub.GetItem(objecitemType, name)
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
		log.Tracef("round %d", idx)
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

	stats["instanciation"] = 0
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
				continue
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
		defer types.CatchPanic("crowdsec/GetPrometheusMetric")
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
	if metrics["instanciation"] == 0 {
		return
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Current Count", "Overflows", "Instanciated", "Poured", "Expired"})
	table.Append([]string{fmt.Sprintf("%d", metrics["curr_count"]), fmt.Sprintf("%d", metrics["overflow"]), fmt.Sprintf("%d", metrics["instanciation"]), fmt.Sprintf("%d", metrics["pour"]), fmt.Sprintf("%d", metrics["underflow"])})

	fmt.Printf(" - (Scenario) %s: \n", itemName)
	table.Render()
	fmt.Println()
}

func ShowParserMetric(itemName string, metrics map[string]map[string]int) {
	skip := true

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Parsers", "Hits", "Parsed", "Unparsed"})
	for source, stats := range metrics {
		if stats["hits"] > 0 {
			table.Append([]string{source, fmt.Sprintf("%d", stats["hits"]), fmt.Sprintf("%d", stats["parsed"]), fmt.Sprintf("%d", stats["unparsed"])})
			skip = false
		}
	}
	if !skip {
		fmt.Printf(" - (Parser) %s: \n", itemName)
		table.Render()
		fmt.Println()
	}
}

//it's a rip of the cli version, but in silent-mode
func silenceInstallItem(name string, obtype string) (string, error) {
	var item *cwhub.Item
	item = cwhub.GetItem(obtype, name)
	if item == nil {
		return "", fmt.Errorf("error retrieving item")
	}
	it := *item
	if downloadOnly && it.Downloaded && it.UpToDate {
		return fmt.Sprintf("%s is already downloaded and up-to-date", it.Name), nil
	}
	it, err := cwhub.DownloadLatest(csConfig.Cscli, it, forceInstall)
	if err != nil {
		return "", fmt.Errorf("error while downloading %s : %v", it.Name, err)
	}
	if err := cwhub.AddItem(obtype, it); err != nil {
		return "", err
	}

	if downloadOnly {
		return fmt.Sprintf("Downloaded %s to %s", it.Name, csConfig.Cscli.HubDir+"/"+it.RemotePath), nil
	}
	it, err = cwhub.EnableItem(csConfig.Cscli, it)
	if err != nil {
		return "", fmt.Errorf("error while enabled %s : %v", it.Name, err)
	}
	if err := cwhub.AddItem(obtype, it); err != nil {
		return "", err
	}
	return fmt.Sprintf("Enabled %s", it.Name), nil
}

func RestoreHub(dirPath string) error {
	var err error

	for _, itype := range cwhub.ItemTypes {
		itemDirectory := fmt.Sprintf("%s/%s/", dirPath, itype)
		if _, err = os.Stat(itemDirectory); err != nil {
			log.Infof("no %s in backup", itype)
			continue
		}
		/*restore the upstream items*/
		upstreamListFN := fmt.Sprintf("%s/upstream-%s.json", itemDirectory, itype)
		file, err := ioutil.ReadFile(upstreamListFN)
		if err != nil {
			return fmt.Errorf("error while opening %s : %s", upstreamListFN, err)
		}
		var upstreamList []string
		err = json.Unmarshal([]byte(file), &upstreamList)
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
		files, err := ioutil.ReadDir(itemDirectory)
		if err != nil {
			return fmt.Errorf("failed enumerating files of %s : %s", itemDirectory, err)
		}
		for _, file := range files {
			//dir are stages, keep track
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
			ifiles, err := ioutil.ReadDir(itemDirectory + "/" + stage + "/")
			if err != nil {
				return fmt.Errorf("failed enumerating files of %s : %s", itemDirectory+"/"+stage, err)
			}
			//finaly copy item
			for _, tfile := range ifiles {
				log.Infof("Going to restore local/tainted [%s]", tfile.Name())
				sourceFile := fmt.Sprintf("%s/%s/%s", itemDirectory, stage, tfile.Name())
				destinationFile := fmt.Sprintf("%s%s", stagedir, tfile.Name())
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
		if itemMap != nil {
			itemDirectory = fmt.Sprintf("%s/%s/", dirPath, itemType)
			if err := os.MkdirAll(itemDirectory, os.ModePerm); err != nil {
				return fmt.Errorf("error while creating %s : %s", itemDirectory, err)
			}
			upstreamParsers = []string{}
			stage := ""
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
						tmp := strings.Split(v.LocalPath, "/")
						stage = "/" + tmp[len(tmp)-2] + "/"
						fstagedir := fmt.Sprintf("%s%s", itemDirectory, stage)
						if err := os.MkdirAll(fstagedir, os.ModePerm); err != nil {
							return fmt.Errorf("error while creating stage dir %s : %s", fstagedir, err)
						}
					}
					clog.Debugf("[%s] : backuping file (tainted:%t local:%t up-to-date:%t)", k, v.Tainted, v.Local, v.UpToDate)
					tfile := fmt.Sprintf("%s%s%s", itemDirectory, stage, v.FileName)
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
			err = ioutil.WriteFile(upstreamParsersFname, upstreamParsersContent, 0644)
			if err != nil {
				return fmt.Errorf("unable to write to %s %s : %s", itemType, upstreamParsersFname, err)
			}
			clog.Infof("Wrote %d entries for %s to %s", len(upstreamParsers), itemType, upstreamParsersFname)

		} else {
			clog.Infof("No %s to backup.", itemType)
		}
	}

	return nil
}
