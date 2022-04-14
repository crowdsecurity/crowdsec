package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
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
	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v2"
)

func printHelp(cmd *cobra.Command) {
	err := cmd.Help()
	if err != nil {
		log.Fatalf("unable to print help(): %s", err)
	}
}

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
	case "country":
		*scope = types.Country
	case "as":
		*scope = types.AS
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
		csVersion := cwversion.VersionStrip()
		if csVersion == latest {
			cwhub.HubBranch = "master"
		} else if semver.Compare(csVersion, latest) == 1 { // if current version is greater than the latest we are in pre-release
			log.Debugf("Your current crowdsec version seems to be a pre-release (%s)", csVersion)
			cwhub.HubBranch = "master"
		} else if csVersion == "" {
			log.Warningf("Crowdsec version is '', using master branch for the hub")
			cwhub.HubBranch = "master"
		} else {
			log.Warnf("Crowdsec is not the latest version. Current version is '%s' and the latest stable version is '%s'. Please update it!", csVersion, latest)
			log.Warnf("As a result, you will not be able to use parsers/scenarios/collections added to Crowdsec Hub after CrowdSec %s", latest)
			cwhub.HubBranch = csVersion
		}
		log.Debugf("Using branch '%s' for the hub", cwhub.HubBranch)
	}
	return nil
}

func ListItems(itemTypes []string, args []string, showType bool, showHeader bool) {

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
			fmt.Println(strings.ToUpper(itemType))
			table := tablewriter.NewWriter(os.Stdout)
			table.SetCenterSeparator("")
			table.SetColumnSeparator("")
			table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
			table.SetAlignment(tablewriter.ALIGN_LEFT)
			table.SetHeader([]string{"Name", fmt.Sprintf("%v Status", emoji.Package), "Version", "Local Path"})
			for _, status := range statuses {
				table.Append([]string{status.Name, status.UTF8_Status, status.LocalVersion, status.LocalPath})
			}
			table.Render()
		}
	} else if csConfig.Cscli.Output == "json" {
		x, err := json.MarshalIndent(hubStatusByItemType, "", " ")
		if err != nil {
			log.Fatalf("failed to unmarshal")
		}
		fmt.Printf("%s", string(x))
	} else if csConfig.Cscli.Output == "raw" {
		csvwriter := csv.NewWriter(os.Stdout)
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

func InstallItem(name string, obtype string, force bool) error {
	it := cwhub.GetItem(obtype, name)
	if it == nil {
		return fmt.Errorf("unable to retrieve item : %s", name)
	}
	item := *it
	if downloadOnly && item.Downloaded && item.UpToDate {
		log.Warningf("%s is already downloaded and up-to-date", item.Name)
		if !force {
			return nil
		}
	}
	item, err := cwhub.DownloadLatest(csConfig.Hub, item, force, false)
	if err != nil {
		return fmt.Errorf("error while downloading %s : %v", item.Name, err)
	}
	cwhub.AddItem(obtype, item)
	if downloadOnly {
		log.Infof("Downloaded %s to %s", item.Name, csConfig.Hub.HubDir+"/"+item.RemotePath)
		return nil
	}
	item, err = cwhub.EnableItem(csConfig.Hub, item)
	if err != nil {
		return fmt.Errorf("error while enabling  %s : %v.", item.Name, err)
	}
	cwhub.AddItem(obtype, item)
	log.Infof("Enabled %s", item.Name)

	return nil
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
		item, err = cwhub.DisableItem(csConfig.Hub, item, purge, forceAction)
		if err != nil {
			log.Fatalf("unable to disable %s : %v", item.Name, err)
		}
		cwhub.AddItem(itemType, item)
		return
	} else if name == "" && all {
		for _, v := range cwhub.GetItemMap(itemType) {
			v, err = cwhub.DisableItem(csConfig.Hub, v, purge, forceAction)
			if err != nil {
				log.Fatalf("unable to disable %s : %v", v.Name, err)
			}
			cwhub.AddItem(itemType, v)
			disabled++
		}
	}
	if name != "" && !all {
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
			continue
		}

		if !v.Downloaded {
			log.Warningf("%s : not downloaded, please install.", v.Name)
			continue
		}

		found = true
		if v.UpToDate {
			log.Infof("%s : up-to-date", v.Name)

			if err = cwhub.DownloadDataIfNeeded(csConfig.Hub, v, force); err != nil {
				log.Fatalf("%s : download failed : %v", v.Name, err)
			}

			if !force {
				continue
			}
		}
		v, err = cwhub.DownloadLatest(csConfig.Hub, v, force, true)
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
	if !found && name == "" {
		log.Infof("No %s installed, nothing to upgrade", itemType)
	} else if !found {
		log.Errorf("Item '%s' not found in hub", name)
	} else if updated == 0 && found {
		if name == "" {
			log.Infof("All %s are already up-to-date", itemType)
		} else {
			log.Infof("Item '%s' is up-to-date", name)
		}
	} else if updated != 0 {
		log.Infof("Upgraded %d items", updated)
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

	if csConfig.Prometheus.Enabled {
		if csConfig.Prometheus.ListenAddr == "" || csConfig.Prometheus.ListenPort == 0 {
			log.Warningf("No prometheus address or port specified in '%s', can't show metrics", *csConfig.FilePath)
			return
		}
		if prometheusURL == "" {
			log.Debugf("No prometheus URL provided using: %s:%d", csConfig.Prometheus.ListenAddr, csConfig.Prometheus.ListenPort)
			prometheusURL = fmt.Sprintf("http://%s:%d/metrics", csConfig.Prometheus.ListenAddr, csConfig.Prometheus.ListenPort)
		}
		fmt.Printf("\nCurrent metrics : \n\n")
		ShowMetrics(hubItem)
	}
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

func RestoreHub(dirPath string) error {
	var err error

	if err := csConfig.LoadHub(); err != nil {
		return err
	}
	if err := setHubBranch(); err != nil {
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
		err = ioutil.WriteFile(upstreamParsersFname, upstreamParsersContent, 0644)
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
