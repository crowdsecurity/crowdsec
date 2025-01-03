// Package cwhub is responsible for providing the state of the local hub to the security engine and cscli command.
// Installation, upgrade and removal of items or data files has been moved to pkg/hubops.
//
// # Definitions
//
//   - A hub ITEM is a file that defines a parser, a scenario, a collection... in the case of a collection, it has dependencies on other hub items.
//   - The hub INDEX is a JSON file that contains a tree of available hub items.
//   - A REMOTE HUB is an HTTP server that hosts the hub index and the hub items. It can serve from several branches, usually linked to the CrowdSec version.
//   - A LOCAL HUB is a directory that contains a copy of the hub index and the downloaded hub items.
//
// Once downloaded, hub items can be installed by linking to them from the configuration directory.
// If an item is present in the configuration directory but it's not a link to the local hub, it is
// considered as a LOCAL ITEM and won't be removed or upgraded.
//
// # Directory Structure
//
// A typical directory layout is the following:
//
// For the local hub (HubDir = /etc/crowdsec/hub):
//
//   - /etc/crowdsec/hub/.index.json
//   - /etc/crowdsec/hub/parsers/{stage}/{author}/{parser-name}.yaml
//   - /etc/crowdsec/hub/scenarios/{author}/{scenario-name}.yaml
//
// For the configuration directory (InstallDir = /etc/crowdsec):
//
//   - /etc/crowdsec/parsers/{stage}/{parser-name.yaml} -> /etc/crowdsec/hub/parsers/{stage}/{author}/{parser-name}.yaml
//   - /etc/crowdsec/scenarios/{scenario-name.yaml} -> /etc/crowdsec/hub/scenarios/{author}/{scenario-name}.yaml
//   - /etc/crowdsec/scenarios/local-scenario.yaml
//
// Note that installed items are not grouped by author, this may change in the future if we want to
// support items with the same name from different authors.
//
// Only parsers and postoverflows have the concept of stage.
//
// Additionally, an item can reference a DATA SET that is installed in a different location than
// the item itself. These files are stored in the data directory (InstallDataDir = /var/lib/crowdsec/data).
//
//   - /var/lib/crowdsec/data/http_path_traversal.txt
//   - /var/lib/crowdsec/data/jira_cve_2021-26086.txt
//   - /var/lib/crowdsec/data/log4j2_cve_2021_44228.txt
//   - /var/lib/crowdsec/data/sensitive_data.txt
//
// # Using the package
//
// The main entry point is the Hub struct. You can create a new instance with NewHub().
// This constructor takes three parameters, but only the LOCAL HUB configuration is required:
//
//	import (
//		"fmt"
//		"github.com/crowdsecurity/crowdsec/pkg/csconfig"
//		"github.com/crowdsecurity/crowdsec/pkg/cwhub"
//	)
//
//	localHub := csconfig.LocalHubCfg{
//		HubIndexFile:	"/etc/crowdsec/hub/.index.json",
//		HubDir:		"/etc/crowdsec/hub",
//		InstallDir:	"/etc/crowdsec",
//		InstallDataDir: "/var/lib/crowdsec/data",
//	}
//
//	hub, err := cwhub.NewHub(localHub, nil, logger)
//	if err != nil {
//		return fmt.Errorf("unable to initialize hub: %w", err)
//	}
//
// If the logger is nil, the item-by-item messages will be discarded, including warnings.
// After configuring the hub, you must sync its state with items on disk.
//
//	err := hub.Load()
//	if err != nil {
//		return fmt.Errorf("unable to load hub: %w", err)
//	}
//
// Now you can use the hub object to access the existing items:
//
//	// list all the parsers
//	for _, parser := range hub.GetItemsByType(cwhub.PARSERS, false) {
//		fmt.Printf("parser: %s\n", parser.Name)
//	}
//
//	// retrieve a specific collection
//	coll := hub.GetItem(cwhub.COLLECTIONS, "crowdsecurity/linux")
//	if coll == nil {
//		return fmt.Errorf("collection not found")
//	}
//
// Some commands require an object to provide the hub index, or contents:
//
//	indexProvider := cwhub.Downloader{
//		URLTemplate: "https://cdn-hub.crowdsec.net/crowdsecurity/%s/%s",
//		Branch: "master",
//	}
//
// The URLTemplate is a string that will be used to build the URL of the remote hub. It must contain two
// placeholders: the branch and the file path (it will be an index or an item).
//
// Before calling hub.Load(), you can update the index file by calling the Update() method:
//
//	err := hub.Update(context.Background(), indexProvider)
//	if err != nil {
//		return fmt.Errorf("unable to update hub index: %w", err)
//	}
//
// Note that the command will fail if the hub has already been synced. If you want to do it (ex. after a configuration
// change the application is notified with SIGHUP) you have to instantiate a new hub object and dispose of the old one.
package cwhub
