package cwhub

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

// const HubIndexFile = ".index.json"

// RemoteHubCfg contains where to find the remote hub, which branch etc.
type RemoteHubCfg struct {
	Branch      string
	URLTemplate string
	IndexPath   string
}

type Hub struct {
	Items          HubItems
	local          *csconfig.LocalHubCfg
	remote         *RemoteHubCfg
	skippedLocal   int
	skippedTainted int
}

var (
	theHub           *Hub
	ErrIndexNotFound = fmt.Errorf("index not found")
)

// GetHub returns the hub singleton
// it returns an error if it's not initialized to avoid nil dereference
// XXX: convenience function that we should get rid of at some point
func GetHub() (*Hub, error) {
	if theHub == nil {
		return nil, fmt.Errorf("hub not initialized")
	}

	return theHub, nil
}

// InitHub initializes the Hub, syncs the local state and returns the singleton for immediate use
func InitHub(local *csconfig.LocalHubCfg, remote *RemoteHubCfg) (*Hub, error) {
	if local == nil {
		return nil, fmt.Errorf("no hub configuration found")
	}

	log.Debugf("loading hub idx %s", local.HubIndexFile)

	bidx, err := os.ReadFile(local.HubIndexFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read index file: %w", err)
	}

	ret, err := ParseIndex(bidx)
	if err != nil {
		if !errors.Is(err, ErrMissingReference) {
			return nil, fmt.Errorf("unable to load existing index: %w", err)
		}

		// XXX: why the error check if we bail out anyway?
		return nil, err
	}

	theHub = &Hub{
		Items:  ret,
		local:  local,
		remote: remote,
	}

	_, err = theHub.LocalSync()
	if err != nil {
		return nil, fmt.Errorf("failed to sync Hub index with local deployment : %w", err)
	}

	return theHub, nil
}

// InitHubUpdate is like InitHub but downloads and updates the index instead of reading from the disk
// It is used to inizialize the hub when there is no index file yet
func InitHubUpdate(local *csconfig.LocalHubCfg, remote *RemoteHubCfg) (*Hub, error) {
	if local == nil {
		return nil, fmt.Errorf("no configuration found for hub")
	}

	bidx, err := remote.DownloadIndex(local.HubIndexFile)
	if err != nil {
		return nil, fmt.Errorf("failed to download index: %w", err)
	}

	ret, err := ParseIndex(bidx)
	if err != nil {
		if !errors.Is(err, ErrMissingReference) {
			return nil, fmt.Errorf("failed to read index: %w", err)
		}
	}

	theHub = &Hub{
		Items:  ret,
		local:  local,
		remote: remote,
	}

	if _, err := theHub.LocalSync(); err != nil {
		return nil, fmt.Errorf("failed to sync: %w", err)
	}

	return theHub, nil
}

func (r RemoteHubCfg) urlTo(remotePath string) (string, error) {
	if fmt.Sprintf(r.URLTemplate, "%s", "%s") != r.URLTemplate {
		return "", fmt.Errorf("invalid URL template '%s'", r.URLTemplate)
	}

	return fmt.Sprintf(r.URLTemplate, r.Branch, remotePath), nil
}

// DownloadIndex downloads the latest version of the index and returns the content
func (r RemoteHubCfg) DownloadIndex(localPath string) ([]byte, error) {
	url, err := r.urlTo(r.IndexPath)
	if err != nil {
		return nil, fmt.Errorf("failed to build hub index request: %w", err)
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request for hub index: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed http request for hub index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, ErrIndexNotFound
		}

		return nil, fmt.Errorf("bad http code %d while requesting %s", resp.StatusCode, req.URL.String())
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request answer for hub index: %w", err)
	}

	oldContent, err := os.ReadFile(localPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warningf("failed to read hub index: %s", err)
		}
	} else if bytes.Equal(body, oldContent) {
		log.Info("hub index is up to date")
		return body, nil
	}

	file, err := os.OpenFile(localPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)

	if err != nil {
		return nil, fmt.Errorf("while opening hub index file: %w", err)
	}
	defer file.Close()

	wsize, err := file.Write(body)
	if err != nil {
		return nil, fmt.Errorf("while writing hub index file: %w", err)
	}

	log.Infof("Wrote index to %s, %d bytes", localPath, wsize)

	return body, nil
}

// ParseIndex takes the content of an index file and returns the map of associated parsers/scenarios/collections
func ParseIndex(buff []byte) (HubItems, error) {
	var (
		RawIndex     HubItems
		missingItems []string
	)

	if err := json.Unmarshal(buff, &RawIndex); err != nil {
		return nil, fmt.Errorf("failed to unmarshal index: %w", err)
	}

	log.Debugf("%d item types in hub index", len(ItemTypes))

	// Iterate over the different types to complete the struct
	for _, itemType := range ItemTypes {
		log.Tracef("%s: %d items", itemType, len(RawIndex[itemType]))

		for name, item := range RawIndex[itemType] {
			item.Name = name
			item.Type = itemType
			x := strings.Split(item.RemotePath, "/")
			item.FileName = x[len(x)-1]
			RawIndex[itemType][name] = item

			if itemType != COLLECTIONS {
				continue
			}

			// if it's a collection, check its sub-items are present
			// XXX should be done later
			for _, sub := range item.SubItems() {
				if _, ok := RawIndex[sub.Type][sub.Name]; !ok {
					log.Errorf("Referred %s %s in collection %s doesn't exist.", sub.Type, sub.Name, item.Name)
					missingItems = append(missingItems, sub.Name)
				}
			}
		}
	}

	if len(missingItems) > 0 {
		return RawIndex, fmt.Errorf("%q: %w", missingItems, ErrMissingReference)
	}

	return RawIndex, nil
}

// ItemStats returns total counts of the hub items
func (h *Hub) ItemStats() []string {
	loaded := ""

	for _, itemType := range ItemTypes {
		// ensure the order is always the same
		if h.Items[itemType] == nil {
			continue
		}

		if len(h.Items[itemType]) == 0 {
			continue
		}

		loaded += fmt.Sprintf("%d %s, ", len(h.Items[itemType]), itemType)
	}

	loaded = strings.Trim(loaded, ", ")
	if loaded == "" {
		// empty hub
		loaded = "0 items"
	}

	ret := []string{
		fmt.Sprintf("Loaded: %s", loaded),
	}

	if h.skippedLocal > 0 || h.skippedTainted > 0 {
		ret = append(ret, fmt.Sprintf("Unmanaged items: %d local, %d tainted", h.skippedLocal, h.skippedTainted))
	}

	return ret
}
