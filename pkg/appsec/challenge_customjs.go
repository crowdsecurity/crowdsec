// challenge_customjs.go resolves the browser-side detection modules an
// appsec-config ships through the hub's `data:` mechanism:
//
//	data:
//	  - source_url: https://hub-data.crowdsec.net/challenge/custom-v1.js
//	    dest_file: challenge/custom.js
//	    type: challenge-js
//

package appsec

import (
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

// LoadCustomJS compiles the declared modules into the script served to the
// browser.
func (wc *AppsecConfig) LoadCustomJS(dataDir string) string {
	detectors := wc.readCustomJS(dataDir)
	if len(detectors) == 0 {
		return ""
	}

	out, rejected := challenge.AssembleCustomJS(detectors)

	for _, r := range rejected {
		wc.Logger.Errorf("custom challenge script %s rejected: %s", r.Name, r.Err)
	}

	// The page still renders and nothing at the HTTP layer shows a detector
	// missing, so this line is the only place a dropped one surfaces.
	wc.Logger.Infof("custom challenge scripts: %d loaded, %d rejected", len(detectors)-len(rejected), len(rejected))

	return out
}

// readCustomJS collects the declared modules in order. Read failures are
// logged and skipped rather than returned, so one unreadable file costs only
// its own detector.
func (wc *AppsecConfig) readCustomJS(dataDir string) []challenge.Detector {
	var (
		detectors []challenge.Detector
		seen      = make(map[string]bool)
	)

	for _, d := range wc.Data {
		if d == nil || d.Type != exprhelpers.ChallengeJSDataType {
			continue
		}

		if d.DestPath == "" {
			wc.Logger.Errorf("missing dest_file for %s data in appsec-config %s", exprhelpers.ChallengeJSDataType, wc.Name)
			continue
		}

		// esbuild resolves a module once per path, so a repeated dest_file
		// would otherwise register the same hook twice.
		if seen[d.DestPath] {
			wc.Logger.Warnf("custom challenge script %s declared more than once, ignoring the repeat", d.DestPath)
			continue
		}

		path, err := cwhub.SafePath(dataDir, d.DestPath)
		if err != nil {
			wc.Logger.Errorf("invalid dest_file %q: %s", d.DestPath, err)
			continue
		}

		content, err := os.ReadFile(path)
		if err != nil {
			wc.Logger.Errorf("unable to read custom challenge script %s: %s", d.DestPath, err)
			continue
		}

		seen[d.DestPath] = true

		wc.Logger.Infof("loaded custom challenge script %s (%d bytes)", d.DestPath, len(content))

		detectors = append(detectors, challenge.Detector{Name: d.DestPath, Source: string(content)})
	}

	return detectors
}
