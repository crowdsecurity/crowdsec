// challenge_customjs.go resolves the browser-side detection script an
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

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

// LoadCustomJS concatenates the declared scripts in order, so a base detection
// bundle and a site-specific fix compose. Read failures are logged, not fatal:
// bot detection has to survive a data file that hasn't downloaded yet.
func (wc *AppsecConfig) LoadCustomJS(dataDir string) string {
	var out []byte

	for _, d := range wc.Data {
		if d == nil || d.Type != exprhelpers.ChallengeJSDataType {
			continue
		}

		if d.DestPath == "" {
			wc.Logger.Errorf("missing dest_file for %s data in appsec-config %s", exprhelpers.ChallengeJSDataType, wc.Name)
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

		wc.Logger.Infof("loaded custom challenge script %s (%d bytes)", d.DestPath, len(content))

		// Guards against a file with no trailing newline or semicolon splicing
		// into the next one.
		if len(out) > 0 {
			out = append(out, '\n', ';', '\n')
		}

		out = append(out, content...)
	}

	return string(out)
}
