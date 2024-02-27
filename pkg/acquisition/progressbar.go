package acquisition

import (
	"os"
	"time"

	isatty "github.com/mattn/go-isatty"
	progressbar "github.com/schollz/progressbar/v3"
	tomb "gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// injectProgressBar will inject a progress bar in the acquisition pipeline if stderr is a terminal
func injectProgressBar(output chan types.Event, acquisTomb *tomb.Tomb) chan types.Event {
	if !isatty.IsTerminal(os.Stderr.Fd()) && !isatty.IsCygwinTerminal(os.Stderr.Fd()) {
		return output
	}

	ret := make(chan types.Event)

	go func() {
		pb := progressbar.NewOptions(-1,
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionClearOnFinish(),
			progressbar.OptionShowCount(),
			progressbar.OptionShowIts(),
			progressbar.OptionSpinnerType(43),
			progressbar.OptionThrottle(time.Second/20),
			progressbar.OptionSetRenderBlankState(false),
		)

		for {
			select {
			case <-acquisTomb.Dying():
				if pb != nil {
					pb.Finish()
				}
				return
			case evt := <-ret:
				pb.Add(1)
				output <- evt
			}
		}
	}()

	return ret
}
