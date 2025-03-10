package cwhub

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/crowdsec/pkg/emoji"
)

func TestItemStateText(t *testing.T) {
	// Test the text representation of an item state.
	type test struct {
		state    ItemState
		want     string
		wantIcon string
	}

	tests := []test{
		{
			ItemState{
				LocalPath:    "path/to/install",
				UpToDate:     false,
				Tainted:      false,
				DownloadPath: "path/to/download",
			},
			"enabled,update-available",
			emoji.Warning,
		}, {
			ItemState{
				LocalPath:    "path/to/install",
				UpToDate:     true,
				Tainted:      false,
				DownloadPath: "path/to/download",
			},
			"enabled",
			emoji.CheckMark,
		}, {
			ItemState{
				LocalPath:    "path/to/install",
				UpToDate:     false,
				local:        true,
				Tainted:      false,
				DownloadPath: "",
			},
			"enabled,local",
			emoji.House,
		}, {
			ItemState{
				LocalPath:    "",
				UpToDate:     false,
				Tainted:      false,
				DownloadPath: "path/to/download",
			},
			"disabled,update-available",
			emoji.Prohibited,
		}, {
			ItemState{
				LocalPath:    "path/to/install",
				UpToDate:     false,
				Tainted:      true,
				DownloadPath: "path/to/download",
			},
			"enabled,tainted",
			emoji.Warning,
		},
	}

	for idx, tc := range tests {
		t.Run("Test "+strconv.Itoa(idx), func(t *testing.T) {
			got := tc.state.Text()
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantIcon, tc.state.Emoji())
		})
	}
}
