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
				Installed:  true,
				UpToDate:   false,
				Tainted:    false,
				Downloaded: true,
			},
			"enabled,update-available",
			emoji.Warning,
		}, {
			ItemState{
				Installed:  true,
				UpToDate:   true,
				Tainted:    false,
				Downloaded: true,
			},
			"enabled",
			emoji.CheckMark,
		}, {
			ItemState{
				Installed:  true,
				UpToDate:   false,
				local:      true,
				Tainted:    false,
				Downloaded: false,
			},
			"enabled,local",
			emoji.House,
		}, {
			ItemState{
				Installed:  false,
				UpToDate:   false,
				Tainted:    false,
				Downloaded: true,
			},
			"disabled,update-available",
			emoji.Prohibited,
		}, {
			ItemState{
				Installed:  true,
				UpToDate:   false,
				Tainted:    true,
				Downloaded: true,
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
