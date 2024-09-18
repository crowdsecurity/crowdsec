//go:build windows

package csplugin

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

/*
Due to the complexity of file permission modification with go on windows, we only test the basic behavior the broker,
not if it will actually reject plugins with invalid permissions
*/

func (s *PluginSuite) TestBrokerInit() {
	tests := []struct {
		name        string
		action      func(*testing.T)
		procCfg     csconfig.PluginCfg
		expectedErr string
	}{
		{
			name: "valid config",
		},
		{
			name:        "no plugin dir",
			expectedErr: cstest.PathNotFoundMessage,
			action: func(t *testing.T) {
				err := os.RemoveAll(s.runDir)
				require.NoError(t, err)
			},
		},
		{
			name:        "no plugin binary",
			expectedErr: "binary for plugin dummy_default not found",
			action: func(t *testing.T) {
				err := os.Remove(s.pluginBinary)
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			t := s.T()
			if tc.action != nil {
				tc.action(t)
			}
			_, err := s.InitBroker(&tc.procCfg)
			cstest.RequireErrorContains(t, err, tc.expectedErr)
		})
	}
}

func (s *PluginSuite) TestBrokerRun() {
	t := s.T()

	pb, err := s.InitBroker(nil)
	require.NoError(t, err)

	tomb := tomb.Tomb{}
	go pb.Run(&tomb)

	assert.NoFileExists(t, "./out")
	defer os.Remove("./out")

	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	pb.PluginChannel <- ProfileAlert{ProfileID: uint(0), Alert: &models.Alert{}}
	time.Sleep(time.Second * 4)

	assert.FileExists(t, ".\\out")

	content, err := os.ReadFile("./out")
	require.NoError(t, err, "Error reading file")

	decoder := json.NewDecoder(bytes.NewReader(content))

	var alerts []models.Alert

	// two notifications, one alert each

	err = decoder.Decode(&alerts)
	require.NoError(t, err)
	assert.Len(t, alerts, 1)

	err = decoder.Decode(&alerts)
	require.NoError(t, err)
	assert.Len(t, alerts, 1)

	err = decoder.Decode(&alerts)
	assert.Equal(t, err, io.EOF)
}
