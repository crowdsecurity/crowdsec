package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	plugin "github.com/hashicorp/go-plugin"
	log "github.com/sirupsen/logrus"

	"gopkg.in/yaml.v2"
)

type PluginConfig struct {
	Name     string `yaml:"name"`
	Endpoint string `yaml:"endpoint"`
	Token    string `yaml:"token"`
}

type Splunk struct {
	PluginConfigByName map[string]PluginConfig
	Client             http.Client
}

type Payload struct {
	Event string `json:"event"`
}

func (s *Splunk) Notify(ctx context.Context, notification *Notification) (*Empty, error) {
	log.Infof("received notify signal for %s config", notification.Name)
	if _, ok := s.PluginConfigByName[notification.Name]; !ok {
		return &Empty{}, fmt.Errorf("splunk invalid config name %s", notification.Name)
	}

	cfg := s.PluginConfigByName[notification.Name]
	p := Payload{Event: notification.Text}
	data, err := json.Marshal(p)
	if err != nil {
		return &Empty{}, err
	}

	req, err := http.NewRequest("POST", cfg.Endpoint, strings.NewReader(string(data)))
	if err != nil {
		return &Empty{}, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Splunk %s", cfg.Token))
	resp, err := s.Client.Do(req)

	if err != nil {
		return &Empty{}, err
	}

	if resp.StatusCode != 200 {
		content, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return &Empty{}, fmt.Errorf("got non 200 response and failed to read error %s", string(err.Error()))
		}

		return &Empty{}, fmt.Errorf("got non 200 response %s", string(content))
	}

	return &Empty{}, nil
}

func (s *Splunk) Configure(ctx context.Context, config *Config) (*Empty, error) {
	d := PluginConfig{}
	err := yaml.Unmarshal(config.Config, &d)
	s.PluginConfigByName[d.Name] = d
	return &Empty{}, err
}

func main() {
	var handshake = plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "CROWDSEC_PLUGIN_KEY",
		MagicCookieValue: os.Getenv("CROWDSEC_PLUGIN_KEY"),
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	sp := &Splunk{PluginConfigByName: make(map[string]PluginConfig), Client: *client}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			"splunk": &NotifierPlugin{
				Impl: sp,
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
