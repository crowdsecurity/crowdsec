package main

import (
	"context"
	"fmt"
	"time"

	protobufs "github.com/crowdsecurity/crowdsec/pkg/protobufs"
	runtime "github.com/go-openapi/runtime/client"
	strfmt "github.com/go-openapi/strfmt"
	hclog "github.com/hashicorp/go-hclog"
	alert "github.com/prometheus/alertmanager/api/v2/client/alert"
	"github.com/prometheus/alertmanager/api/v2/models"
	yaml "gopkg.in/yaml.v2"
)

type AlertmanagerPlugin struct {
	ConfigByName map[string]PluginConfig
}

func (n *AlertmanagerPlugin) Configure(ctx context.Context, config *protobufs.Config) (*protobufs.Empty, error) {
	d := PluginConfig{}
	if err := yaml.Unmarshal(config.Config, &d); err != nil {
		return nil, err
	}
	n.ConfigByName[d.Name] = d
	return &protobufs.Empty{}, nil
}

func (n *AlertmanagerPlugin) Notify(ctx context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {
	if _, ok := n.ConfigByName[notification.Name]; !ok {
		return nil, fmt.Errorf("invalid plugin config name %s", notification.Name)
	}
	cfg := n.ConfigByName[notification.Name]
	if cfg.LogLevel != nil && *cfg.LogLevel != "" {
		logger.SetLevel(hclog.LevelFromString(*cfg.LogLevel))
	} else {
		logger.SetLevel(hclog.Info)
	}

	format := strfmt.NewFormats()
	transport := runtime.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	transport.DefaultAuthentication = runtime.BasicAuth(cfg.User, cfg.Password)
	client := alert.New(transport, format)

	alertParams := n.createPostAlertParams(ctx, cfg, notification)
	_, err := client.PostAlerts(alertParams)
	if err != nil {
		logger.Error("ErreurPostAlerts:", err.Error())
		return nil, err
	} else {
		logger.Info(fmt.Sprintf(" %s ", notification.Name))
	}
	return &protobufs.Empty{}, nil
}

func (n *AlertmanagerPlugin) createPostAlertParams(ctx context.Context, cfg PluginConfig, notification *protobufs.Notification) *alert.PostAlertsParams {
	alertParams := alert.NewPostAlertsParams()
	now := time.Now()
	params := &models.PostableAlert{
		StartsAt: strfmt.DateTime(now),
		EndsAt:   strfmt.DateTime(now.Add(5 * time.Minute)),
		Alert: models.Alert{
			Labels: models.LabelSet{
				"alertname": "crowdsec_alert",
				"source":   cfg.Source,
				"team":      cfg.Team,
				"text":      notification.Text,
			},
		},
	}
	alertParams.Alerts = models.PostableAlerts{params}
	return alertParams
}
