package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
	"github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	mail "github.com/xhit/go-simple-mail/v2"
	"gopkg.in/yaml.v2"
)

var baseLogger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name:       "email-plugin",
	Level:      hclog.LevelFromString("INFO"),
	Output:     os.Stderr,
	JSONFormat: true,
})

var AuthStringToType map[string]mail.AuthType = map[string]mail.AuthType{
	"none":    mail.AuthNone,
	"crammd5": mail.AuthCRAMMD5,
	"login":   mail.AuthLogin,
	"plain":   mail.AuthPlain,
}

var EncryptionStringToType map[string]mail.Encryption = map[string]mail.Encryption{
	"ssltls":   mail.EncryptionSSLTLS,
	"starttls": mail.EncryptionSTARTTLS,
	"none":     mail.EncryptionNone,
}

type PluginConfig struct {
	Name     string  `yaml:"name"`
	LogLevel *string `yaml:"log_level"`

	SMTPHost       string       `yaml:"smtp_host"`
	SMTPPort       int          `yaml:"smtp_port"`
	SMTPUsername   string       `yaml:"smtp_username"`
	SMTPPassword   string       `yaml:"smtp_password"`
	SenderEmail    string       `yaml:"sender_email"`
	SenderName     string       `yaml:"sender_name"`
	ReceiverEmails []string     `yaml:"receiver_emails"`
	EmailSubject   string       `yaml:"email_subject"`
	EncryptionType string       `yaml:"encryption_type"`
	AuthType       string       `yaml:"auth_type"`
	HeloHost       string       `yaml:"helo_host"`
	EmailTimeout   EmailTimeout `yaml:"email_timeout"`
}

type EmailTimeout struct {
	Connect   string        `yaml:"connect"`
	Send      string        `yaml:"send"`
	P_Connect time.Duration `yaml:"-"`
	P_Send    time.Duration `yaml:"-"`
}

func (e *EmailTimeout) Parse() error {
	var err error
	e.P_Connect, err = time.ParseDuration(e.Connect)
	if err != nil {
		return fmt.Errorf("invalid connect timeout: %s", err)
	}
	e.P_Send, err = time.ParseDuration(e.Send)
	if err != nil {
		return fmt.Errorf("invalid send timeout: %s", err)
	}
	return nil
}

type EmailPlugin struct {
	ConfigByName map[string]PluginConfig
}

func (n *EmailPlugin) Configure(ctx context.Context, config *protobufs.Config) (*protobufs.Empty, error) {
	d := PluginConfig{
		SMTPPort:       25,
		SenderName:     "Crowdsec",
		EmailSubject:   "Crowdsec notification",
		EncryptionType: "ssltls",
		AuthType:       "login",
		SenderEmail:    "crowdsec@crowdsec.local",
		HeloHost:       "localhost",
		EmailTimeout:   EmailTimeout{Connect: "10s", Send: "10s"},
	}

	if err := yaml.Unmarshal(config.Config, &d); err != nil {
		return nil, err
	}

	if d.Name == "" {
		return nil, fmt.Errorf("name is required")
	}

	if d.SMTPHost == "" {
		return nil, fmt.Errorf("SMTP host is not set")
	}

	if d.ReceiverEmails == nil || len(d.ReceiverEmails) == 0 {
		return nil, fmt.Errorf("Receiver emails are not set")
	}

	if err := d.EmailTimeout.Parse(); err != nil {
		return nil, err
	}

	n.ConfigByName[d.Name] = d
	baseLogger.Debug(fmt.Sprintf("Email plugin '%s' use SMTP host '%s:%d'", d.Name, d.SMTPHost, d.SMTPPort))
	return &protobufs.Empty{}, nil
}

func (n *EmailPlugin) Notify(ctx context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {
	if _, ok := n.ConfigByName[notification.Name]; !ok {
		return nil, fmt.Errorf("invalid plugin config name %s", notification.Name)
	}
	cfg := n.ConfigByName[notification.Name]

	logger := baseLogger.Named(cfg.Name)

	if cfg.LogLevel != nil && *cfg.LogLevel != "" {
		logger.SetLevel(hclog.LevelFromString(*cfg.LogLevel))
	}

	logger.Debug("got notification")

	server := mail.NewSMTPClient()
	server.Host = cfg.SMTPHost
	server.Port = cfg.SMTPPort
	server.Username = cfg.SMTPUsername
	server.Password = cfg.SMTPPassword
	server.Encryption = EncryptionStringToType[cfg.EncryptionType]
	server.Authentication = AuthStringToType[cfg.AuthType]
	server.Helo = cfg.HeloHost
	server.ConnectTimeout = cfg.EmailTimeout.P_Connect
	server.SendTimeout = cfg.EmailTimeout.P_Send

	logger.Debug("making smtp connection")
	smtpClient, err := server.Connect()
	if err != nil {
		return &protobufs.Empty{}, err
	}
	logger.Debug("smtp connection done")

	email := mail.NewMSG()
	email.SetFrom(fmt.Sprintf("%s <%s>", cfg.SenderName, cfg.SenderEmail)).
		AddTo(cfg.ReceiverEmails...).
		SetSubject(cfg.EmailSubject)
	email.SetBody(mail.TextHTML, notification.Text)

	err = email.Send(smtpClient)
	if err != nil {
		return &protobufs.Empty{}, err
	}
	logger.Info(fmt.Sprintf("sent email to %v", cfg.ReceiverEmails))
	return &protobufs.Empty{}, nil
}

func main() {
	var handshake = plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "CROWDSEC_PLUGIN_KEY",
		MagicCookieValue: os.Getenv("CROWDSEC_PLUGIN_KEY"),
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			"email": &protobufs.NotifierPlugin{
				Impl: &EmailPlugin{ConfigByName: make(map[string]PluginConfig)},
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
		Logger:     baseLogger,
	})
}
