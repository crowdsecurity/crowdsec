module github.com/crowdsecurity/email-plugin

go 1.20

replace github.com/crowdsecurity/crowdsec => ../../../

require (
	github.com/crowdsecurity/crowdsec v1.5.0
	github.com/hashicorp/go-hclog v1.0.0
	github.com/hashicorp/go-plugin v1.4.3
	github.com/xhit/go-simple-mail/v2 v2.10.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/fatih/color v1.13.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/hashicorp/yamux v0.0.0-20180604194846-3520598351bb // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mitchellh/go-testing-interface v1.0.0 // indirect
	github.com/oklog/run v1.0.0 // indirect
	golang.org/x/net v0.7.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	google.golang.org/genproto v0.0.0-20220502173005-c8bf987b8c21 // indirect
	google.golang.org/grpc v1.47.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
)
