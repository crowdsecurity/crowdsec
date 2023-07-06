module github.com/crowdsecurity/slack-plugin

go 1.20

replace github.com/crowdsecurity/crowdsec => ../../../

require (
	github.com/crowdsecurity/crowdsec v1.5.2
	github.com/hashicorp/go-hclog v1.5.0
	github.com/hashicorp/go-plugin v1.4.10
	github.com/slack-go/slack v0.9.2
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/fatih/color v1.15.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/hashicorp/yamux v0.0.0-20180604194846-3520598351bb // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mitchellh/go-testing-interface v1.0.0 // indirect
	github.com/oklog/run v1.0.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/net v0.9.0 // indirect
	golang.org/x/sys v0.9.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	google.golang.org/grpc v1.56.1 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
)
