module github.com/crowdsecurity/slack-plugin

go 1.19

require (
	github.com/crowdsecurity/crowdsec v1.4.1
	github.com/hashicorp/go-hclog v1.0.0
	github.com/hashicorp/go-plugin v1.4.2
	github.com/slack-go/slack v0.9.2
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/fatih/color v1.13.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/hashicorp/yamux v0.0.0-20180604194846-3520598351bb // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mitchellh/go-testing-interface v1.0.0 // indirect
	github.com/oklog/run v1.0.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/net v0.0.0-20220418201149-a630d4f3e7a2 // indirect
	golang.org/x/sys v0.0.0-20220513210249-45d2b4557a2a // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20220414192740-2d67ff6cf2b4 // indirect
	google.golang.org/grpc v1.45.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)

replace github.com/golang/protobuf => ../../../pkg/golang-protobuf