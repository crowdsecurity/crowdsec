module github.com/crowdsecurity/slack-plugin

replace github.com/crowdsecurity/crowdsec => /home/shivam/work/crowdsec/

go 1.16

require (
	github.com/crowdsecurity/crowdsec v1.1.1
	github.com/hashicorp/go-hclog v0.16.2
	github.com/hashicorp/go-plugin v1.4.2
	github.com/sirupsen/logrus v1.8.1
	github.com/slack-go/slack v0.9.2
	google.golang.org/grpc v1.40.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/yaml.v2 v2.4.0
)
