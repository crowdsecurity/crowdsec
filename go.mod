module github.com/crowdsecurity/crowdsec

go 1.13

require (
	github.com/AlecAivazis/survey/v2 v2.2.7
	github.com/Microsoft/go-winio v0.4.16 // indirect
	github.com/antonmedv/expr v1.8.9
	github.com/appleboy/gin-jwt/v2 v2.6.4
	github.com/buger/jsonparser v1.1.1
	github.com/containerd/containerd v1.4.3 // indirect
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/davecgh/go-spew v1.1.1
	github.com/denisbrodbeck/machineid v1.0.1
	github.com/dghubble/sling v1.3.0
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v20.10.2+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/enescakir/emoji v1.0.0
	github.com/facebook/ent v0.5.4
	github.com/gin-gonic/gin v1.6.3
	github.com/go-co-op/gocron v0.5.1
	github.com/go-openapi/errors v0.19.9
	github.com/go-openapi/strfmt v0.19.11
	github.com/go-openapi/swag v0.19.12
	github.com/go-openapi/validate v0.20.0
	github.com/go-playground/validator/v10 v10.4.1 // indirect
	github.com/go-sql-driver/mysql v1.5.1-0.20200311113236-681ffa848bae
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/go-querystring v1.0.0
	github.com/google/uuid v1.1.5 // indirect
	github.com/goombaio/namegenerator v0.0.0-20181006234301-989e774b106e
	github.com/hashicorp/go-version v1.2.1
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/lib/pq v1.9.0
	github.com/logrusorgru/grokky v0.0.0-20180829062225-47edf017d42c
	github.com/mattn/go-colorable v0.1.8 // indirect
	github.com/mattn/go-runewidth v0.0.10 // indirect
	github.com/mattn/go-sqlite3 v2.0.3+incompatible
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/nxadm/tail v1.4.6
	github.com/olekukonko/tablewriter v0.0.4
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.1
	github.com/oschwald/geoip2-golang v1.4.0
	github.com/oschwald/maxminddb-golang v1.8.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.9.0
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/procfs v0.3.0 // indirect
	github.com/prometheus/prom2json v1.3.0
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/stretchr/testify v1.6.1
	github.com/ugorji/go v1.2.3 // indirect
	github.com/vjeantet/grok v1.0.1 // indirect
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	golang.org/x/mod v0.4.1
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b // indirect
	golang.org/x/sys v0.0.0-20210113181707-4bcb84eeeb78
	golang.org/x/term v0.0.0-20201210144234-2321bbc49cbf // indirect
	golang.org/x/text v0.3.5 // indirect
	google.golang.org/genproto v0.0.0-20210114201628-6edceaf6022f // indirect
	google.golang.org/grpc v1.35.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gopkg.in/yaml.v2 v2.4.0
	gotest.tools/v3 v3.0.3 // indirect
)

replace golang.org/x/time/rate => github.com/crowdsecurity/crowdsec/pkg/time/rate v0.0.0
