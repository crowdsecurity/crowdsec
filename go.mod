module github.com/crowdsecurity/crowdsec

go 1.13

require (
	github.com/AlecAivazis/survey/v2 v2.2.1
	github.com/Microsoft/go-winio v0.4.14 // indirect
	github.com/antonmedv/expr v1.8.9
	github.com/appleboy/gin-jwt/v2 v2.6.4
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef // indirect
	github.com/buger/jsonparser v1.0.0
	github.com/containerd/containerd v1.3.4 // indirect
	github.com/coreos/go-systemd v0.0.0-20190321100706-95778dfbb74e
	github.com/davecgh/go-spew v1.1.1
	github.com/denisbrodbeck/machineid v1.0.1
	github.com/dghubble/sling v1.3.0
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v20.10.2+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/enescakir/emoji v1.0.0
	github.com/facebook/ent v0.5.4
	github.com/gin-gonic/gin v1.6.3
	github.com/go-co-op/gocron v0.3.3
	github.com/go-openapi/analysis v0.19.12 // indirect
	github.com/go-openapi/errors v0.19.8
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/loads v0.19.6 // indirect
	github.com/go-openapi/runtime v0.19.24 // indirect
	github.com/go-openapi/spec v0.19.13 // indirect
	github.com/go-openapi/strfmt v0.19.10
	github.com/go-openapi/swag v0.19.11
	github.com/go-openapi/validate v0.19.12
	github.com/go-playground/validator/v10 v10.4.1 // indirect
	github.com/go-sql-driver/mysql v1.5.1-0.20200311113236-681ffa848bae
	github.com/google/go-querystring v1.0.0
	github.com/goombaio/namegenerator v0.0.0-20181006234301-989e774b106e
	github.com/hashicorp/go-version v1.2.1
	github.com/jinzhu/gorm v1.9.12
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/lib/pq v1.9.0
	github.com/logrusorgru/grokky v0.0.0-20180829062225-47edf017d42c
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/mattn/go-sqlite3 v2.0.3+incompatible
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/nxadm/tail v1.4.4
	github.com/olekukonko/tablewriter v0.0.4
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1
	github.com/oschwald/geoip2-golang v1.4.0
	github.com/oschwald/maxminddb-golang v1.6.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.8.0
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/common v0.15.0 // indirect
	github.com/prometheus/prom2json v1.3.0
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/stretchr/testify v1.6.1
	github.com/ugorji/go/codec v1.2.0 // indirect
	github.com/vjeantet/grok v1.0.1 // indirect
	go.mongodb.org/mongo-driver v1.4.3 // indirect
	golang.org/x/crypto v0.0.0-20201116153603-4be66e5b6582
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b // indirect
	golang.org/x/mod v0.4.0
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b // indirect
	golang.org/x/sys v0.0.0-20201116161645-c061ba923fbb
	golang.org/x/text v0.3.4 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0
	golang.org/x/tools v0.0.0-20210108195828-e2f9c7f1fc8e // indirect
	google.golang.org/protobuf v1.25.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gopkg.in/yaml.v2 v2.3.0
	gotest.tools v2.2.0+incompatible // indirect
	gotest.tools/v3 v3.0.3 // indirect
)

replace golang.org/x/time/rate => github.com/crowdsecurity/crowdsec/pkg/time/rate v0.0.0
