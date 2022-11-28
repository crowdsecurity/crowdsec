module github.com/crowdsecurity/crowdsec

go 1.19

require (
	entgo.io/ent v0.11.3
	github.com/AlecAivazis/survey/v2 v2.2.7
	github.com/Microsoft/go-winio v0.5.2 // indirect
	github.com/alexliesenfeld/health v0.5.1
	github.com/antonmedv/expr v1.9.0
	github.com/appleboy/gin-jwt/v2 v2.8.0
	github.com/aws/aws-sdk-go v1.42.25
	github.com/buger/jsonparser v1.1.1
	github.com/c-robinson/iplib v1.0.3
	github.com/confluentinc/bincover v0.2.0
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/crowdsecurity/dlog v0.0.0-20170105205344-4fb5f8204f26
	github.com/crowdsecurity/grokky v0.1.0
	github.com/crowdsecurity/machineid v1.0.2
	github.com/davecgh/go-spew v1.1.1
	github.com/dghubble/sling v1.3.0
	github.com/docker/docker v20.10.2+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/enescakir/emoji v1.0.0
	github.com/fatih/color v1.13.0
	github.com/fsnotify/fsnotify v1.5.1
	github.com/gin-gonic/gin v1.7.7
	github.com/go-co-op/gocron v1.17.0
	github.com/go-openapi/errors v0.20.1
	github.com/go-openapi/strfmt v0.19.11
	github.com/go-openapi/swag v0.19.12
	github.com/go-openapi/validate v0.20.0
	github.com/go-sql-driver/mysql v1.6.0
	github.com/google/go-querystring v1.0.0
	github.com/google/uuid v1.3.0
	github.com/goombaio/namegenerator v0.0.0-20181006234301-989e774b106e
	github.com/hashicorp/go-hclog v1.0.0
	github.com/hashicorp/go-plugin v1.4.2
	github.com/hashicorp/go-version v1.2.1
	github.com/jackc/pgx/v4 v4.14.1
	github.com/jarcoal/httpmock v1.1.0
	github.com/jszwec/csvutil v1.5.1
	github.com/lib/pq v1.10.7
	github.com/mattn/go-sqlite3 v1.14.15
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/nxadm/tail v1.4.6
	github.com/oschwald/geoip2-golang v1.4.0
	github.com/oschwald/maxminddb-golang v1.8.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/prom2json v1.3.0
	github.com/r3labs/diff/v2 v2.14.1
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.5.0
	github.com/stretchr/testify v1.8.0
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4
	google.golang.org/grpc v1.45.0
	google.golang.org/protobuf v1.28.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gopkg.in/yaml.v2 v2.4.0
	gotest.tools/v3 v3.0.3
)

require (
	github.com/Masterminds/sprig/v3 v3.2.2
	github.com/aquasecurity/table v1.8.0
	github.com/beevik/etree v1.1.0
	github.com/blackfireio/osinfo v1.0.3
	github.com/google/winops v0.0.0-20211216095627-f0e86eb1453b
	github.com/gorilla/websocket v1.5.0
	github.com/ivanpirog/coloredcobra v1.0.1
	github.com/mattn/go-isatty v0.0.14
	github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58
	github.com/segmentio/kafka-go v0.4.34
	github.com/texttheater/golang-levenshtein/levenshtein v0.0.0-20200805054039-cae8b0eaed6c
	golang.org/x/sys v0.0.0-20220722155257-8c9f86f7a55f
)

require (
	ariga.io/atlas v0.7.2-0.20220927111110-867ee0cca56a // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.1.1 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/ahmetalpbalkan/dlog v0.0.0-20170105205344-4fb5f8204f26 // indirect
	github.com/apparentlymart/go-textseg/v13 v13.0.0 // indirect
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/containerd/containerd v1.6.2 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/creack/pty v1.1.11 // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-openapi/analysis v0.19.16 // indirect
	github.com/go-openapi/inflect v0.19.0 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-openapi/loads v0.20.0 // indirect
	github.com/go-openapi/runtime v0.19.24 // indirect
	github.com/go-openapi/spec v0.20.0 // indirect
	github.com/go-playground/locales v0.14.0 // indirect
	github.com/go-playground/universal-translator v0.18.0 // indirect
	github.com/go-playground/validator/v10 v10.10.0 // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.2.0 // indirect
	github.com/golang/glog v0.0.0-20210429001901-424d2337a529 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.7 // indirect
	github.com/gorilla/mux v1.7.3 // indirect
	github.com/hashicorp/hcl/v2 v2.13.0 // indirect
	github.com/hashicorp/yamux v0.0.0-20180604194846-3520598351bb // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.10.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.2.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jackc/pgtype v1.9.1 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/klauspost/compress v1.15.7 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-testing-interface v1.0.0 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/oklog/run v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2-0.20211117181255-693428a734f5 // indirect
	github.com/pierrec/lz4/v4 v4.1.15 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/common v0.30.0 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tidwall/gjson v1.13.0 // indirect
	github.com/ugorji/go/codec v1.2.6 // indirect
	github.com/vjeantet/grok v1.0.1 // indirect
	github.com/vmihailenco/msgpack v4.0.4+incompatible // indirect
	github.com/zclconf/go-cty v1.10.0 // indirect
	go.mongodb.org/mongo-driver v1.9.0 // indirect
	golang.org/x/net v0.0.0-20220706163947-c90051bbdb60 // indirect
	golang.org/x/sync v0.0.0-20220722155255-886fb9371eb4 // indirect
	golang.org/x/term v0.0.0-20220526004731-065cf7ba2467 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20220414192740-2d67ff6cf2b4 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace golang.org/x/time/rate => github.com/crowdsecurity/crowdsec/pkg/time/rate v0.0.0
