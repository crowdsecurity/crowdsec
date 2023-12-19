module github.com/crowdsecurity/crowdsec

go 1.21

// Don't use the toolchain directive to avoid uncontrolled downloads during
// a build, especially in sandboxed environments (freebsd, gentoo...).
// toolchain go1.21.3

require (
	entgo.io/ent v0.12.4
	github.com/AlecAivazis/survey/v2 v2.3.7
	github.com/Masterminds/semver/v3 v3.2.1
	github.com/Masterminds/sprig/v3 v3.2.3
	github.com/agext/levenshtein v1.2.1
	github.com/alexliesenfeld/health v0.8.0
	github.com/antonmedv/expr v1.15.3
	github.com/appleboy/gin-jwt/v2 v2.8.0
	github.com/aquasecurity/table v1.8.0
	github.com/aws/aws-lambda-go v1.41.0
	github.com/aws/aws-sdk-go v1.48.15
	github.com/beevik/etree v1.1.0
	github.com/blackfireio/osinfo v1.0.3
	github.com/bluele/gcache v0.0.2
	github.com/buger/jsonparser v1.1.1
	github.com/c-robinson/iplib v1.0.3
	github.com/cespare/xxhash/v2 v2.2.0
	github.com/crowdsecurity/coraza/v3 v3.0.0-20231213144607-41d5358da94f
	github.com/crowdsecurity/dlog v0.0.0-20170105205344-4fb5f8204f26
	github.com/crowdsecurity/go-cs-lib v0.0.5
	github.com/crowdsecurity/grokky v0.2.1
	github.com/crowdsecurity/machineid v1.0.2
	github.com/davecgh/go-spew v1.1.1
	github.com/dghubble/sling v1.3.0
	github.com/docker/docker v24.0.7+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/enescakir/emoji v1.0.0
	github.com/fatih/color v1.15.0
	github.com/fsnotify/fsnotify v1.6.0
	github.com/gin-gonic/gin v1.9.1
	github.com/go-co-op/gocron v1.17.0
	github.com/go-openapi/errors v0.20.1
	github.com/go-openapi/strfmt v0.19.11
	github.com/go-openapi/swag v0.22.3
	github.com/go-openapi/validate v0.20.0
	github.com/go-sql-driver/mysql v1.6.0
	github.com/goccy/go-yaml v1.11.0
	github.com/gofrs/uuid v4.0.0+incompatible
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/google/go-querystring v1.0.0
	github.com/google/uuid v1.3.0
	github.com/google/winops v0.0.0-20230712152054-af9b550d0601
	github.com/goombaio/namegenerator v0.0.0-20181006234301-989e774b106e
	github.com/gorilla/websocket v1.5.0
	github.com/hashicorp/go-hclog v1.5.0
	github.com/hashicorp/go-plugin v1.4.10
	github.com/hashicorp/go-version v1.2.1
	github.com/hexops/gotextdiff v1.0.3
	github.com/ivanpirog/coloredcobra v1.0.1
	github.com/jackc/pgx/v4 v4.14.1
	github.com/jarcoal/httpmock v1.1.0
	github.com/jszwec/csvutil v1.5.1
	github.com/lithammer/dedent v1.1.0
	github.com/mattn/go-isatty v0.0.19
	github.com/mattn/go-sqlite3 v1.14.16
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/nxadm/tail v1.4.8
	github.com/oschwald/geoip2-golang v1.4.0
	github.com/oschwald/maxminddb-golang v1.8.0
	github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.16.0
	github.com/prometheus/client_model v0.4.0
	github.com/prometheus/prom2json v1.3.0
	github.com/r3labs/diff/v2 v2.14.1
	github.com/sanity-io/litter v1.5.5
	github.com/segmentio/kafka-go v0.4.45
	github.com/shirou/gopsutil/v3 v3.23.5
	github.com/sirupsen/logrus v1.9.3
	github.com/slack-go/slack v0.12.2
	github.com/spf13/cobra v1.7.0
	github.com/stretchr/testify v1.8.4
	github.com/umahmood/haversine v0.0.0-20151105152445-808ab04add26
	github.com/wasilibs/go-re2 v1.3.0
	github.com/xhit/go-simple-mail/v2 v2.16.0
	golang.org/x/crypto v0.17.0
	golang.org/x/mod v0.11.0
	golang.org/x/sys v0.15.0
	golang.org/x/text v0.14.0
	google.golang.org/grpc v1.56.3
	google.golang.org/protobuf v1.31.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
	gotest.tools/v3 v3.5.0
	k8s.io/apiserver v0.28.4
)

require (
	ariga.io/atlas v0.14.1-0.20230918065911-83ad451a4935 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/ahmetalpbalkan/dlog v0.0.0-20170105205344-4fb5f8204f26 // indirect
	github.com/apparentlymart/go-textseg/v13 v13.0.0 // indirect
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bytedance/sonic v1.9.1 // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20221115062448-fe3a3abad311 // indirect
	github.com/corazawaf/libinjection-go v0.1.2 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/creack/pty v1.1.18 // indirect
	github.com/docker/distribution v2.8.2+incompatible // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.2 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-openapi/analysis v0.19.16 // indirect
	github.com/go-openapi/inflect v0.19.0 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/loads v0.20.0 // indirect
	github.com/go-openapi/runtime v0.19.24 // indirect
	github.com/go-openapi/spec v0.20.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.14.0 // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/glog v1.1.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/hashicorp/hcl/v2 v2.13.0 // indirect
	github.com/hashicorp/yamux v0.0.0-20180604194846-3520598351bb // indirect
	github.com/huandu/xstrings v1.3.3 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
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
	github.com/klauspost/compress v1.17.3 // indirect
	github.com/klauspost/cpuid/v2 v2.2.4 // indirect
	github.com/leodido/go-urn v1.2.4 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/magefile/mage v1.15.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-testing-interface v1.0.0 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/oklog/run v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.3-0.20211202183452-c5a74bcca799 // indirect
	github.com/pelletier/go-toml/v2 v2.0.8 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20230725210150-fb29fc3c913e // indirect
	github.com/pierrec/lz4/v4 v4.1.18 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/common v0.44.0 // indirect
	github.com/prometheus/procfs v0.10.1 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sergi/go-diff v1.3.1 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tetratelabs/wazero v1.2.1 // indirect
	github.com/tidwall/gjson v1.17.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tklauser/go-sysconf v0.3.11 // indirect
	github.com/tklauser/numcpus v0.6.0 // indirect
	github.com/toorop/go-dkim v0.0.0-20201103131630-e1cd1a0a5208 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.11 // indirect
	github.com/vmihailenco/msgpack v4.0.4+incompatible // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
	github.com/zclconf/go-cty v1.8.0 // indirect
	go.mongodb.org/mongo-driver v1.9.4 // indirect
	golang.org/x/arch v0.3.0 // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/sync v0.5.0 // indirect
	golang.org/x/term v0.15.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.8.1-0.20230428195545-5283a0178901 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230525234030-28d5490b6b19 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	k8s.io/api v0.28.4 // indirect
	k8s.io/apimachinery v0.28.4 // indirect
	k8s.io/klog/v2 v2.100.1 // indirect
	k8s.io/utils v0.0.0-20230406110748-d93618cff8a2 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
)

replace golang.org/x/time/rate => github.com/crowdsecurity/crowdsec/pkg/time/rate v0.0.0
