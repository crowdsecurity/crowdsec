module github.com/crowdsecurity/crowdsec

go 1.13

require (
	github.com/Microsoft/go-winio v0.4.14 // indirect
	github.com/antonmedv/expr v1.8.2
	github.com/buger/jsonparser v1.0.0
	github.com/containerd/containerd v1.3.4 // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/denisbrodbeck/machineid v1.0.1
	github.com/dghubble/sling v1.3.0
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v17.12.0-ce-rc1.0.20200419140219-55e6d7d36faf+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/docker/go-units v0.4.0 // indirect
	github.com/enescakir/emoji v1.0.0
	github.com/goombaio/namegenerator v0.0.0-20181006234301-989e774b106e
	github.com/hashicorp/go-version v1.2.0
	github.com/jamiealquiza/tachymeter v2.0.0+incompatible
	github.com/jinzhu/gorm v1.9.12
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/logrusorgru/grokky v0.0.0-20180829062225-47edf017d42c
	github.com/mattn/go-runewidth v0.0.9 // indirect
	github.com/mattn/go-sqlite3 v2.0.3+incompatible
	github.com/nxadm/tail v1.4.4
	github.com/olekukonko/tablewriter v0.0.4
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/oschwald/geoip2-golang v1.4.0
	github.com/oschwald/maxminddb-golang v1.6.0
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v1.5.1
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/common v0.9.1
	github.com/prometheus/prom2json v1.3.0
	github.com/sevlyar/go-daemon v0.1.5
	github.com/sirupsen/logrus v1.5.0
	github.com/spf13/cobra v0.0.7
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b // indirect
	golang.org/x/mod v0.2.0
	golang.org/x/sys v0.0.0-20200212091648-12a6c2dcc1e4
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0
	golang.org/x/tools v0.0.0-20200422022333-3d57cf2e726e // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gopkg.in/yaml.v2 v2.2.8
)

replace golang.org/x/time/rate => github.com/crowdsecurity/crowdsec/pkg/time/rate v0.0.0
