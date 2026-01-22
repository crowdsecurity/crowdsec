package kubernetesacquisition

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type Configuration struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`

	Selector  string `yaml:"selector"`
	Namespace string `yaml:"namespace"`
}
