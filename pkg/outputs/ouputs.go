package outputs

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cwplugin"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"

	"github.com/crowdsecurity/crowdsec/pkg/cwapi"

	"github.com/antonmedv/expr"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type OutputFactory struct {
	BackendFolder string `yaml:"backend"`
}

type Output struct {
	API      *cwapi.ApiCtx
	bManager *cwplugin.BackendManager
}

/*
Transform an overflow (SignalOccurence) and a Profile into a BanOrder
*/
func OvflwToOrder(sig types.SignalOccurence, prof types.Profile) (*types.BanOrder, error, error) {
	var ordr types.BanOrder
	var warn error

	//Identify remediation type
	if prof.Remediation.Ban {
		ordr.MeasureType = "ban"
	} else if prof.Remediation.Slow {
		ordr.MeasureType = "slow"
	} else if prof.Remediation.Captcha {
		ordr.MeasureType = "captcha"
	} else {
		/*if the profil has no remediation, no order */
		return nil, nil, fmt.Errorf("no remediation")
	}
	ordr.MeasureSource = "local"
	ordr.Reason = sig.Scenario
	//Identify scope
	v, ok := sig.Labels["scope"]
	if !ok {
		//if remediation_scope isn't specified, it's IP
		v = "ip"
	}
	ordr.Scope = v
	asn, err := strconv.Atoi(sig.Source.AutonomousSystemNumber)
	if err != nil {
		warn = fmt.Errorf("invalid as number : %s : %s", sig.Source.AutonomousSystemNumber, err)
	}
	ordr.TargetAS = asn
	ordr.TargetASName = sig.Source.AutonomousSystemOrganization
	ordr.TargetIP = sig.Source.Ip
	ordr.TargetRange = sig.Source.Range
	ordr.TargetCountry = sig.Source.Country
	switch v {
	case "range":
		ordr.TxtTarget = ordr.TargetRange.String()
	case "ip":
		ordr.TxtTarget = ordr.TargetIP.String()
	case "as":
		ordr.TxtTarget = fmt.Sprintf("ban as %d (unsupported)", ordr.TargetAS)
	case "country":
		ordr.TxtTarget = fmt.Sprintf("ban country %s (unsupported)", ordr.TargetCountry)
	default:
		log.Errorf("Unknown remediation scope '%s'", sig.Labels["remediation_Scope"])
		return nil, fmt.Errorf("unknown remediation scope"), nil
	}
	//Set deadline
	ordr.Until = sig.Stop_at.Add(prof.Remediation.TimeDuration)
	return &ordr, nil, warn
}

func (o *Output) FlushAll() {
	if o.API != nil {
		if err := o.API.Flush(); err != nil {
			log.Errorf("Failing API flush : %s", err)
		}
	}
	if o.bManager != nil {
		if err := o.bManager.Flush(); err != nil {
			log.Errorf("Failing Sqlite flush : %s", err)
		}
	}
}

func (o *Output) ProcessOutput(sig types.SignalOccurence, profiles []types.Profile) error {

	var logger *log.Entry
	if sig.Source != nil {
		logger = log.WithFields(log.Fields{
			"source_ip":  sig.Source.Ip.String(),
			"scenario":   sig.Scenario,
			"bucket_id":  sig.Bucket_id,
			"event_time": sig.Stop_at,
		})
	} else {
		logger = log.WithFields(log.Fields{
			"scenario":   sig.Scenario,
			"bucket_id":  sig.Bucket_id,
			"event_time": sig.Stop_at,
		})
	}

	for _, profile := range profiles {
		if profile.RunTimeFilter != nil {
			//Evaluate node's filter
			output, err := expr.Run(profile.RunTimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"sig": sig}))
			if err != nil {
				logger.Warningf("failed to run filter : %v", err)
				continue
			}
			switch out := output.(type) {
			case bool:
				/* filter returned false, don't process Node */
				if !out {
					logger.Debugf("eval(FALSE) '%s'", profile.Filter)
					continue
				}
			default:
				logger.Warningf("Expr '%s' returned non-bool", profile.Filter)
				continue
			}
			logger.Debugf("eval(TRUE) '%s'", profile.Filter)
		}
		/*the filter was ok*/
		ordr, err, warn := OvflwToOrder(sig, profile)
		if err != nil {
			logger.Errorf("Unable to turn Overflow to Order : %v", err)
			return err
		}
		if warn != nil {
			logger.Infof("node warning : %s", warn)
		}
		if ordr != nil {
			bans, err := types.OrderToApplications(ordr)
			if err != nil {
				logger.Errorf("Error turning order to ban applications : %v", err)
				return err
			}
			logger.Warningf("%s triggered a %s %s %s remediation for [%s]", ordr.TxtTarget, ordr.Until.Sub(sig.Stop_at), ordr.Scope, ordr.MeasureType, sig.Scenario)
			sig.BanApplications = bans
		} else {
			//Order didn't lead to concrete bans
			logger.Infof("Processing Overflow with no decisions %s", sig.Alert_message)
		}

		// if ApiPush is nil (not specified in profile configuration) we use global api config (from default.yaml)
		if profile.ApiPush == nil || *profile.ApiPush {
			if o.API != nil { // if API is not nil, we can push
				if err = o.API.AppendSignal((sig)); err != nil {
					return fmt.Errorf("failed to append signal : %s", err)
				}
			}
		}
		for _, outputConfig := range profile.OutputConfigs {
			if pluginName, ok := outputConfig["plugin"]; ok {
				if o.bManager.IsBackendPlugin(pluginName) {
					if toStore, ok := outputConfig["store"]; ok {
						boolConv, err := strconv.ParseBool(toStore)
						if err != nil {
							log.Errorf("unable to parse boolean value of store configuration '%s' : %s", toStore, err)
						}
						if !boolConv {
							continue
						}
					}
					if err = o.bManager.InsertOnePlugin(sig, pluginName); err != nil {
						return fmt.Errorf("failed to insert plugin %s : %s", pluginName, err)
					}
				}
			}
		}
	}
	return nil
}

func LoadOutputProfiles(profileConfig string) ([]types.Profile, error) {

	var (
		profiles []types.Profile
	)

	yamlFile, err := os.Open(profileConfig)
	if err != nil {
		log.Errorf("Can't access parsing configuration file with '%v'.", err)
		return nil, err
	}
	//process the yaml
	dec := yaml.NewDecoder(yamlFile)
	dec.SetStrict(true)
	for {
		profile := types.Profile{}
		err = dec.Decode(&profile)
		if err != nil {
			if err == io.EOF {
				log.Tracef("End of yaml file")
				break
			}
			log.Errorf("Error decoding profile configuration file with '%s': %v", profileConfig, err)
			return nil, err
		}
		//compile filter if present
		if profile.Filter != "" {
			profile.RunTimeFilter, err = expr.Compile(profile.Filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"sig": &types.SignalOccurence{}})))
			if err != nil {
				log.Errorf("Compilation failed %v\n", err)
				return nil, err
			}
		}

		if profile.Remediation.Ban || profile.Remediation.Slow || profile.Remediation.Captcha {
			profile.Remediation.TimeDuration, err = time.ParseDuration(profile.Remediation.Duration)
			if err != nil {
				log.Fatalf("Unable to parse profile duration '%s'", profile.Remediation.Duration)
			}
		}
		//ensure we have outputs :)
		if profile.OutputConfigs == nil {
			log.Errorf("Profile has empty OutputConfigs")
			return nil, err
		}

		profiles = append(profiles, profile)
	}

	/*Initialize individual connectors*/
	return profiles, nil

}

func (o *Output) InitAPI(config map[string]string) error {
	var err error
	o.API = &cwapi.ApiCtx{}
	log.Infof("API connector init")
	err = o.API.Init(config["path"], config["profile"])
	if err != nil {
		log.Errorf("API init failed, won't push/pull : %v", err)
		return err
	}
	return nil
}

func (o *Output) LoadAPIConfig(configFile string) error {
	var err error
	o.API = &cwapi.ApiCtx{}

	err = o.API.LoadConfig(configFile)
	if err != nil {
		return err
	}
	return nil
}

func (o *Output) load(config *OutputFactory, isDaemon bool) error {
	var err error
	if config == nil {
		return fmt.Errorf("missing output plugin configuration")
	}
	log.Debugf("loading backend plugins ...")
	o.bManager, err = cwplugin.NewBackendPlugin(config.BackendFolder, isDaemon)
	if err != nil {
		return err
	}
	return nil
}

func (o *Output) Delete(target string) (int, error) {
	nbDel, err := o.bManager.Delete(target)
	return nbDel, err
}

func (o *Output) DeleteAll() error {
	err := o.bManager.DeleteAll()
	return err
}

func (o *Output) Insert(sig types.SignalOccurence) error {
	err := o.bManager.Insert(sig)
	return err
}

func (o *Output) Flush() error {
	err := o.bManager.Flush()
	return err
}

func (o *Output) ReadAT(timeAT time.Time) ([]map[string]string, error) {
	ret, err := o.bManager.ReadAT(timeAT)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func NewOutput(config *OutputFactory, isDaemon bool) (*Output, error) {
	var output Output
	err := output.load(config, isDaemon)
	if err != nil {
		return nil, err
	}
	return &output, nil
}
