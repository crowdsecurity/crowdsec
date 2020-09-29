package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"path"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/outputs"
	"github.com/crowdsecurity/crowdsec/pkg/types"

	"github.com/denisbrodbeck/machineid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var (
	upper  = "ABCDEFGHIJKLMNOPQRSTUVWXY"
	lower  = "abcdefghijklmnopqrstuvwxyz"
	digits = "0123456789"
)

var (
	userID    string // for flag parsing
	outputCTX *outputs.Output
)

const (
	uuid          = "/proc/sys/kernel/random/uuid"
	apiConfigFile = "api.yaml"
)

func dumpCredentials() error {
	if config.output == "json" {
		credsYaml, err := json.Marshal(&outputCTX.API.Creds)
		if err != nil {
			log.Fatalf("Can't marshal credentials : %v", err)
		}
		fmt.Printf("%s\n", string(credsYaml))
	} else {
		credsYaml, err := yaml.Marshal(&outputCTX.API.Creds)
		if err != nil {
			log.Fatalf("Can't marshal credentials : %v", err)
		}
		fmt.Printf("%s\n", string(credsYaml))
	}
	return nil
}

func generatePassword(passwordLength int) string {
	rand.Seed(time.Now().UnixNano())
	charset := upper + lower + digits

	buf := make([]byte, passwordLength)
	buf[0] = digits[rand.Intn(len(digits))]
	buf[1] = upper[rand.Intn(len(upper))]
	buf[2] = lower[rand.Intn(len(lower))]

	for i := 3; i < passwordLength; i++ {
		buf[i] = charset[rand.Intn(len(charset))]
	}
	rand.Shuffle(len(buf), func(i, j int) {
		buf[i], buf[j] = buf[j], buf[i]
	})

	return string(buf)
}

func pullTOP() error {
	/*profile from cwhub*/
	var profiles []string
	if _, ok := cwhub.HubIdx[cwhub.SCENARIOS]; !ok || len(cwhub.HubIdx[cwhub.SCENARIOS]) == 0 {
		log.Errorf("no loaded scenarios, can't fill profiles")
		return fmt.Errorf("no profiles")
	}
	for _, item := range cwhub.HubIdx[cwhub.SCENARIOS] {
		if item.Tainted || !item.Installed {
			continue
		}
		profiles = append(profiles, item.Name)
	}
	outputCTX.API.Creds.Profile = strings.Join(profiles[:], ",")
	if err := outputCTX.API.Signin(); err != nil {
		log.Fatalf(err.Error())
	}

	ret, err := outputCTX.API.PullTop()
	if err != nil {
		log.Fatalf(err.Error())
	}
	log.Warningf("api pull returned %d entries", len(ret))
	for _, item := range ret {
		if _, ok := item["range_ip"]; !ok {
			continue
		}
		if _, ok := item["scenario"]; !ok {
			continue
		}

		if _, ok := item["action"]; !ok {
			continue
		}
		if _, ok := item["expiration"]; !ok {
			continue
		}
		if _, ok := item["country"]; !ok {
			item["country"] = ""
		}
		if _, ok := item["as_org"]; !ok {
			item["as_org"] = ""
		}
		if _, ok := item["as_num"]; !ok {
			item["as_num"] = ""
		}
		var signalOcc types.SignalOccurence
		signalOcc, err = simpleBanToSignal(item["range_ip"], item["scenario"], item["expiration"], item["action"], item["as_name"], item["as_num"], item["country"], "api")
		if err != nil {
			return fmt.Errorf("failed to convert ban to signal : %s", err)
		}
		if err := outputCTX.Insert(signalOcc); err != nil {
			log.Fatalf("Unable to write pull to Database : %+s", err.Error())
		}
	}
	outputCTX.Flush()
	log.Infof("Wrote %d bans from api to database.", len(ret))
	return nil
}

func NewAPICmd() *cobra.Command {

	var cmdAPI = &cobra.Command{
		Use:   "api [action]",
		Short: "Crowdsec API interaction",
		Long: `
Allow to register your machine into crowdsec API to send and receive signal.
		`,
		Example: `
cscli api register      # Register to Crowdsec API
cscli api pull          # Pull malevolant IPs from Crowdsec API
cscli api reset         # Reset your machines credentials
cscli api enroll        # Enroll your machine to the user account you created on Crowdsec backend
cscli api credentials   # Display your API credentials
`,
		Args: cobra.MinimumNArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if !config.configured {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			outputConfig := outputs.OutputFactory{
				BackendFolder: config.BackendPluginFolder,
				Flush:         false,
			}
			outputCTX, err = outputs.NewOutput(&outputConfig)
			if err != nil {
				return err
			}

			err = outputCTX.LoadAPIConfig(path.Join(config.InstallFolder, apiConfigFile))
			if err != nil {
				return err
			}
			return nil
		},
	}

	var cmdAPIRegister = &cobra.Command{
		Use:   "register",
		Short: "Register on Crowdsec API",
		Long: `This command will register your machine to crowdsec API to allow you to receive list of malveolent IPs. 
		The printed machine_id and password should be added to your api.yaml file.`,
		Example: `cscli api register`,
		Args:    cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			id, err := machineid.ID()
			if err != nil {
				log.Debugf("failed to get machine-id with usual files : %s", err)
			}
			if id == "" || err != nil {
				bID, err := ioutil.ReadFile(uuid)
				if err != nil {
					log.Fatalf("can'get a valid machine_id")
				}
				id = string(bID)
				id = strings.ReplaceAll(id, "-", "")[:32]
			}
			password := generatePassword(64)

			if err := outputCTX.API.RegisterMachine(fmt.Sprintf("%s%s", id, generatePassword(16)), password); err != nil {
				log.Fatalf(err.Error())
			}
			fmt.Printf("machine_id: %s\n", outputCTX.API.Creds.User)
			fmt.Printf("password: %s\n", outputCTX.API.Creds.Password)
		},
	}

	var cmdAPIEnroll = &cobra.Command{
		Use:     "enroll",
		Short:   "Associate your machine to an existing crowdsec user",
		Long:    `Enrolling your machine into your user account will allow for more accurate lists and threat detection. See website to create user account.`,
		Example: `cscli api enroll -u 1234567890ffff`,
		Args:    cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := outputCTX.API.Signin(); err != nil {
				log.Fatalf("unable to signin : %s", err)
			}
			if err := outputCTX.API.Enroll(userID); err != nil {
				log.Fatalf(err.Error())
			}
		},
	}

	var cmdAPIResetPassword = &cobra.Command{
		Use:     "reset",
		Short:   "Reset password on CrowdSec API",
		Long:    `Attempts to reset your credentials to the API.`,
		Example: `cscli api reset`,
		Args:    cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			id, err := machineid.ID()
			if err != nil {
				log.Debugf("failed to get machine-id with usual files : %s", err)
			}
			if id == "" || err != nil {
				bID, err := ioutil.ReadFile(uuid)
				if err != nil {
					log.Fatalf("can'get a valid machine_id")
				}
				id = string(bID)
				id = strings.ReplaceAll(id, "-", "")[:32]
			}

			password := generatePassword(64)
			if err := outputCTX.API.ResetPassword(fmt.Sprintf("%s%s", id, generatePassword(16)), password); err != nil {
				log.Fatalf(err.Error())
			}
			fmt.Printf("machine_id: %s\n", outputCTX.API.Creds.User)
			fmt.Printf("password: %s\n", outputCTX.API.Creds.Password)
		},
	}

	var cmdAPIPull = &cobra.Command{
		Use:     "pull",
		Short:   "Pull crowdsec API TopX",
		Long:    `Pulls a list of malveolent IPs relevant to your situation and add them into the local ban database.`,
		Example: `cscli api pull`,
		Args:    cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf(err.Error())
			}
			err := pullTOP()
			if err != nil {
				log.Fatalf(err.Error())
			}
		},
	}

	var cmdAPICreds = &cobra.Command{
		Use:     "credentials",
		Short:   "Display api credentials",
		Long:    ``,
		Example: `cscli api credentials`,
		Args:    cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := dumpCredentials(); err != nil {
				log.Fatalf(err.Error())
			}
		},
	}

	cmdAPI.AddCommand(cmdAPICreds)
	cmdAPIEnroll.Flags().StringVarP(&userID, "user", "u", "", "User ID (required)")
	if err := cmdAPIEnroll.MarkFlagRequired("user"); err != nil {
		log.Errorf("'user' flag : %s", err)
	}
	cmdAPI.AddCommand(cmdAPIEnroll)
	cmdAPI.AddCommand(cmdAPIResetPassword)
	cmdAPI.AddCommand(cmdAPIRegister)
	cmdAPI.AddCommand(cmdAPIPull)
	return cmdAPI
}
