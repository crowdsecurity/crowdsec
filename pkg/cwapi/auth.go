package cwapi

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/types"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/dghubble/sling"
	"gopkg.in/tomb.v2"
)

type ApiCtx struct {
	/*config*/
	ApiVersion   string   `yaml:"version"`
	PullPath     string   `yaml:"pull_path"`
	PushPath     string   `yaml:"push_path"`
	SigninPath   string   `yaml:"signin_path"`
	RegisterPath string   `yaml:"register_path"`
	ResetPwdPath string   `yaml:"reset_pwd_path"`
	EnrollPath   string   `yaml:"enroll_path"`
	BaseURL      string   `yaml:"url"`
	CfgUser      string   `yaml:"machine_id"`
	CfgPassword  string   `yaml:"password"`
	Creds        ApiCreds `yaml:"-"`
	/*mostly for mocking/faking api*/
	Muted     bool `yaml:"-"`
	DebugDump bool `yaml:"-"`
	/*runtime*/
	tokenExpired bool          `yaml:"-"`
	toPush       []types.Event `yaml:"-"`
	Http         *sling.Sling  `yaml:"-"`
	PusherTomb   tomb.Tomb     `yaml:"-"`
}

type ApiCreds struct {
	User     string `json:"machine_id" yaml:"machine_id"`
	Password string `json:"password" yaml:"password"`
	Profile  string `json:"profile,omitempty" yaml:"profile,omitempty"`
}

type ApiResp struct {
	StatusCode int    `json:"statusCode"`
	Error      string `json:"error"`
	Message    string `json:"message"`
}

type PullResp struct {
	StatusCode int                 `json:"statusCode"`
	Body       []map[string]string `json:"message"`
}

func (ctx *ApiCtx) WriteConfig(cfg string) error {
	ret, err := yaml.Marshal(ctx)
	if err != nil {
		return fmt.Errorf("failed to marshal config : %s", err)
	}
	if err := ioutil.WriteFile(cfg, ret, 0600); err != nil {
		return fmt.Errorf("failed to write api file %s : %s", cfg, ret)
	}
	return nil
}

func (ctx *ApiCtx) LoadConfig(cfg string) error {
	rcfg, err := ioutil.ReadFile(cfg)
	if err != nil {
		return fmt.Errorf("api load configuration: unable to read configuration file '%s' : %s", cfg, err)
	}
	if err := yaml.UnmarshalStrict(rcfg, &ctx); err != nil {
		return fmt.Errorf("api load configuration: unable to unmarshall configuration file '%s' : %s", cfg, err)
	}
	if ctx.ApiVersion != cwversion.Constraint_api {
		return fmt.Errorf("api load configuration: cscli version only supports %s api, not %s", cwversion.Constraint_api, ctx.ApiVersion)
	}
	ctx.Creds.User = ctx.CfgUser
	ctx.Creds.Password = ctx.CfgPassword

	/*
		For sling, if a path starts with '/', it's an absolute path, and it will get rid of the 'prefix',
		leading to bad urls
	*/
	if strings.HasPrefix(ctx.PullPath, "/") ||
		strings.HasPrefix(ctx.PushPath, "/") ||
		strings.HasPrefix(ctx.SigninPath, "/") ||
		strings.HasPrefix(ctx.RegisterPath, "/") ||
		strings.HasPrefix(ctx.ResetPwdPath, "/") ||
		strings.HasPrefix(ctx.EnrollPath, "/") {
		log.Warningf("!API paths must not be prefixed by /")
	}

	httpClient := &http.Client{Timeout: 20 * time.Second}

	ctx.Http = sling.New().Client(httpClient).Base(ctx.BaseURL+"/"+ctx.ApiVersion+"/").Set("User-Agent", fmt.Sprintf("Crowdsec/%s", cwversion.VersionStr()))
	log.Printf("api load configuration: configuration loaded successfully (base:%s)", ctx.BaseURL+"/"+ctx.ApiVersion+"/")
	return nil
}

func (ctx *ApiCtx) Init(cfg string, profile string) error {
	var err error

	err = ctx.LoadConfig(cfg)
	if err != nil {
		return err
	}
	ctx.Creds.Profile = profile
	ctx.toPush = make([]types.Event, 0)
	err = ctx.Signin()
	if err != nil {
		return err
	}
	//start the background go-routine
	ctx.PusherTomb.Go(func() error {
		err := ctx.pushLoop()
		if err != nil {
			log.Errorf("api push error : %s", err)
			return err
		}
		return nil
	})
	return nil
}

func (ctx *ApiCtx) Shutdown() error {
	ctx.PusherTomb.Kill(nil)
	log.Infof("Waiting for API routine to finish")
	if err := ctx.PusherTomb.Wait(); err != nil {
		return fmt.Errorf("API routine returned error : %s", err)
	}
	return nil
}

func (ctx *ApiCtx) Signin() error {
	if ctx.Creds.User == "" || ctx.Creds.Password == "" {
		return fmt.Errorf("api signin: missing credentials in api.yaml")
	}
	jsonResp := &ApiResp{}

	resp, err := ctx.Http.Post(ctx.SigninPath).BodyJSON(ctx.Creds).ReceiveSuccess(jsonResp)
	if err != nil {
		return fmt.Errorf("api signin: HTTP request creation failed: %s", err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("api signin: unable to read API response body: '%s'", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("api signin: return bad HTTP code (%d): %s", resp.StatusCode, string(body))
	}
	if jsonResp.Message == "" || jsonResp.StatusCode != 200 {
		return fmt.Errorf("api signin failed. http response: %s", body)
	}

	ctx.Http = ctx.Http.Set("Authorization", jsonResp.Message)
	log.Printf("api signin: signed in successfuly")
	return nil
}

func (ctx *ApiCtx) RegisterMachine(machineID string, password string) error {
	ctx.Creds.User = machineID
	ctx.Creds.Password = password

	req, err := ctx.Http.New().Post(ctx.RegisterPath).BodyJSON(ctx.Creds).Request()
	if err != nil {
		return fmt.Errorf("api register machine: HTTP request creation failed: %s", err)
	}
	log.Debugf("api register: URL: '%s'", req.URL)

	httpClient := http.Client{Timeout: 20 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("api register machine: API call failed : %s", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("api register machine: unable to read API response body: %s", err.Error())
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("api register machine: return bad HTTP code (%d): %s", resp.StatusCode, string(body))
	}

	jsonResp := ApiResp{}
	err = json.Unmarshal(body, &jsonResp)
	if err != nil {
		return fmt.Errorf("api register machine: unable to unmarshall api response '%s': %s", string(body), err.Error())
	}
	return nil
}

func (ctx *ApiCtx) ResetPassword(machineID string, password string) error {
	ctx.Creds.User = machineID
	ctx.Creds.Password = password

	data := map[string]string{"machine_id": ctx.Creds.User, "password": ctx.Creds.Password}
	req, err := ctx.Http.New().Post(ctx.ResetPwdPath).BodyJSON(data).Request()
	if err != nil {
		return fmt.Errorf("api reset password: HTTP request creation failed: %s", err)
	}
	log.Debugf("api reset: URL: '%s'", req.URL)

	httpClient := http.Client{Timeout: 20 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("api reset password: API call failed : %s", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("api reset password: unable to read API response body: %s", err.Error())
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("api reset password: return bad HTTP code (%d): %s", resp.StatusCode, string(body))
	}

	jsonResp := ApiResp{}
	err = json.Unmarshal(body, &jsonResp)
	if err != nil {
		return fmt.Errorf("api reset password: unable to unmarshall api response '%s': %s", string(body), err.Error())
	}
	if jsonResp.StatusCode != 200 {
		return fmt.Errorf("api reset password: return bad HTTP code (%d): %s", jsonResp.StatusCode, string(body))
	}
	return nil
}
