package metabase

import (
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

type Prefs struct {
	SiteName      string `json:"site_name"`
	SiteLocal     string `json:"site_locale"`
	AllowTracking string `json:"allow_tracking"`
}

type UserSetup struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	SiteName  string `json:"site_name"`
}

type Setup struct {
	Token    string      `json:"token"`
	Prefs    *Prefs      `json:"prefs"`
	Database interface{} `json:"database"`
	User     *UserSetup  `json:"user"`
	Client   *HTTP       `json:"-"`
	URL      string      `json:"-"`
	DumpPath string      `json:"-"`
}

func NewSetup(config *Config, client *HTTP) (*Setup, error) {
	setup := &Setup{
		Token: config.setupToken,
		Prefs: &Prefs{
			SiteName:      "crowdsec",
			SiteLocal:     "fr",
			AllowTracking: "false",
		},
		Database: nil,
		User: &UserSetup{
			FirstName: "crowdsec",
			LastName:  "crowdsec",
			Email:     config.mbUsername,
			Password:  config.mbPassword,
			SiteName:  "crowdsec",
		},
		Client:   client,
		URL:      config.mbURL,
		DumpPath: config.mbFolder,
	}

	return setup, nil
}

func (s *Setup) Run() error {

	success, errormsg, err := s.Client.Do("POST", routes[setupEndpoint], &s)
	if err != nil {
		return fmt.Errorf("login: unable to read response body: %s", err)
	}
	if errormsg != nil {
		return fmt.Errorf("setup run: %v", errormsg)
	}
	body, ok := success.(map[string]interface{})
	if !ok {
		return fmt.Errorf("setup run: bad response type: %+v", success)
	}

	if _, ok := body["id"]; !ok {
		return fmt.Errorf("setup run: no id in response: %v", body)
	}
	id, ok := body["id"].(string)
	if !ok {
		return fmt.Errorf("setup run: bad id type: %+v", body["id"])
	}

	s.Client.Set("Cookie", fmt.Sprintf("metabase.SESSION=%s", id))

	creds, err := yaml.Marshal(map[string]string{
		"username": s.User.Email,
		"password": s.User.Password,
		"url":      s.URL,
	})
	if err != nil {
		return fmt.Errorf("unable to marshal metabase api credentials: %s", err)
	}

	err = ioutil.WriteFile(filepath.Join(s.DumpPath, credentialFile), creds, 0600)
	if err != nil {
		return fmt.Errorf("write api credentials in '%s' failed: %s", filepath.Join(s.DumpPath, credentialFile), err)
	}

	log.Printf("URL: '%s'", s.URL)
	log.Printf("Username: '%s'", s.User.Email)
	log.Printf("Password: '%s'", s.User.Password)

	return err

}
