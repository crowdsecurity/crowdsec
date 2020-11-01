package metabase

import (
	"fmt"
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
			Email:     config.Username,
			Password:  config.Password,
			SiteName:  "crowdsec",
		},
		Client:   client,
		URL:      config.URL,
		DumpPath: config.Folder,
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

	return err

}
