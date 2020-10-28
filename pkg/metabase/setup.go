package metabase

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

func (m *Metabase) FirstSetup() (map[string]interface{}, *http.Response, error) {
	var respJSON map[string]interface{}
	type Prefs struct {
		SiteName      string `json:"site_name"`
		SiteLocal     string `json:"site_locale"`
		AllowTracking string `json:"allow_tracking"`
	}

	type User struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		Password  string `json:"password"`
		SiteName  string `json:"site_name"`
	}

	data := struct {
		Token    string      `json:"token"`
		Prefs    *Prefs      `json:"prefs"`
		Database interface{} `json:"database"`
		User     *User       `json:"user"`
	}{
		Token: m.Config.setupToken,
		Prefs: &Prefs{
			SiteName:      "crowdsec",
			SiteLocal:     "fr",
			AllowTracking: "false",
		},
		Database: nil,
		User: &User{
			FirstName: "crowdsec",
			LastName:  "crowdsec",
			Email:     "crowdsec@crowdsec.net",
			Password:  m.Config.mbPassword,
			SiteName:  "crowdsec",
		},
	}

	resp, err := m.Client.New().Post(routes[setup]).BodyJSON(data).Receive(&respJSON, &respJSON)
	m.Client = m.Client.Set("Cookie", fmt.Sprintf("metabase.SESSION=%s", respJSON["id"].(string)))

	creds, err := yaml.Marshal(map[string]string{
		"username": m.Config.mbUsername,
		"password": m.Config.mbPassword,
		"url":      m.Config.mbURL,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal metabase api credentials: %s", err)
	}

	err = ioutil.WriteFile(filepath.Join(m.Config.mbFolder, credentialFile), creds, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("write api credentials in '%s' failed: %s", filepath.Join(m.Config.mbFolder, credentialFile), err)
	}

	log.Printf("Username: '%s'", m.Config.mbUsername)
	log.Printf("Password: '%s'", m.Config.mbPassword)

	return respJSON, resp, err

}
