package metabase

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

func (m *Metabase) WaitAlive() error {
	var resp *http.Response
	var properties map[string]interface{}
	var err error
	for {
		if properties, resp, err = m.GetSession(); err == nil {
			break
		}
		fmt.Printf(".")
		time.Sleep(2 * time.Second)
	}
	fmt.Printf("\n")

	if resp.StatusCode != 200 {
		return fmt.Errorf("api session: server return code %d", resp.StatusCode)
	}

	if properties == nil {
		return fmt.Errorf("bad response from metabase API: %d", resp.StatusCode)
	}

	m.Config.setupToken = properties["setup-token"].(string)
	return nil
}

func (m *Metabase) LoadCredentials() error {
	yamlFile, err := ioutil.ReadFile(filepath.Join(m.Config.mbFolder, credentialFile))
	if err != nil {
		return err
	}

	creds := make(map[string]string)

	var username string
	var password string
	var url string
	var ok bool

	err = yaml.Unmarshal(yamlFile, creds)
	if err != nil {
		return err
	}

	if username, ok = creds["username"]; !ok {
		return fmt.Errorf("'username' not found in credentials file '%s'", filepath.Join(m.Config.mbFolder, credentialFile))
	}

	if password, ok = creds["password"]; !ok {
		return fmt.Errorf("'password' not found in credentials file '%s'", filepath.Join(m.Config.mbFolder, credentialFile))
	}

	if url, ok = creds["url"]; !ok {
		return fmt.Errorf("'url' not found in credentials file '%s'", filepath.Join(m.Config.mbFolder, credentialFile))
	}

	m.Config.mbUsername = username
	m.Config.mbPassword = password
	m.Config.mbURL = url

	if err := m.Init(); err != nil {
		return err
	}

	return nil

}

func (m *Metabase) GetSession() (map[string]interface{}, *http.Response, error) {
	var respJSON map[string]interface{}
	resp, err := m.Client.New().Get(routes[getSession]).Receive(&respJSON, &respJSON)

	if err != nil {
		return nil, nil, err
	}

	return respJSON, resp, err
}

func (m *Metabase) Login() (map[string]interface{}, *http.Response, error) {
	var respJSON map[string]interface{}

	if err := m.LoadCredentials(); err != nil {
		return nil, nil, err
	}

	resp, err := m.Client.New().Post(routes[login]).BodyJSON(map[string]string{
		"username": m.Config.mbUsername,
		"password": m.Config.mbPassword,
	}).Receive(&respJSON, &respJSON)

	if err != nil {
		return nil, nil, err
	}
	m.Client = m.Client.Set("Cookie", fmt.Sprintf("metabase.SESSION=%s", respJSON["id"].(string)))

	m.User, _, err = m.CurrentUser()
	if err != nil {
		return nil, nil, err
	}

	return respJSON, resp, nil

}

func (m *Metabase) ResetPassword(newPassword string) error {
	var respJSON map[string]interface{}
	resp, err := m.Client.New().Post(routes[resetPassword]).BodyJSON(map[string]string{
		"id":           "1",
		"password":     newPassword,
		"old_password": m.Config.mbPassword,
	}).Receive(&respJSON, &respJSON)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrapf(err, "reset password: fail to unmarshall body (status code %d)", resp.StatusCode)
		}
		return fmt.Errorf("reset password: server return code %d: %s", resp.StatusCode, body)
	}

	return nil
}
