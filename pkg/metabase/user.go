package metabase

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

type User struct {
	Email       string `json:"email"`
	FirstName   string `json:"first_name"`
	LastLogin   string `json:"last_login"`
	IsQbnewb    bool   `json:"is_qbnewb"`
	IsSuperuser bool   `json:"is_superuser"`
	ID          int    `json:"id"`
	LastName    string `json:"last_name"`
	DateJoined  string `json:"date_joined"`
	CommonName  string `json:"common_name"`
	Client      *HTTP  `json:"-"`
	Username    string `json:"-"`
	Password    string `json:"-"`
}

func NewUser(config *Config, client *HTTP) (*User, error) {
	user := &User{
		Username: config.mbUsername,
		Password: config.mbPassword,
		Client:   client,
	}

	return user, nil
}

func (u *User) UpdateCurrent() error {
	success, errormsg, err := u.Client.Do("GET", routes[currentUserEndpoint], nil)
	if err != nil {
		return err
	}

	if errormsg != nil {
		return fmt.Errorf("update current: %+v", errormsg)
	}
	user, err := json.Marshal(success)
	if err != nil {
		return errors.Wrap(err, "update current:")
	}

	if err := json.Unmarshal(user, u); err != nil {
		return errors.Wrap(err, "udpate current:")
	}

	return nil

}

func (u *User) Login() (interface{}, error) {

	body := map[string]string{
		"username": u.Username,
		"password": u.Password,
	}
	success, errormsg, err := u.Client.Do("POST", routes[loginEndpoint], body)
	if err != nil {
		return nil, err
	}

	if errormsg != nil {
		return nil, fmt.Errorf("login: %+v", errormsg)
	}
	resp, ok := success.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("login: bad response type: %+v", success)
	}
	if _, ok := resp["id"]; !ok {
		return nil, fmt.Errorf("can't update session id, no id in response: %v", resp)
	}
	id, ok := resp["id"].(string)
	if !ok {
		return nil, fmt.Errorf("login: bad id type: %+v", resp["id"])
	}

	u.Client.Set("Cookie", fmt.Sprintf("metabase.SESSION=%s", id))
	if err := u.UpdateCurrent(); err != nil {
		return nil, err
	}

	if err := u.UpdateCurrent(); err != nil {
		return nil, err

	}

	return body, nil
}

func (u *User) ResetPassword(newPassword string) error {
	_, errormsg, err := u.Client.Do("POST", routes[resetPasswordEndpoint], map[string]string{
		"id":           "1",
		"password":     newPassword,
		"old_password": u.Password,
	})
	if err != nil {
		return err
	}

	if errormsg != nil {
		return fmt.Errorf("reset password: %+v", errormsg)
	}

	return nil
}
