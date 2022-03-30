package metabase

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type Metabase struct {
	Config        *Config
	Client        *APIClient
	Container     *Container
	Database      *Database
	InternalDBURL string
}

type Config struct {
	Database      *csconfig.DatabaseCfg `yaml:"database"`
	ListenAddr    string                `yaml:"listen_addr"`
	ListenPort    string                `yaml:"listen_port"`
	ListenURL     string                `yaml:"listen_url"`
	Username      string                `yaml:"username"`
	Password      string                `yaml:"password"`
	DBPath        string                `yaml:"metabase_db_path"`
	DockerGroupID string                `yaml:"-"`
}

var (
	metabaseDefaultUser     = "crowdsec@crowdsec.net"
	metabaseDefaultPassword = "!!Cr0wdS3c_M3t4b4s3??"
	metabaseImage           = "metabase/metabase:v0.41.5"
	containerSharedFolder   = "/metabase-data"
	metabaseSQLiteDBURL     = "https://crowdsec-statics-assets.s3-eu-west-1.amazonaws.com/metabase_sqlite.zip"
)

func TestAvailability() error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("cscli dashboard is only available on amd64, but you are running %s", runtime.GOARCH)
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client : %s", err)
	}

	_, err = cli.Ping(context.TODO())
	return err

}

func (m *Metabase) Init(containerName string) error {
	var err error
	var DBConnectionURI string
	var remoteDBAddr string

	switch m.Config.Database.Type {
	case "mysql":
		return fmt.Errorf("'mysql' is not supported yet for cscli dashboard")
		//DBConnectionURI = fmt.Sprintf("MB_DB_CONNECTION_URI=mysql://%s:%d/%s?user=%s&password=%s&allowPublicKeyRetrieval=true", remoteDBAddr, m.Config.Database.Port, m.Config.Database.DbName, m.Config.Database.User, m.Config.Database.Password)
	case "sqlite":
		m.InternalDBURL = metabaseSQLiteDBURL
	case "postgresql", "postgres", "pgsql":
		return fmt.Errorf("'postgresql' is not supported yet by cscli dashboard")
	default:
		return fmt.Errorf("database '%s' not supported", m.Config.Database.Type)
	}

	m.Client, err = NewAPIClient(m.Config.ListenURL)
	if err != nil {
		return err
	}
	m.Database, err = NewDatabase(m.Config.Database, m.Client, remoteDBAddr)
	if err != nil {
		return err
	}
	m.Container, err = NewContainer(m.Config.ListenAddr, m.Config.ListenPort, m.Config.DBPath, containerName, metabaseImage, DBConnectionURI, m.Config.DockerGroupID)
	if err != nil {
		return errors.Wrap(err, "container init")
	}

	return nil
}

func NewMetabase(configPath string, containerName string) (*Metabase, error) {
	m := &Metabase{}
	if err := m.LoadConfig(configPath); err != nil {
		return m, err
	}
	if err := m.Init(containerName); err != nil {
		return m, err
	}
	return m, nil
}

func (m *Metabase) LoadConfig(configPath string) error {
	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		return err
	}

	config := &Config{}

	err = yaml.Unmarshal(yamlFile, config)
	if err != nil {
		return err
	}
	if config.Username == "" {
		return fmt.Errorf("'username' not found in configuration file '%s'", configPath)
	}

	if config.Password == "" {
		return fmt.Errorf("'password' not found in configuration file '%s'", configPath)
	}

	if config.ListenURL == "" {
		return fmt.Errorf("'listen_url' not found in configuration file '%s'", configPath)
	}

	m.Config = config

	return nil

}

func SetupMetabase(dbConfig *csconfig.DatabaseCfg, listenAddr string, listenPort string, username string, password string, mbDBPath string, dockerGroupID string, containerName string) (*Metabase, error) {
	metabase := &Metabase{
		Config: &Config{
			Database:      dbConfig,
			ListenAddr:    listenAddr,
			ListenPort:    listenPort,
			Username:      username,
			Password:      password,
			ListenURL:     fmt.Sprintf("http://%s:%s", listenAddr, listenPort),
			DBPath:        mbDBPath,
			DockerGroupID: dockerGroupID,
		},
	}
	if err := metabase.Init(containerName); err != nil {
		return nil, errors.Wrap(err, "metabase setup init")
	}

	if err := metabase.DownloadDatabase(false); err != nil {
		return nil, errors.Wrap(err, "metabase db download")
	}

	if err := metabase.Container.Create(); err != nil {
		return nil, errors.Wrap(err, "container create")
	}

	if err := metabase.Container.Start(); err != nil {
		return nil, errors.Wrap(err, "container start")
	}

	log.Infof("waiting for metabase to be up (can take up to a minute)")
	if err := metabase.WaitAlive(); err != nil {
		return nil, errors.Wrap(err, "wait alive")
	}

	if err := metabase.Database.Update(); err != nil {
		return nil, errors.Wrap(err, "update database")
	}

	if err := metabase.Scan(); err != nil {
		return nil, errors.Wrap(err, "db scan")
	}

	if err := metabase.ResetCredentials(); err != nil {
		return nil, errors.Wrap(err, "reset creds")
	}

	return metabase, nil
}

func (m *Metabase) WaitAlive() error {
	var err error
	for {
		err = m.Login(metabaseDefaultUser, metabaseDefaultPassword)
		if err != nil {
			if strings.Contains(err.Error(), "password:did not match stored password") {
				log.Errorf("Password mismatch error, is your dashboard already setup ? Run 'cscli dashboard remove' to reset it.")
				return errors.Wrapf(err, "Password mismatch error")
			}
			log.Debugf("%+v", err)
		} else {
			break
		}

		fmt.Printf(".")
		time.Sleep(2 * time.Second)
	}
	fmt.Printf("\n")
	return nil
}

func (m *Metabase) Login(username string, password string) error {
	body := map[string]string{"username": username, "password": password}
	successmsg, errormsg, err := m.Client.Do("POST", routes[sessionEndpoint], body)
	if err != nil {
		return err
	}

	if errormsg != nil {
		return errors.Wrap(err, "http login")
	}
	resp, ok := successmsg.(map[string]interface{})
	if !ok {
		return fmt.Errorf("login: bad response type: %+v", successmsg)
	}
	if _, ok := resp["id"]; !ok {
		return fmt.Errorf("login: can't update session id, no id in response: %v", successmsg)
	}
	id, ok := resp["id"].(string)
	if !ok {
		return fmt.Errorf("login: bad id type: %+v", resp["id"])
	}
	m.Client.Set("Cookie", fmt.Sprintf("metabase.SESSION=%s", id))
	return nil
}

func (m *Metabase) Scan() error {
	_, errormsg, err := m.Client.Do("POST", routes[scanEndpoint], nil)
	if err != nil {
		return err
	}
	if errormsg != nil {
		return errors.Wrap(err, "http scan")
	}

	return nil
}

func (m *Metabase) ResetPassword(current string, new string) error {
	body := map[string]string{
		"id":           "1",
		"password":     new,
		"old_password": current,
	}
	_, errormsg, err := m.Client.Do("PUT", routes[resetPasswordEndpoint], body)
	if err != nil {
		return errors.Wrap(err, "reset username")
	}
	if errormsg != nil {
		return errors.Wrap(err, "http reset password")
	}
	return nil
}

func (m *Metabase) ResetUsername(username string) error {
	body := struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		GroupIDs  []int  `json:"group_ids"`
	}{
		FirstName: "Crowdsec",
		LastName:  "Crowdsec",
		Email:     username,
		GroupIDs:  []int{1, 2},
	}

	_, errormsg, err := m.Client.Do("PUT", routes[userEndpoint], body)
	if err != nil {
		return errors.Wrap(err, "reset username")
	}

	if errormsg != nil {
		return errors.Wrap(err, "http reset username")
	}

	return nil
}

func (m *Metabase) ResetCredentials() error {
	if err := m.ResetPassword(metabaseDefaultPassword, m.Config.Password); err != nil {
		return err
	}

	/*if err := m.ResetUsername(m.Config.Username); err != nil {
		return err
	}*/

	return nil
}

func (m *Metabase) DumpConfig(path string) error {
	data, err := yaml.Marshal(m.Config)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, data, 0600)
}

func (m *Metabase) DownloadDatabase(force bool) error {

	metabaseDBSubpath := path.Join(m.Config.DBPath, "metabase.db")
	_, err := os.Stat(metabaseDBSubpath)
	if err == nil && !force {
		log.Printf("%s exists, skip.", metabaseDBSubpath)
		return nil
	}

	if err := os.MkdirAll(metabaseDBSubpath, 0755); err != nil {
		return fmt.Errorf("failed to create %s : %s", metabaseDBSubpath, err)
	}

	req, err := http.NewRequest("GET", m.InternalDBURL, nil)
	if err != nil {
		return fmt.Errorf("failed to build request to fetch metabase db : %s", err)
	}
	//This needs to be removed once we move the zip out of github
	//req.Header.Add("Accept", `application/vnd.github.v3.raw`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed request to fetch metabase db : %s", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("got http %d while requesting metabase db %s, stop", resp.StatusCode, m.InternalDBURL)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed request read while fetching metabase db : %s", err)
	}
	log.Debugf("Got %d bytes archive", len(body))

	if err := m.ExtractDatabase(bytes.NewReader(body)); err != nil {
		return fmt.Errorf("while extracting zip : %s", err)
	}
	return nil
}

func (m *Metabase) ExtractDatabase(buf *bytes.Reader) error {
	r, err := zip.NewReader(buf, int64(buf.Len()))
	if err != nil {
		return err
	}
	for _, f := range r.File {
		if strings.Contains(f.Name, "..") {
			return fmt.Errorf("invalid path '%s' in archive", f.Name)
		}
		tfname := fmt.Sprintf("%s/%s", m.Config.DBPath, f.Name)
		log.Tracef("%s -> %d", f.Name, f.UncompressedSize64)
		if f.UncompressedSize64 == 0 {
			continue
		}
		tfd, err := os.OpenFile(tfname, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("failed opening target file '%s' : %s", tfname, err)
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("while opening zip content %s : %s", f.Name, err)
		}
		written, err := io.Copy(tfd, rc)
		if err == io.EOF {
			log.Printf("files finished ok")
		} else if err != nil {
			return fmt.Errorf("while copying content to %s : %s", tfname, err)
		}
		log.Debugf("written %d bytes to %s", written, tfname)
		rc.Close()
	}
	return nil
}

func RemoveDatabase(dataDir string) error {
	return os.RemoveAll(path.Join(dataDir, "metabase.db"))
}
