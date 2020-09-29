package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/dghubble/sling"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	metabaseImage  = "metabase/metabase"
	metabaseDbURI  = "https://crowdsec-statics-assets.s3-eu-west-1.amazonaws.com/metabase.db.zip"
	metabaseDbPath = "/var/lib/crowdsec/data"
	/**/
	metabaseListenAddress = "127.0.0.1"
	metabaseListenPort    = "3000"
	metabaseContainerID   = "/crowdsec-metabase"
	/*informations needed to setup a random password on user's behalf*/
	metabaseURI          = "http://localhost:3000/api/"
	metabaseURISession   = "session"
	metabaseURIRescan    = "database/2/rescan_values"
	metabaseURIUpdatepwd = "user/1/password"
	defaultPassword      = "c6cmetabase"
	defaultEmail         = "metabase@crowdsec.net"
)

func NewDashboardCmd() *cobra.Command {
	/* ---- UPDATE COMMAND */
	var cmdDashboard = &cobra.Command{
		Use:   "dashboard",
		Short: "Start a dashboard (metabase) container.",
		Long:  `Start a metabase container exposing dashboards and metrics.`,
		Args:  cobra.ExactArgs(1),
		Example: `cscli dashboard setup
cscli dashboard start
cscli dashboard stop
cscli dashboard setup --force`,
	}

	var force bool
	var cmdDashSetup = &cobra.Command{
		Use:   "setup",
		Short: "Setup a metabase container.",
		Long:  `Perform a metabase docker setup, download standard dashboards, create a fresh user and start the container`,
		Args:  cobra.ExactArgs(0),
		Example: `cscli dashboard setup
cscli dashboard setup --force
cscli dashboard setup -l 0.0.0.0 -p 443
 `,
		Run: func(cmd *cobra.Command, args []string) {
			if err := downloadMetabaseDB(force); err != nil {
				log.Fatalf("Failed to download metabase DB : %s", err)
			}
			log.Infof("Downloaded metabase DB")
			if err := createMetabase(); err != nil {
				log.Fatalf("Failed to start metabase container : %s", err)
			}
			log.Infof("Started metabase")
			newpassword := generatePassword(64)
			if err := resetMetabasePassword(newpassword); err != nil {
				log.Fatalf("Failed to reset password : %s", err)
			}
			log.Infof("Setup finished")
			log.Infof("url : http://%s:%s", metabaseListenAddress, metabaseListenPort)
			log.Infof("username: %s", defaultEmail)
			log.Infof("password: %s", newpassword)
		},
	}
	cmdDashSetup.Flags().BoolVarP(&force, "force", "f", false, "Force setup : override existing files.")
	cmdDashSetup.Flags().StringVarP(&metabaseDbPath, "dir", "d", metabaseDbPath, "Shared directory with metabase container.")
	cmdDashSetup.Flags().StringVarP(&metabaseListenAddress, "listen", "l", metabaseListenAddress, "Listen address of container")
	cmdDashSetup.Flags().StringVarP(&metabaseListenPort, "port", "p", metabaseListenPort, "Listen port of container")
	cmdDashboard.AddCommand(cmdDashSetup)

	var cmdDashStart = &cobra.Command{
		Use:   "start",
		Short: "Start the metabase container.",
		Long:  `Stats the metabase container using docker.`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := startMetabase(); err != nil {
				log.Fatalf("Failed to start metabase container : %s", err)
			}
			log.Infof("Started metabase")
			log.Infof("url : http://%s:%s", metabaseListenAddress, metabaseListenPort)
		},
	}
	cmdDashboard.AddCommand(cmdDashStart)

	var remove bool
	var cmdDashStop = &cobra.Command{
		Use:   "stop",
		Short: "Stops the metabase container.",
		Long:  `Stops the metabase container using docker.`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := stopMetabase(remove); err != nil {
				log.Fatalf("Failed to stop metabase container : %s", err)
			}
		},
	}
	cmdDashStop.Flags().BoolVarP(&remove, "remove", "r", false, "remove (docker rm) container as well.")
	cmdDashboard.AddCommand(cmdDashStop)
	return cmdDashboard
}

func downloadMetabaseDB(force bool) error {

	metabaseDBSubpath := path.Join(metabaseDbPath, "metabase.db")

	_, err := os.Stat(metabaseDBSubpath)
	if err == nil && !force {
		log.Printf("%s exists, skip.", metabaseDBSubpath)
		return nil
	}

	if err := os.MkdirAll(metabaseDBSubpath, 0755); err != nil {
		return fmt.Errorf("failed to create %s : %s", metabaseDBSubpath, err)
	}

	req, err := http.NewRequest("GET", metabaseDbURI, nil)
	if err != nil {
		return fmt.Errorf("failed to build request to fetch metabase db : %s", err)
	}
	//This needs to be removed once we move the zip out of github
	req.Header.Add("Accept", `application/vnd.github.v3.raw`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed request to fetch metabase db : %s", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("got http %d while requesting metabase db %s, stop", resp.StatusCode, metabaseDbURI)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed request read while fetching metabase db : %s", err)
	}

	log.Printf("Got %d bytes archive", len(body))
	if err := extractMetabaseDB(bytes.NewReader(body)); err != nil {
		return fmt.Errorf("while extracting zip : %s", err)
	}
	return nil
}

func extractMetabaseDB(buf *bytes.Reader) error {
	r, err := zip.NewReader(buf, int64(buf.Len()))
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range r.File {
		if strings.Contains(f.Name, "..") {
			return fmt.Errorf("invalid path '%s' in archive", f.Name)
		}
		tfname := fmt.Sprintf("%s/%s", metabaseDbPath, f.Name)
		log.Debugf("%s -> %d", f.Name, f.UncompressedSize64)
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
		log.Infof("written %d bytes to %s", written, tfname)
		rc.Close()
	}
	return nil
}

func resetMetabasePassword(newpassword string) error {

	httpctx := sling.New().Base(metabaseURI).Set("User-Agent", fmt.Sprintf("Crowdsec/%s", cwversion.VersionStr()))

	log.Printf("Waiting for metabase API to be up (can take up to a minute)")
	for {
		sessionreq, err := httpctx.New().Post(metabaseURISession).BodyJSON(map[string]string{"username": defaultEmail, "password": defaultPassword}).Request()
		if err != nil {
			return fmt.Errorf("api signin: HTTP request creation failed: %s", err)
		}
		httpClient := http.Client{Timeout: 20 * time.Second}
		resp, err := httpClient.Do(sessionreq)
		if err != nil {
			fmt.Printf(".")
			log.Debugf("While waiting for metabase to be up : %s", err)
			time.Sleep(1 * time.Second)
			continue
		}
		defer resp.Body.Close()
		fmt.Printf("\n")
		log.Printf("Metabase API is up")
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("metabase session unable to read API response body: '%s'", err)
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("metabase session http error (%d): %s", resp.StatusCode, string(body))
		}
		log.Printf("Successfully authenticated")
		jsonResp := make(map[string]string)
		err = json.Unmarshal(body, &jsonResp)
		if err != nil {
			return fmt.Errorf("failed to unmarshal metabase api response '%s': %s", string(body), err.Error())
		}
		log.Debugf("unmarshaled response : %v", jsonResp)
		httpctx = httpctx.Set("Cookie", fmt.Sprintf("metabase.SESSION=%s", jsonResp["id"]))
		break
	}

	/*rescan values*/
	sessionreq, err := httpctx.New().Post(metabaseURIRescan).Request()
	if err != nil {
		return fmt.Errorf("metabase rescan_values http error : %s", err)
	}
	httpClient := http.Client{Timeout: 20 * time.Second}
	resp, err := httpClient.Do(sessionreq)
	if err != nil {
		return fmt.Errorf("while trying to do rescan api call to metabase : %s", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("while reading rescan api call response : %s", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("got '%s' (http:%d) while trying to rescan metabase", string(body), resp.StatusCode)
	}
	/*update password*/
	sessionreq, err = httpctx.New().Put(metabaseURIUpdatepwd).BodyJSON(map[string]string{
		"id":           "1",
		"password":     newpassword,
		"old_password": defaultPassword}).Request()
	if err != nil {
		return fmt.Errorf("metabase password change http error : %s", err)
	}
	httpClient = http.Client{Timeout: 20 * time.Second}
	resp, err = httpClient.Do(sessionreq)
	if err != nil {
		return fmt.Errorf("while trying to reset metabase password : %s", err)
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("while reading from %s: '%s'", metabaseURIUpdatepwd, err)
	}
	if resp.StatusCode != 200 {
		log.Printf("Got %s (http:%d) while trying to reset password.", string(body), resp.StatusCode)
		log.Printf("Password has probably already been changed.")
		log.Printf("Use the dashboard install command to reset existing setup.")
		return fmt.Errorf("got http error %d on %s : %s", resp.StatusCode, metabaseURIUpdatepwd, string(body))
	}
	log.Printf("Changed password !")
	return nil
}

func startMetabase() error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client : %s", err)
	}

	if err := cli.ContainerStart(ctx, metabaseContainerID, types.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("failed while starting %s : %s", metabaseContainerID, err)
	}

	return nil
}

func stopMetabase(remove bool) error {
	log.Printf("Stop docker metabase %s", metabaseContainerID)
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client : %s", err)
	}
	var to time.Duration = 20 * time.Second
	if err := cli.ContainerStop(ctx, metabaseContainerID, &to); err != nil {
		return fmt.Errorf("failed while stopping %s : %s", metabaseContainerID, err)
	}

	if remove {
		log.Printf("Removing docker metabase %s", metabaseContainerID)
		if err := cli.ContainerRemove(ctx, metabaseContainerID, types.ContainerRemoveOptions{}); err != nil {
			return fmt.Errorf("failed remove container %s : %s", metabaseContainerID, err)
		}
	}
	return nil
}

func createMetabase() error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to start docker client : %s", err)
	}

	log.Printf("Pulling docker image %s", metabaseImage)
	reader, err := cli.ImagePull(ctx, metabaseImage, types.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull docker image : %s", err)
	}
	defer reader.Close()
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fmt.Print(".")
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read imagepull reader: %s", err)
	}
	fmt.Print("\n")

	hostConfig := &container.HostConfig{
		PortBindings: nat.PortMap{
			"3000/tcp": []nat.PortBinding{
				{
					HostIP:   metabaseListenAddress,
					HostPort: metabaseListenPort,
				},
			},
		},
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: metabaseDbPath,
				Target: "/metabase-data",
			},
		},
	}
	dockerConfig := &container.Config{
		Image: metabaseImage,
		Tty:   true,
		Env:   []string{"MB_DB_FILE=/metabase-data/metabase.db"},
	}

	log.Printf("Creating container")
	resp, err := cli.ContainerCreate(ctx, dockerConfig, hostConfig, nil, metabaseContainerID)
	if err != nil {
		return fmt.Errorf("failed to create container : %s", err)
	}
	log.Printf("Starting container")
	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("failed to start docker container : %s", err)
	}
	return nil
}
