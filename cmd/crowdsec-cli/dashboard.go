package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/metabase"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	metabaseURL        string
	metabaseImportPath string
	metabaseExportPath string

	metabaseFolderPath  = ""
	metabaseArchivePath = "/etc/crowdsec/metabase/crowdsec_metabase.tar"
	metabaseArchive     = "crowdsec_metabase.tar"

	metabaseConfigPath string
	metabaseConfigFile = "config.yaml"

	metabaseUsername = "crowdsec@crowdsec.net"
	metabasePassword string

	metabaseImage         = "metabase/metabase"
	metabaseDbURI         = "https://crowdsec-statics-assets.s3-eu-west-1.amazonaws.com/metabase.db.zip"
	metabaseListenAddress = "127.0.0.1"
	metabaseListenPort    = "3000"
	metabaseContainerID   = "/crowdsec-metabase"
	metabaseURI           = "http://localhost:3000/api/"
)

func NewDashboardCmd() *cobra.Command {
	/* ---- UPDATE COMMAND */
	var cmdDashboard = &cobra.Command{
		Use:   "dashboard [command]",
		Short: "Manage your metabase dashboard container",
		Long:  `Install/Start/Stop/Remove a metabase container exposing dashboard and metrics.`,
		Args:  cobra.ExactArgs(1),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if metabaseFolderPath == "" {
				metabaseFolderPath = filepath.Join(csConfig.ConfigPaths.ConfigDir, "metabase/")
			}
			metabaseConfigPath = filepath.Join(metabaseFolderPath, metabaseConfigFile)
			if err := os.MkdirAll(csConfig.ConfigPaths.DataDir, os.ModePerm); err != nil {
				log.Fatalf(err.Error())
			}
		},
		Example: `
cscli dashboard setup
cscli dashboard start
cscli dashboard stop
cscli dashboard remove
`,
	}

	cmdDashboard.Flags().StringVar(&metabaseFolderPath, "metabase-folder", metabaseFolderPath, "metabase folder to store dashboards/datasources ..")

	var force bool
	var cmdDashSetup = &cobra.Command{
		Use:   "setup",
		Short: "Setup a metabase container.",
		Long:  `Perform a metabase docker setup, download standard dashboards, create a fresh user and start the container (will use configured database in crowdsec local api configuration).`,
		Args:  cobra.ExactArgs(0),
		Example: `
cscli dashboard setup
cscli dashboard setup --listen 0.0.0.0 -u <username> -p <password>
cscli dashboard setup -l 0.0.0.0 -p 443 -u <username> -p <password>
 `,
		Run: func(cmd *cobra.Command, args []string) {

			if err := createMetabase(); err != nil {
				log.Fatalf("failed to start metabase container : %s", err)
			}

			if metabasePassword == "" {
				metabasePassword = generatePassword(16)
			}

			mbURL := fmt.Sprintf("http://%s:%s/", metabaseListenAddress, metabaseListenPort)
			mb := &metabase.Metabase{
				Config: &metabase.Config{
					Database:      csConfig.DbConfig,
					ListenAddress: metabaseListenAddress,
					ListenPort:    metabaseListenPort,
					URL:           mbURL,
					Username:      metabaseUsername,
					Password:      metabasePassword,
					Folder:        metabaseFolderPath,
				},
			}
			if err := mb.Setup(metabaseArchivePath); err != nil {
				log.Fatalf(err.Error())
			}

			if err := mb.DumpConfig(metabaseConfigPath); err != nil {
				log.Fatalf(err.Error())
			}

			log.Printf("URL: '%s'", mb.Config.URL)
			log.Printf("Username: '%s'", mb.Config.Username)
			log.Printf("Password: '%s'", mb.Config.Password)

		},
	}
	cmdDashSetup.Flags().BoolVarP(&force, "force", "f", false, "Force setup : override existing files.")
	cmdDashSetup.Flags().StringVarP(&metabaseListenAddress, "listen", "l", metabaseListenAddress, "Listen address of container")
	cmdDashSetup.Flags().StringVarP(&metabaseListenPort, "port", "p", metabaseListenPort, "Listen port of container")
	cmdDashSetup.Flags().StringVarP(&metabaseUsername, "username", "u", metabaseUsername, "metabase username")
	cmdDashSetup.Flags().StringVar(&metabasePassword, "password", "", "metabase password")
	cmdDashSetup.Flags().StringVarP(&metabaseArchivePath, "archive", "a", metabaseArchivePath, "metabase archive path")

	cmdDashboard.AddCommand(cmdDashSetup)

	var cmdDashStart = &cobra.Command{
		Use:   "start",
		Short: "Start the metabase container.",
		Long:  `Stats the metabase container using docker.`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := startMetabase(); err != nil {
				log.Fatalf("failed to start metabase container : %s", err)
			}
			mb, err := metabase.NewMetabase(metabaseConfigPath)
			if err != nil {
				log.Fatalf(err.Error())
			}
			log.Infof("Metabase started")
			log.Printf("URL: '%s'", mb.Config.URL)
			log.Printf("Username: '%s'", mb.Config.Username)
			log.Printf("Password: '%s'", mb.Config.Password)
		},
	}
	cmdDashboard.AddCommand(cmdDashStart)

	var cmdDashStop = &cobra.Command{
		Use:   "stop",
		Short: "Stops the metabase container.",
		Long:  `Stops the metabase container using docker.`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := stopMetabase(); err != nil {
				log.Fatalf("Failed to stop metabase container : %s", err)
			}
		},
	}
	cmdDashboard.AddCommand(cmdDashStop)

	var cmdDashRemove = &cobra.Command{
		Use:   "remove",
		Short: "removes the metabase container.",
		Long:  `removes the metabase container using docker.`,
		Args:  cobra.ExactArgs(0),
		Example: `
cscli dashboard remove
cscli dashboard remove --force
 `,
		Run: func(cmd *cobra.Command, args []string) {
			if force {
				if err := stopMetabase(); err != nil {
					log.Fatalf("Failed to stop metabase container : %s", err)
				}
			}
			if err := removeMetabase(); err != nil {
				log.Fatalf("Failed to remove metabase container : %s", err)
			}
			if force {
				if err := removeMetabaseImage(); err != nil {
					log.Fatalf("Failed to stop metabase container : %s", err)
				}
			}
		},
	}
	cmdDashRemove.Flags().BoolVarP(&force, "force", "f", false, "Force remove : stop the container if running and remove.")
	cmdDashboard.AddCommand(cmdDashRemove)

	var cmdDashExport = &cobra.Command{
		Use:   "export",
		Short: "export the metabase dashboards.",
		Long:  `export the metabase dashboards to a .tar archive`,
		Args:  cobra.ExactArgs(0),
		Example: `
cscli dashboard export
cscli dashboard export -a <export_archive_path>
 `,
		Run: func(cmd *cobra.Command, args []string) {
			mb, err := metabase.NewMetabase(metabaseConfigPath)
			if err != nil {
				log.Fatalf(err.Error())
			}

			if err := mb.Login(); err != nil {
				log.Fatalf(err.Error())
			}

			if err := mb.Export(metabaseExportPath); err != nil {
				log.Fatalf(err.Error())
			}
			log.Infof("dashboards exported successfully to '%s'", metabaseExportPath)
		},
	}
	cmdDashExport.Flags().StringVarP(&metabaseExportPath, "archive", "a", "./", "Export metabase to provided path")
	cmdDashboard.AddCommand(cmdDashExport)

	var cmdDashImport = &cobra.Command{
		Use:   "import",
		Short: "import the metabase container.",
		Long:  `import the metabase container using docker.`,
		Args:  cobra.ExactArgs(0),
		Example: `
cscli dashboard import
cscli dashboard import -a <import_archive_path>
`,
		Run: func(cmd *cobra.Command, args []string) {
			mb, err := metabase.NewMetabase(metabaseConfigPath)
			if err != nil {
				log.Fatalf(err.Error())
			}

			if err := mb.Login(); err != nil {
				log.Fatalf(err.Error())
			}

			if err := mb.Import(metabaseImportPath); err != nil {
				log.Fatalf(err.Error())
			}
		},
	}
	cmdDashImport.Flags().StringVarP(&metabaseImportPath, "archive", "a", "", "import metabase from provided path")
	cmdDashboard.AddCommand(cmdDashImport)

	return cmdDashboard
}

func downloadMetabaseDB(force bool) error {

	metabaseDBSubpath := path.Join(csConfig.ConfigPaths.DataDir, "metabase.db")

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
		tfname := fmt.Sprintf("%s/%s", csConfig.ConfigPaths.DataDir, f.Name)
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
		log.Infof("written %d bytes to %s", written, tfname)
		rc.Close()
	}
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

func stopMetabase() error {
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

	return nil
}

func removeMetabase() error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client : %s", err)
	}

	log.Printf("Removing docker metabase %s", metabaseContainerID)
	if err := cli.ContainerRemove(ctx, metabaseContainerID, types.ContainerRemoveOptions{}); err != nil {
		return fmt.Errorf("failed remove container %s : %s", metabaseContainerID, err)
	}

	return nil
}

func removeMetabaseImage() error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client : %s", err)
	}

	log.Printf("Removing docker image %s", metabaseImage)
	if _, err := cli.ImageRemove(ctx, metabaseImage, types.ImageRemoveOptions{}); err != nil {
		return fmt.Errorf("failed remove %s image: %s", metabaseImage, err)
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
				Source: csConfig.ConfigPaths.DataDir,
				Target: "/metabase-data",
			},
		},
	}
	dockerConfig := &container.Config{
		Image: metabaseImage,
		Tty:   true,
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
