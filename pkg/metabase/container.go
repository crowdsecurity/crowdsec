package metabase

import (
	"bufio"
	"context"
	"fmt"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"
)

type Container struct {
	ListenAddr    string
	ListenPort    string
	SharedFolder  string
	Image         string
	Name          string
	ID            string
	CLI           *client.Client
	MBDBUri       string
	DockerGroupID string
}

func NewContainer(listenAddr string, listenPort string, sharedFolder string, containerName string, image string, mbDBURI string, dockerGroupID string) (*Container, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client : %s", err)
	}
	return &Container{
		ListenAddr:    listenAddr,
		ListenPort:    listenPort,
		SharedFolder:  sharedFolder,
		Image:         image,
		Name:          containerName,
		CLI:           cli,
		MBDBUri:       mbDBURI,
		DockerGroupID: dockerGroupID,
	}, nil
}

func (c *Container) Create() error {
	ctx := context.Background()
	log.Printf("Pulling docker image %s", c.Image)
	reader, err := c.CLI.ImagePull(ctx, c.Image, types.ImagePullOptions{})
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
					HostIP:   c.ListenAddr,
					HostPort: c.ListenPort,
				},
			},
		},
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: c.SharedFolder,
				Target: containerSharedFolder,
			},
		},
	}

	env := []string{
		fmt.Sprintf("MB_DB_FILE=%s/metabase.db", containerSharedFolder),
	}
	if c.MBDBUri != "" {
		env = append(env, c.MBDBUri)
	}

	env = append(env, fmt.Sprintf("MGID=%s", c.DockerGroupID))
	dockerConfig := &container.Config{
		Image: c.Image,
		Tty:   true,
		Env:   env,
	}

	log.Infof("creating container '%s'", c.Name)
	resp, err := c.CLI.ContainerCreate(ctx, dockerConfig, hostConfig, nil, nil, c.Name)
	if err != nil {
		return fmt.Errorf("failed to create container : %s", err)
	}
	c.ID = resp.ID

	return nil
}

func (c *Container) Start() error {
	ctx := context.Background()
	if err := c.CLI.ContainerStart(ctx, c.Name, types.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("failed while starting %s : %s", c.ID, err)
	}

	return nil
}

func StartContainer(name string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client : %s", err)
	}
	ctx := context.Background()
	if err := cli.ContainerStart(ctx, name, types.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("failed while starting %s : %s", name, err)
	}

	return nil
}

func StopContainer(name string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client : %s", err)
	}
	ctx := context.Background()
	to := container.StopOptions{Timeout: ptr.Of(20)}
	if err := cli.ContainerStop(ctx, name, to); err != nil {
		return fmt.Errorf("failed while stopping %s : %s", name, err)
	}
	log.Printf("container stopped successfully")
	return nil
}

func RemoveContainer(name string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client : %s", err)
	}
	ctx := context.Background()
	log.Printf("Removing docker metabase %s", name)
	if err := cli.ContainerRemove(ctx, name, types.ContainerRemoveOptions{}); err != nil {
		return fmt.Errorf("failed to remove container %s : %s", name, err)
	}
	return nil
}

func RemoveImageContainer(image string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client : %s", err)
	}
	ctx := context.Background()
	log.Printf("Removing docker image '%s'", image)
	if _, err := cli.ImageRemove(ctx, image, types.ImageRemoveOptions{}); err != nil {
		return fmt.Errorf("failed to remove image container %s : %s", image, err)
	}
	return nil
}

func IsContainerExist(name string) bool {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("failed to create docker client : %s", err)
	}
	ctx := context.Background()
	if _, err := cli.ContainerInspect(ctx, name); err != nil {
		return false
	}
	return true
}
