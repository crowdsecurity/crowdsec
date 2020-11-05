package metabase

import (
	"bufio"
	"context"
	"fmt"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	log "github.com/sirupsen/logrus"
)

type Container struct {
	ListenAddr   string
	ListenPort   string
	SharedFolder string
	Image        string
	Name         string
	ID           string
	CLI          *client.Client
	MBDBUri      string
}

func NewContainer(listenAddr string, listenPort string, sharedFolder string, name string, image string, mbDBURI string) (*Container, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client : %s", err)
	}
	return &Container{
		ListenAddr:   listenAddr,
		ListenPort:   listenPort,
		SharedFolder: sharedFolder,
		Image:        image,
		Name:         name,
		CLI:          cli,
		MBDBUri:      mbDBURI,
	}, nil
}

func (c *Container) Start() error {
	ctx := context.Background()
	if err := c.CLI.ContainerStart(ctx, c.ID, types.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("failed while starting %s : %s", c.ID, err)
	}

	return nil
}

func (c *Container) Stop() error {
	ctx := context.Background()
	var to time.Duration = 20 * time.Second
	if err := c.CLI.ContainerStop(ctx, c.Name, &to); err != nil {
		return fmt.Errorf("failed while stopping %s : %s", c.ID, err)
	}
	log.Printf("container stopped successfully")
	return nil
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

	dockerConfig := &container.Config{
		Image: c.Image,
		Tty:   true,
		Env:   env,
	}

	log.Infof("creating container '%s'", c.Name)
	resp, err := c.CLI.ContainerCreate(ctx, dockerConfig, hostConfig, nil, c.Name)
	if err != nil {
		return fmt.Errorf("failed to create container : %s", err)
	}
	c.ID = resp.ID

	return nil
}

func (c *Container) Remove() error {
	ctx := context.Background()
	log.Printf("Removing docker metabase %s", c.Name)
	if err := c.CLI.ContainerRemove(ctx, c.Name, types.ContainerRemoveOptions{}); err != nil {
		return fmt.Errorf("failed remove container %s : %s", c.Name, err)
	}
	return nil
}

func (c *Container) RemoveImage() error {
	ctx := context.Background()

	log.Printf("Removing docker image %s", c.Image)
	if _, err := c.CLI.ImageRemove(ctx, c.Image, types.ImageRemoveOptions{}); err != nil {
		return fmt.Errorf("failed remove %s image: %s", c.Image, err)
	}

	return nil
}
