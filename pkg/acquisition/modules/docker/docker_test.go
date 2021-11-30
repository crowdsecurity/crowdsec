package dockeracquisition

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	dockerTypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/stretchr/testify/assert"
)

const testContainerName = "docker_test"

func TestConfigure(t *testing.T) {

}

func TestBadConfiguration(t *testing.T) {
	log.Infof("Test 'TestBadConfiguration'")

	tests := []struct {
		config      string
		expectedErr string
	}{
		{
			config:      `foobar: asd`,
			expectedErr: "line 1: field foobar not found in type dockeracquisition.DockerConfiguration",
		},
		{
			config: `
mode: tail
source: docker`,
			expectedErr: "no containers names or containers ID configuration provided",
		},
		{
			config: `
mode: cat
source: docker
container_name:
 - toto`,
			expectedErr: "",
		},
	}

	subLogger := log.WithFields(log.Fields{
		"type": "docker",
	})
	for _, test := range tests {
		f := DockerSource{}
		err := f.Configure([]byte(test.config), subLogger)
		if test.expectedErr != "" && err == nil {
			t.Fatalf("Expected err %s but got nil !", test.expectedErr)
		}
		if test.expectedErr != "" {
			assert.Contains(t, err.Error(), test.expectedErr)
		}
	}
}

func TestConfigureDSN(t *testing.T) {
	log.Infof("Test 'TestConfigureDSN'")

	tests := []struct {
		name        string
		dsn         string
		expectedErr string
	}{
		{
			name:        "invalid DSN",
			dsn:         "asd://",
			expectedErr: "invalid DSN asd:// for docker source, must start with docker://",
		},
		{
			name:        "empty DSN",
			dsn:         "docker://",
			expectedErr: "empty docker:// DSN",
		},
		{
			name:        "DSN ok with log_level",
			dsn:         "docker://test_docker?log_level=warn",
			expectedErr: "",
		},
		{
			name:        "DSN invalid log_level",
			dsn:         "docker://test_docker?log_level=foobar",
			expectedErr: "unknown level foobar: not a valid logrus Level:",
		},
		{
			name:        "DSN ok with multiple parameters",
			dsn:         "docker://test_docker?since=42min&docker_host=unix:///var/run/podman/podman.sock",
			expectedErr: "",
		},
	}
	subLogger := log.WithFields(log.Fields{
		"type": "docker",
	})
	for _, test := range tests {
		f := DockerSource{}
		err := f.ConfigureByDSN(test.dsn, map[string]string{"type": "testtype"}, subLogger)
		if test.expectedErr != "" {
			assert.Contains(t, err.Error(), test.expectedErr)
		} else {
			assert.Equal(t, err, nil)
		}
	}
}

type mockDockerCli struct {
	client.Client
}

/*
func TestStreamingAcquisition(t *testing.T) {
	tests := []struct {
			config         string
			expectedErr    string
			expectedOutput string
			expectedLines  int
			logType        string
			logLevel       log.Level
		}{
			{
				config: `
	source: docker
	mode: cat
	container_name:
	 - docker_test`,
				expectedErr:    "",
				expectedOutput: "",
				expectedLines:  1,
				logType:        "test",
				logLevel:       log.InfoLevel,
			},
		}

		containerID, err := StartContainer(testContainerName)
		if err != nil {
			t.Fatalf("unable to start docker for test: %s", err.Error())
		}

		for _, ts := range tests {
			var logger *log.Logger
			var subLogger *log.Entry
			var hook *test.Hook
			if ts.expectedOutput != "" {
				logger, hook = test.NewNullLogger()
				logger.SetLevel(ts.logLevel)
				subLogger = logger.WithFields(log.Fields{
					"type": "docker",
				})
			} else {
				subLogger = log.WithFields(log.Fields{
					"type": "docker",
				})
			}

			tomb := tomb.Tomb{}
			out := make(chan types.Event)
			dockerSource := DockerSource{}
			err := dockerSource.Configure([]byte(ts.config), subLogger)
			if err != nil {
				t.Fatalf("Unexpected error : %s", err)
			}
			actualLines := 0
			if ts.expectedLines != 0 {
				go func() {
				READLOOP:
					for {
						select {
						case <-out:
							actualLines++
						case <-time.After(1 * time.Second):
							break READLOOP
						}
					}
				}()
			}
			fmt.Printf("RUNNING:!!\n")
			err = dockerSource.StreamingAcquisition(out, &tomb)
			fmt.Printf("ACQUISITION OK:!!\n")
			if ts.expectedErr == "" && err != nil {
				if err := StopContainer(containerID); err != nil {
					t.Fatalf("unable to stop testing container '%s' : %s", testContainerName, err.Error())
				}
				t.Fatalf("Unexpected error : %s", err)
			} else if ts.expectedErr != "" && err != nil {
				assert.Contains(t, err.Error(), ts.expectedErr)
				continue
			} else if ts.expectedErr != "" && err == nil {
				t.Fatalf("Expected error %s, but got nothing !", ts.expectedErr)
			}

			if ts.expectedLines != 0 {
				time.Sleep(1 * time.Second)
				assert.Equal(t, ts.expectedLines, actualLines)
			}
			tomb.Kill(nil)
			tomb.Wait()
			if ts.expectedOutput != "" {
				if hook.LastEntry() == nil {
					if err := StopContainer(containerID); err != nil {
						t.Fatalf("unable to stop testing container '%s' : %s", testContainerName, err.Error())
					}
					t.Fatalf("Expected log output '%s' but got nothing !", ts.expectedOutput)
				}
				assert.Contains(t, hook.LastEntry().Message, ts.expectedOutput)
				hook.Reset()
			}
		}
		if err := StopContainer(containerID); err != nil {
			t.Fatalf("unable to stop testing container '%s' : %s", testContainerName, err.Error())
		}
}

func StartContainer(containerName string) (string, error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", err
	}

	reader, err := cli.ImagePull(ctx, "docker.io/library/alpine", dockerTypes.ImagePullOptions{})
	if err != nil {
		return "", err
	}

	defer reader.Close()
	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image:        "alpine",
		Cmd:          []string{"echo", "hello world"},
		AttachStdin:  false,
		AttachStdout: false,
		AttachStderr: false,
	}, nil, nil, nil, containerName)
	if err != nil {
		if strings.Contains(err.Error(), "is already in use") {
			runningContainer, err := cli.ContainerList(context.Background(), dockerTypes.ContainerListOptions{All: true})
			if err != nil {
				return "", err
			}
			for _, container := range runningContainer {
				for _, contName := range container.Names {
					if containerName == contName[1:] {
						if err := cli.ContainerRemove(ctx, container.ID, dockerTypes.ContainerRemoveOptions{}); err != nil {
							return "", err
						}
						time.Sleep(1)
						return StartContainer(containerName)
					}
				}
			}
		} else {
			return "", err
		}
	}

	if err := cli.ContainerStart(ctx, resp.ID, dockerTypes.ContainerStartOptions{}); err != nil {
		return "", err
	}
	return resp.ID, nil
}

func StopContainer(containerID string) error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	if err := cli.ContainerStop(ctx, containerID, nil); err != nil {
		return err
	}

	if err := cli.ContainerRemove(ctx, containerID, dockerTypes.ContainerRemoveOptions{}); err != nil {
		return err
	}

	return nil
}
*/

func (cli *mockDockerCli) ContainerList(ctx context.Context, options dockerTypes.ContainerListOptions) ([]dockerTypes.Container, error) {
	containers := make([]dockerTypes.Container, 0)
	container := &dockerTypes.Container{
		ID:    "12456",
		Names: []string{testContainerName},
	}
	containers = append(containers, *container)

	return containers, nil
}

func (cli *mockDockerCli) ContainerLogs(ctx context.Context, container string, options dockerTypes.ContainerLogsOptions) (io.ReadCloser, error) {
	data := fmt.Sprintf(`
hello
world
	`)
	r := io.NopCloser(strings.NewReader(data)) // r type is io.ReadCloser

	return r, nil
}

func TestOneShot(t *testing.T) {
	log.Infof("Test 'TestOneShot'")

	tests := []struct {
		dsn            string
		expectedErr    string
		expectedOutput string
		expectedLines  int
		logType        string
		logLevel       log.Level
	}{
		{
			dsn:            "docker://non_exist_docker",
			expectedErr:    "no docker found, can't run one shot acquisition",
			expectedOutput: "",
			expectedLines:  0,
			logType:        "test",
			logLevel:       log.InfoLevel,
		},
		{
			dsn:            "docker://" + testContainerName,
			expectedErr:    "",
			expectedOutput: "",
			expectedLines:  3,
			logType:        "test",
			logLevel:       log.InfoLevel,
		},
	}

	for _, ts := range tests {
		var subLogger *log.Entry
		var logger *log.Logger
		if ts.expectedOutput != "" {
			logger.SetLevel(ts.logLevel)
			subLogger = logger.WithFields(log.Fields{
				"type": "docker",
			})
		} else {
			log.SetLevel(ts.logLevel)
			subLogger = log.WithFields(log.Fields{
				"type": "docker",
			})
		}

		dockerClient := &DockerSource{}
		labels := make(map[string]string)
		labels["type"] = ts.logType

		if err := dockerClient.ConfigureByDSN(ts.dsn, labels, subLogger); err != nil {
			t.Fatalf("unable to configure dsn '%s': %s", ts.dsn, err)
		}
		dockerClient.Client = new(mockDockerCli)
		out := make(chan types.Event)
		actualLines := 0
		if ts.expectedLines != 0 {
			go func() {
			READLOOP:
				for {
					select {
					case <-out:
						actualLines++
					case <-time.After(1 * time.Second):
						break READLOOP
					}
				}
			}()
		}
		tomb := tomb.Tomb{}
		err := dockerClient.OneShotAcquisition(out, &tomb)

		if ts.expectedErr == "" && err != nil {
			t.Fatalf("Unexpected error : %s", err)
		} else if ts.expectedErr != "" && err != nil {
			assert.Contains(t, err.Error(), ts.expectedErr)
			continue
		} else if ts.expectedErr != "" && err == nil {
			t.Fatalf("Expected error %s, but got nothing !", ts.expectedErr)
		}
		// else we do the check before actualLines is incremented ...
		time.Sleep(1 * time.Second)
		if ts.expectedLines != 0 {
			assert.Equal(t, ts.expectedLines, actualLines)
		}
	}

}
