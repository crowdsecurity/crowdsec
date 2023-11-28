package dockeracquisition

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	dockerTypes "github.com/docker/docker/api/types"
	dockerContainer "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/stretchr/testify/assert"
)

const testContainerName = "docker_test"

var readLogs = false

func TestConfigure(t *testing.T) {
	log.Infof("Test 'TestConfigure'")

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
		cstest.AssertErrorContains(t, err, test.expectedErr)
	}
}

func TestConfigureDSN(t *testing.T) {
	log.Infof("Test 'TestConfigureDSN'")
	var dockerHost string
	if runtime.GOOS == "windows" {
		dockerHost = "npipe:////./pipe/docker_engine"
	} else {
		dockerHost = "unix:///var/run/podman/podman.sock"
	}
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
			dsn:         fmt.Sprintf("docker://test_docker?since=42min&docker_host=%s", dockerHost),
			expectedErr: "",
		},
	}
	subLogger := log.WithFields(log.Fields{
		"type": "docker",
	})
	for _, test := range tests {
		f := DockerSource{}
		err := f.ConfigureByDSN(test.dsn, map[string]string{"type": "testtype"}, subLogger, "")
		cstest.AssertErrorContains(t, err, test.expectedErr)
	}
}

type mockDockerCli struct {
	client.Client
}

func TestStreamingAcquisition(t *testing.T) {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.Info("Test 'TestStreamingAcquisition'")
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
			expectedLines:  3,
			logType:        "test",
			logLevel:       log.InfoLevel,
		},
		{
			config: `
source: docker
mode: cat
container_name_regexp:
 - docker_*`,
			expectedErr:    "",
			expectedOutput: "",
			expectedLines:  3,
			logType:        "test",
			logLevel:       log.InfoLevel,
		},
	}

	for _, ts := range tests {
		var logger *log.Logger
		var subLogger *log.Entry
		if ts.expectedOutput != "" {
			logger.SetLevel(ts.logLevel)
			subLogger = logger.WithFields(log.Fields{
				"type": "docker",
			})
		} else {
			subLogger = log.WithFields(log.Fields{
				"type": "docker",
			})
		}

		readLogs = false
		dockerTomb := tomb.Tomb{}
		out := make(chan types.Event)
		dockerSource := DockerSource{}
		err := dockerSource.Configure([]byte(ts.config), subLogger)
		if err != nil {
			t.Fatalf("Unexpected error : %s", err)
		}
		dockerSource.Client = new(mockDockerCli)
		actualLines := 0
		readerTomb := &tomb.Tomb{}
		streamTomb := tomb.Tomb{}
		streamTomb.Go(func() error {
			return dockerSource.StreamingAcquisition(out, &dockerTomb)
		})
		readerTomb.Go(func() error {
			time.Sleep(1 * time.Second)
			ticker := time.NewTicker(1 * time.Second)
			for {
				select {
				case <-out:
					actualLines++
					ticker.Reset(1 * time.Second)
				case <-ticker.C:
					log.Infof("no more lines to read")
					dockerSource.t.Kill(nil)
					return nil
				}
			}
		})
		cstest.AssertErrorContains(t, err, ts.expectedErr)

		if err := readerTomb.Wait(); err != nil {
			t.Fatal(err)
		}
		if ts.expectedLines != 0 {
			assert.Equal(t, ts.expectedLines, actualLines)
		}
		err = streamTomb.Wait()
		if err != nil {
			t.Fatalf("docker acquisition error: %s", err)
		}
	}

}

func (cli *mockDockerCli) ContainerList(ctx context.Context, options dockerTypes.ContainerListOptions) ([]dockerTypes.Container, error) {
	if readLogs == true {
		return []dockerTypes.Container{}, nil
	}
	containers := make([]dockerTypes.Container, 0)
	container := &dockerTypes.Container{
		ID:    "12456",
		Names: []string{testContainerName},
	}
	containers = append(containers, *container)

	return containers, nil
}

func (cli *mockDockerCli) ContainerLogs(ctx context.Context, container string, options dockerTypes.ContainerLogsOptions) (io.ReadCloser, error) {
	if readLogs == true {
		return io.NopCloser(strings.NewReader("")), nil
	}
	readLogs = true
	data := []string{"docker\n", "test\n", "1234\n"}
	ret := ""
	for _, line := range data {
		startLineByte := make([]byte, 8)
		binary.LittleEndian.PutUint32(startLineByte, 1) //stdout stream
		binary.BigEndian.PutUint32(startLineByte[4:], uint32(len(line)))
		ret += fmt.Sprintf("%s%s", startLineByte, line)
	}
	r := io.NopCloser(strings.NewReader(ret)) // r type is io.ReadCloser
	return r, nil
}

func (cli *mockDockerCli) ContainerInspect(ctx context.Context, c string) (dockerTypes.ContainerJSON, error) {
	r := dockerTypes.ContainerJSON{
		Config: &dockerContainer.Config{
			Tty: false,
		},
	}
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
			expectedErr:    "no container found named: non_exist_docker, can't run one shot acquisition",
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

		readLogs = false
		dockerClient := &DockerSource{}
		labels := make(map[string]string)
		labels["type"] = ts.logType

		if err := dockerClient.ConfigureByDSN(ts.dsn, labels, subLogger, ""); err != nil {
			t.Fatalf("unable to configure dsn '%s': %s", ts.dsn, err)
		}
		dockerClient.Client = new(mockDockerCli)
		out := make(chan types.Event, 100)
		tomb := tomb.Tomb{}
		err := dockerClient.OneShotAcquisition(out, &tomb)
		cstest.AssertErrorContains(t, err, ts.expectedErr)

		// else we do the check before actualLines is incremented ...
		if ts.expectedLines != 0 {
			assert.Equal(t, ts.expectedLines, len(out))
		}
	}

}
