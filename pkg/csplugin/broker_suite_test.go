package csplugin

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type PluginSuite struct {
	suite.Suite

	// where the plugin is built - temporary directory for the suite
	buildDir string
	// full path to the built plugin binary
	builtBinary string

	runDir       string // temporary directory for each test
	pluginDir    string // (config_paths.plugin_dir)
	notifDir     string // (config_paths.notification_dir)
	pluginBinary string // full path to the plugin binary (unique for each test)
	pluginConfig string // full path to the notification config (unique for each test)

	pluginBroker *PluginBroker
}

func TestPluginSuite(t *testing.T) {
	suite.Run(t, new(PluginSuite))
}

func (s *PluginSuite) SetupSuite() {
	var err error

	t := s.T()

	s.buildDir, err = os.MkdirTemp("", "cs_plugin_test_build")
	require.NoError(t, err)

	s.builtBinary = filepath.Join(s.buildDir, "notification-dummy")

	if runtime.GOOS == "windows" {
		s.builtBinary += ".exe"
	}

	cmd := exec.Command("go", "build", "-o", s.builtBinary, "../../cmd/notification-dummy/")
	err = cmd.Run()
	require.NoError(t, err, "while building dummy plugin")
}

func (s *PluginSuite) TearDownSuite() {
	t := s.T()
	err := os.RemoveAll(s.buildDir)
	require.NoError(t, err)
}

func copyFile(src string, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()

	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()

	_, err = io.Copy(d, s)
	if err != nil {
		return err
	}

	err = d.Sync()
	if err != nil {
		return err
	}

	return nil
}

func (s *PluginSuite) SetupTest() {
	s.SetupSubTest()
}

func (s *PluginSuite) TearDownTest() {
	s.TearDownSubTest()
}

func (s *PluginSuite) SetupSubTest() {
	var err error
	t := s.T()

	s.runDir, err = os.MkdirTemp("", "cs_plugin_test")
	require.NoError(t, err)

	s.pluginDir = filepath.Join(s.runDir, "bin")
	err = os.MkdirAll(filepath.Join(s.runDir, "bin"), 0o755)
	require.NoError(t, err, "while creating bin dir")

	s.notifDir = filepath.Join(s.runDir, "config")
	err = os.MkdirAll(s.notifDir, 0o755)
	require.NoError(t, err, "while creating config dir")

	s.pluginBinary = filepath.Join(s.pluginDir, "notification-dummy")

	if runtime.GOOS == "windows" {
		s.pluginBinary += ".exe"
	}

	err = copyFile(s.builtBinary, s.pluginBinary)
	require.NoError(t, err, "while copying built binary")
	err = os.Chmod(s.pluginBinary, 0o744)
	require.NoError(t, err, "chmod 0744 %s", s.pluginBinary)

	s.pluginConfig = filepath.Join(s.notifDir, "dummy.yaml")
	err = copyFile("testdata/dummy.yaml", s.pluginConfig)
	require.NoError(t, err, "while copying plugin config")
}

func (s *PluginSuite) TearDownSubTest() {
	t := s.T()
	if s.pluginBroker != nil {
		s.pluginBroker.Kill()
		s.pluginBroker = nil
	}

	err := os.RemoveAll(s.runDir)
	if runtime.GOOS != "windows" {
		require.NoError(t, err)
	}

	os.Remove("./out")
}

func (s *PluginSuite) InitBroker(procCfg *csconfig.PluginCfg) (*PluginBroker, error) {
	pb := PluginBroker{}
	if procCfg == nil {
		procCfg = &csconfig.PluginCfg{}
	}
	profiles := csconfig.NewDefaultConfig().API.Server.Profiles
	profiles = append(profiles, &csconfig.ProfileCfg{
		Notifications: []string{"dummy_default"},
	})
	err := pb.Init(procCfg, profiles, &csconfig.ConfigurationPaths{
		PluginDir:       s.pluginDir,
		NotificationDir: s.notifDir,
	})
	s.pluginBroker = &pb
	return s.pluginBroker, err
}
