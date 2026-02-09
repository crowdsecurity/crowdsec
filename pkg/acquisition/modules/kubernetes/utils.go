package kubernetespodlogs

import (
	"errors"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func (s *Source) buildConfig() (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}
	if s.Config.KubeConfigFile != "" {
		return clientcmd.BuildConfigFromFlags("", s.Config.KubeConfigFile)
	}

	if s.Config.Auth != nil {
		loadingRules := &clientcmd.ClientConfigLoadingRules{}
		configOverrides := &clientcmd.ConfigOverrides{
			ClusterInfo:    s.Config.Auth.Cluster,
			AuthInfo:       s.Config.Auth.User,
			CurrentContext: "",
		}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
		return kubeConfig.ClientConfig()
	}
	// This should never happen, but just in case...
	return nil, errors.New("could not create kubernetes client configuration")
}
