package kubernetespodlogs

import (
	"flag"
	"fmt"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func (d *Source) buildConfig() (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}
	if d.Config.KubeConfigFile != "" {
		kubeconfig := flag.String("kubeconfig", d.Config.KubeConfigFile, "kubeconfig path")
		flag.Parse()
		return clientcmd.BuildConfigFromFlags("", *kubeconfig)
	}

	if d.Config.Auth != nil {
		loadingRules := &clientcmd.ClientConfigLoadingRules{}
		configOverrides := &clientcmd.ConfigOverrides{
			ClusterInfo:    d.Config.Auth.Cluster,
			AuthInfo:       d.Config.Auth.User,
			CurrentContext: "",
		}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
		return kubeConfig.ClientConfig()
	}
	// This should never happen, but just in case...
	return nil, fmt.Errorf("could not create kubernetes client configuration")
}
