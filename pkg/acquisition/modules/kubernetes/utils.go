package kubernetes

import (
	"fmt"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func (c *Configuration) buildClientConfig() (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}

	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: c.KubeConfigFile}
	overrides := &clientcmd.ConfigOverrides{}
	overrides.CurrentContext = c.KubeContext

	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
	cfg, err = cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("building client config for context %q and kube config file %s: %w", c.KubeContext, c.KubeConfigFile, err)
	}

	return cfg, nil
}
