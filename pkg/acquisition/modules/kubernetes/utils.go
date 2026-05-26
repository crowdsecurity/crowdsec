package kubernetes

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func (c *Configuration) buildClientConfig(logger *log.Entry) (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err == nil {
		if logger != nil {
			logger.WithFields(log.Fields{
				"auth_mode":         "in_cluster",
				"k8s_host":          cfg.Host,
				"bearer_token_file": cfg.BearerTokenFile,
				"namespace":         c.Namespace,
				"selector":          c.Selector,
				"unique_id":         c.UniqueId,
			}).Info("using in-cluster kubernetes client configuration")
		}
		return cfg, nil
	}

	if logger != nil {
		logger.WithFields(log.Fields{
			"auth_mode": "in_cluster",
			"error":     err,
			"namespace": c.Namespace,
			"selector":  c.Selector,
			"unique_id": c.UniqueId,
		}).Warn("failed to build in-cluster kubernetes client configuration, falling back to kubeconfig")
	}

	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: c.KubeConfigFile}
	overrides := &clientcmd.ConfigOverrides{}
	overrides.CurrentContext = c.KubeContext

	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
	cfg, err = cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("building client config for context %q and kube config file %s: %w", c.KubeContext, c.KubeConfigFile, err)
	}

	if logger != nil {
		logger.WithFields(log.Fields{
			"auth_mode":         "kubeconfig",
			"k8s_host":          cfg.Host,
			"bearer_token_file": cfg.BearerTokenFile,
			"kube_config":       c.KubeConfigFile,
			"kube_context":      c.KubeContext,
			"namespace":         c.Namespace,
			"selector":          c.Selector,
			"unique_id":         c.UniqueId,
		}).Info("using kubeconfig-based kubernetes client configuration")
	}

	return cfg, nil
}
