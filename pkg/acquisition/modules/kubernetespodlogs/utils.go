package kubernetespodlogs

import (
	"flag"
	"os"
	"path/filepath"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func buildConfig() (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}
	home, _ := os.UserHomeDir()
	kubeconfig := flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "kubeconfig path")
	flag.Parse()
	return clientcmd.BuildConfigFromFlags("", *kubeconfig)
}
