package csplugin

import "os/exec"

//All functions are empty, just to make the code compile when targeting js/wasm

func (pb *PluginBroker) CreateCmd(binaryPath string) (*exec.Cmd, error) {
	return nil, nil
}

func getPluginTypeAndSubtypeFromPath(path string) (string, string, error) {
	return "", "", nil
}

func pluginIsValid(path string) error {
	return nil
}
