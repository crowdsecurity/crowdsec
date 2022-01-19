package apiserver

import "os"

func cleanFile(path string) {
	os.Remove(path)
}
