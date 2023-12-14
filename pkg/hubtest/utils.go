package hubtest

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"
)

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

func Copy(src string, dst string) error {
	content, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	err = os.WriteFile(dst, content, 0o644)
	if err != nil {
		return err
	}

	return nil
}

// checkPathNotContained returns an error if 'subpath' is inside 'path'
func checkPathNotContained(path string, subpath string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	absSubPath, err := filepath.Abs(subpath)
	if err != nil {
		return err
	}

	current := absSubPath

	for {
		if current == absPath {
			return fmt.Errorf("cannot copy a folder onto itself")
		}

		up := filepath.Dir(current)
		if current == up {
			break
		}

		current = up
	}

	return nil
}

func CopyDir(src string, dest string) error {
	err := checkPathNotContained(src, dest)
	if err != nil {
		return err
	}

	f, err := os.Open(src)
	if err != nil {
		return err
	}

	file, err := f.Stat()
	if err != nil {
		return err
	}

	if !file.IsDir() {
		return fmt.Errorf("Source " + file.Name() + " is not a directory!")
	}

	err = os.MkdirAll(dest, 0755)
	if err != nil {
		return err
	}

	files, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, f := range files {
		if f.IsDir() {
			if err = CopyDir(filepath.Join(src, f.Name()), filepath.Join(dest, f.Name())); err != nil {
				return err
			}
		} else {
			if err = Copy(filepath.Join(src, f.Name()), filepath.Join(dest, f.Name())); err != nil {
				return err
			}
		}
	}

	return nil
}

func IsAlive(target string) (bool, error) {
	start := time.Now()
	for {
		conn, err := net.Dial("tcp", target)
		if err == nil {
			log.Debugf("'%s' is up after %s", target, time.Since(start))
			conn.Close()
			return true, nil
		}
		time.Sleep(500 * time.Millisecond)
		if time.Since(start) > 10*time.Second {
			return false, fmt.Errorf("took more than 10s for %s to be available", target)
		}
	}
}
