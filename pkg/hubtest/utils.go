package hubtest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

func IsAlive(ctx context.Context, target string) (bool, error) {
	start := time.Now()
	for {
		dialer := &net.Dialer{}
		conn, err := dialer.DialContext(ctx, "tcp", target)
		if err == nil {
			log.Debugf("%q is up after %s", target, time.Since(start))
			conn.Close()
			return true, nil
		}
		time.Sleep(500 * time.Millisecond)
		if time.Since(start) > 10*time.Second {
			return false, fmt.Errorf(`timeout connecting to %s -- did you run "sudo docker compose -f docker/appsec/docker-compose.yaml up -d --build" ?`, target)
		}
	}
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
			return errors.New("cannot copy a folder onto itself")
		}

		up := filepath.Dir(current)
		if current == up {
			break
		}

		current = up
	}

	return nil
}

// CopyDir copies the content of a directory to another directory.
// It delegates the operation to os.CopyFS with an additional check to prevent infinite loops.
func CopyDir(src string, dest string) error {
	if err := checkPathNotContained(src, dest); err != nil {
		return err
	}

	return os.CopyFS(dest, os.DirFS(src))
}
