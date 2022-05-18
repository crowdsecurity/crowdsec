package cstest

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Copy(sourceFile string, destinationFile string) error {
	input, err := ioutil.ReadFile(sourceFile)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(destinationFile, input, 0644)
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

	files, err := ioutil.ReadDir(src)
	if err != nil {
		return err
	}

	for _, f := range files {

		if f.IsDir() {

			err = CopyDir(src+"/"+f.Name(), dest+"/"+f.Name())
			if err != nil {
				return err
			}

		}

		if !f.IsDir() {

			content, err := ioutil.ReadFile(src + "/" + f.Name())
			if err != nil {
				return err

			}

			err = ioutil.WriteFile(dest+"/"+f.Name(), content, 0755)
			if err != nil {
				return err

			}

		}

	}

	return nil
}

func AssertErrorContains(t *testing.T, err error, expectedErr string) {
	if expectedErr != "" {
		assert.ErrorContains(t, err, expectedErr)
		return
	}

	assert.NoError(t, err)
}
