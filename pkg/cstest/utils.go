package cstest

import (
	"fmt"
	"io/ioutil"
	"os"
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

func CopyDir(src string, dest string) error {

	if dest[:len(src)] == src {
		return fmt.Errorf("Cannot copy a folder into the folder itself!")
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
	if expectedErr == "" {
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		assert.Equal(t, err, nil)
		return
	}
	if err == nil {
		t.Fatalf("Expected '%s', got nil", expectedErr)
	}
	assert.Contains(t, err.Error(), expectedErr)
}
