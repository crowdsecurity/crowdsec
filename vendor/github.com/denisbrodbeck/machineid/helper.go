package machineid

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// run wraps `exec.Command` with easy access to stdout and stderr.
func run(stdout, stderr io.Writer, cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	c.Stdin = os.Stdin
	c.Stdout = stdout
	c.Stderr = stderr
	return c.Run()
}

// protect calculates HMAC-SHA256 of the application ID, keyed by the machine ID and returns a hex-encoded string.
func protect(appID, id string) string {
	mac := hmac.New(sha256.New, []byte(id))
	mac.Write([]byte(appID))
	return hex.EncodeToString(mac.Sum(nil))
}

func readFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

func trim(s string) string {
	return strings.TrimSpace(strings.Trim(s, "\n"))
}
