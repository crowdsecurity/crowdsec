package main

import (
	"fmt"
	"runtime"
	"testing"
)

func TestMessages(t *testing.T) {

	var inputWant string

	if runtime.GOOS == "freebsd" {
		inputWant = fmt.Sprintf(ReloadMessageFormat, ReloadCmdFreebsd)
	} else {
		inputWant = fmt.Sprintf(ReloadMessageFormat, ReloadCmdLinux)
	}

	inputGot := ReloadMessage()

	if inputWant != inputGot {
		t.Errorf("Want %s, Got %s", inputWant, inputGot)
	}
}
