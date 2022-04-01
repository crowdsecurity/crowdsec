//go:build testrunmain

package main

import (
	"github.com/confluentinc/bincover"

	"testing"
)

func TestBincoverRunMain(t *testing.T) {
	bincover.RunTest(main)
}
