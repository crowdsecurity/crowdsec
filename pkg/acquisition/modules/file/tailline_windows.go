//go:build windows

package fileacquisition

import "strings"

func trimLine(text string) string {
	return strings.TrimRight(text, "\r")
}
