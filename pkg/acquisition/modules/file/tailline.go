//go:build !windows

package fileacquisition

func trimLine(text string) string {
	return text
}
