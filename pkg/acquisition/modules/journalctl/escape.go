package journalctlacquisition

import (
	"strings"
)

// shellEscape escapes a single argument (including command name) if needed.
func shellEscape(s string) string {
	if !strings.ContainsAny(s, " \t\n\"'\\`$&|;<>(){}[]*?!~") {
		return s
	}

	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// formatShellCommand returns a single shell-escaped command string suitable for logging
// or copy-pasting into a POSIX shell. It is meant to help reproduce the datasource behavior
// during debugging.
func formatShellCommand(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = shellEscape(a)
	}

	return strings.Join(parts, " ")
}
