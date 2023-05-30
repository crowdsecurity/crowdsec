package emoji

import (
	"fmt"
	"io"
)

// Sprint wraps fmt.Sprint with emoji support
func Sprint(a ...interface{}) string {
	return Parse(fmt.Sprint(a...))
}

// Sprintf wraps fmt.Sprintf with emoji support
func Sprintf(format string, a ...interface{}) string {
	return Parse(fmt.Sprintf(format, a...))
}

// Sprintln wraps fmt.Sprintln with emoji support
func Sprintln(a ...interface{}) string {
	return Parse(fmt.Sprintln(a...))
}

// Print wraps fmt.Print with emoji support
func Print(a ...interface{}) (n int, err error) {
	return fmt.Print(Sprint(a...))
}

// Println wraps fmt.Println with emoji support
func Println(a ...interface{}) (n int, err error) {
	return fmt.Println(Sprint(a...))
}

// Printf wraps fmt.Printf with emoji support
func Printf(format string, a ...interface{}) (n int, err error) {
	return fmt.Print(Sprintf(format, a...))
}

// Fprint wraps fmt.Fprint with emoji support
func Fprint(w io.Writer, a ...interface{}) (n int, err error) {
	return fmt.Fprint(w, Sprint(a...))
}

// Fprintf wraps fmt.Fprintf with emoji support
func Fprintf(w io.Writer, format string, a ...interface{}) (n int, err error) {
	return fmt.Fprint(w, Sprintf(format, a...))
}

// Fprintln wraps fmt.Fprintln with emoji support
func Fprintln(w io.Writer, a ...interface{}) (n int, err error) {
	return fmt.Fprintln(w, Sprint(a...))
}

// Errorf wraps fmt.Errorf with emoji support
func Errorf(format string, a ...interface{}) error {
	return fmt.Errorf(Sprintf(format, a...))
}
