// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package migrate

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"
)

type (
	// Dir wraps the functionality used to interact with a migration directory.
	Dir interface {
		fs.FS
		// WriteFile writes the data to the named file.
		WriteFile(string, []byte) error

		// Files returns a set of files stored in this Dir to be executed on a database.
		Files() ([]File, error)

		// Checksum returns a HashFile of the migration directory.
		Checksum() (HashFile, error)
	}

	// Formatter wraps the Format method.
	Formatter interface {
		// Format formats the given Plan into one or more migration files.
		Format(*Plan) ([]File, error)
	}

	// File represents a single migration file.
	File interface {
		// Name returns the name of the migration file.
		Name() string
		// Desc returns the description of the migration File.
		Desc() string
		// Version returns the version of the migration File.
		Version() string
		// Bytes returns the read content of the file.
		Bytes() []byte
		// Stmts returns the set of SQL statements this file holds.
		Stmts() ([]string, error)
		// StmtDecls returns the set of SQL statements this file holds alongside its preceding comments.
		StmtDecls() ([]*Stmt, error)
	}
)

// LocalDir implements Dir for a local migration
// directory with default Atlas formatting.
type LocalDir struct {
	path string
}

var _ Dir = (*LocalDir)(nil)

// NewLocalDir returns a new the Dir used by a Planner to work on the given local path.
func NewLocalDir(path string) (*LocalDir, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("sql/migrate: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("sql/migrate: %q is not a dir", path)
	}
	return &LocalDir{path: path}, nil
}

// Path returns the local path used for opening this dir.
func (d *LocalDir) Path() string {
	return d.path
}

// Open implements fs.FS.
func (d *LocalDir) Open(name string) (fs.File, error) {
	return os.Open(filepath.Join(d.path, name))
}

// WriteFile implements Dir.WriteFile.
func (d *LocalDir) WriteFile(name string, b []byte) error {
	return os.WriteFile(filepath.Join(d.path, name), b, 0644)
}

// Files implements Dir.Files. It looks for all files with .sql suffix and orders them by filename.
func (d *LocalDir) Files() ([]File, error) {
	names, err := fs.Glob(d, "*.sql")
	if err != nil {
		return nil, err
	}
	// Sort files lexicographically.
	sort.Slice(names, func(i, j int) bool {
		return names[i] < names[j]
	})
	ret := make([]File, len(names))
	for i, n := range names {
		b, err := fs.ReadFile(d, n)
		if err != nil {
			return nil, fmt.Errorf("sql/migrate: read file %q: %w", n, err)
		}
		ret[i] = NewLocalFile(n, b)
	}
	return ret, nil
}

// Checksum implements Dir.Checksum. By default, it calls Files() and creates a checksum from them.
func (d *LocalDir) Checksum() (HashFile, error) {
	var (
		hs HashFile
		h  = sha256.New()
	)
	files, err := d.Files()
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if _, err = h.Write([]byte(f.Name())); err != nil {
			return nil, err
		}
		// Check if this file contains an "atlas:sum" directive and if so, act to it.
		if mode, ok := directive(string(f.Bytes()), directiveSum); ok && mode == sumModeIgnore {
			continue
		}
		if _, err = h.Write(f.Bytes()); err != nil {
			return nil, err
		}
		hs = append(hs, struct{ N, H string }{f.Name(), base64.StdEncoding.EncodeToString(h.Sum(nil))})
	}
	return hs, nil
}

// LocalFile is used by LocalDir to implement the Scanner interface.
type LocalFile struct {
	n string
	b []byte
}

var _ File = (*LocalFile)(nil)

// NewLocalFile returns a new local file.
func NewLocalFile(name string, data []byte) *LocalFile {
	return &LocalFile{n: name, b: data}
}

// Name implements File.Name.
func (f LocalFile) Name() string {
	return f.n
}

// Desc implements File.Desc.
func (f LocalFile) Desc() string {
	parts := strings.SplitN(f.n, "_", 2)
	if len(parts) == 1 {
		return ""
	}
	return strings.TrimSuffix(parts[1], ".sql")
}

// Version implements File.Version.
func (f LocalFile) Version() string {
	return strings.SplitN(strings.TrimSuffix(f.n, ".sql"), "_", 2)[0]
}

// Stmts returns the SQL statement exists in the local file.
func (f LocalFile) Stmts() ([]string, error) {
	s, err := Stmts(string(f.b))
	if err != nil {
		return nil, err
	}
	stmts := make([]string, len(s))
	for i := range s {
		stmts[i] = s[i].Text
	}
	return stmts, nil
}

// StmtDecls returns the all statement declarations exist in the local file.
func (f LocalFile) StmtDecls() ([]*Stmt, error) {
	return Stmts(string(f.b))
}

// Bytes returns local file data.
func (f LocalFile) Bytes() []byte {
	return f.b
}

var (
	// templateFuncs contains the template.FuncMap for the DefaultFormatter.
	templateFuncs = template.FuncMap{"now": func() string { return time.Now().UTC().Format("20060102150405") }}
	// DefaultFormatter is a default implementation for Formatter.
	DefaultFormatter = &TemplateFormatter{
		templates: []struct{ N, C *template.Template }{
			{
				N: template.Must(template.New("").Funcs(templateFuncs).Parse(
					"{{ with .Version }}{{ . }}{{ else }}{{ now }}{{ end }}{{ with .Name }}_{{ . }}{{ end }}.sql",
				)),
				C: template.Must(template.New("").Parse(
					`{{ range .Changes }}{{ with .Comment }}-- {{ println . }}{{ end }}{{ printf "%s;\n" .Cmd }}{{ end }}`,
				)),
			},
		},
	}
)

// TemplateFormatter implements Formatter by using templates.
type TemplateFormatter struct {
	templates []struct{ N, C *template.Template }
}

// NewTemplateFormatter creates a new Formatter working with the given templates.
//
//	migrate.NewTemplateFormatter(
//		template.Must(template.New("").Parse("{{now.Unix}}{{.Name}}.sql")),                 // name template
//		template.Must(template.New("").Parse("{{range .Changes}}{{println .Cmd}}{{end}}")), // content template
//	)
func NewTemplateFormatter(templates ...*template.Template) (*TemplateFormatter, error) {
	if n := len(templates); n == 0 || n%2 == 1 {
		return nil, fmt.Errorf("zero or odd number of templates given")
	}
	t := new(TemplateFormatter)
	for i := 0; i < len(templates); i += 2 {
		t.templates = append(t.templates, struct{ N, C *template.Template }{templates[i], templates[i+1]})
	}
	return t, nil
}

// Format implements the Formatter interface.
func (t *TemplateFormatter) Format(plan *Plan) ([]File, error) {
	files := make([]File, 0, len(t.templates))
	for _, tpl := range t.templates {
		var n, b bytes.Buffer
		if err := tpl.N.Execute(&n, plan); err != nil {
			return nil, err
		}
		if err := tpl.C.Execute(&b, plan); err != nil {
			return nil, err
		}
		files = append(files, &LocalFile{
			n: n.String(),
			b: b.Bytes(),
		})
	}
	return files, nil
}

// HashFileName of the migration directory integrity sum file.
const HashFileName = "atlas.sum"

// HashFile represents the integrity sum file of the migration dir.
type HashFile []struct{ N, H string }

// HashSum reads the whole dir, sorts the files by name and creates a HashSum from its contents.
//
// Deprecated: Use Dir.Checksum instead.
func HashSum(dir Dir) (HashFile, error) {
	return dir.Checksum()
}

// WriteSumFile writes the given HashFile to the Dir. If the file does not exist, it is created.
func WriteSumFile(dir Dir, sum HashFile) error {
	b, err := sum.MarshalText()
	if err != nil {
		return err
	}
	return dir.WriteFile(HashFileName, b)
}

// Sum returns the checksum of the represented hash file.
func (f HashFile) Sum() string {
	sha := sha256.New()
	for _, f := range f {
		sha.Write([]byte(f.N))
		sha.Write([]byte(f.H))
	}
	return base64.StdEncoding.EncodeToString(sha.Sum(nil))
}

// MarshalText implements encoding.TextMarshaler.
func (f HashFile) MarshalText() ([]byte, error) {
	buf := new(bytes.Buffer)
	for _, f := range f {
		fmt.Fprintf(buf, "%s h1:%s\n", f.N, f.H)
	}
	return []byte(fmt.Sprintf("h1:%s\n%s", f.Sum(), buf)), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (f *HashFile) UnmarshalText(b []byte) error {
	sc := bufio.NewScanner(bytes.NewReader(b))
	// The first line contains the sum.
	sc.Scan()
	sum := strings.TrimPrefix(sc.Text(), "h1:")
	for sc.Scan() {
		li := strings.SplitN(sc.Text(), "h1:", 2)
		if len(li) != 2 {
			return ErrChecksumFormat
		}
		*f = append(*f, struct{ N, H string }{strings.TrimSpace(li[0]), li[1]})
	}
	if sum != f.Sum() {
		return ErrChecksumMismatch
	}
	return sc.Err()
}

// SumByName returns the hash for a migration file by its name.
func (f HashFile) SumByName(n string) (string, error) {
	for _, f := range f {
		if f.N == n {
			return f.H, nil
		}
	}
	return "", errors.New("checksum not found")
}

var (
	// ErrChecksumFormat is returned from Validate if the sum files format is invalid.
	ErrChecksumFormat = errors.New("checksum file format invalid")
	// ErrChecksumMismatch is returned from Validate if the hash sums don't match.
	ErrChecksumMismatch = errors.New("checksum mismatch")
	// ErrChecksumNotFound is returned from Validate if the hash file does not exist.
	ErrChecksumNotFound = errors.New("checksum file not found")
)

// Validate checks if the migration dir is in sync with its sum file.
// If they don't match ErrChecksumMismatch is returned.
func Validate(dir Dir) error {
	fh, err := readHashFile(dir)
	if errors.Is(err, fs.ErrNotExist) {
		// If there are no migration files yet this is okay.
		files, err := fs.ReadDir(dir, "/")
		if err != nil || len(files) > 0 {
			return ErrChecksumNotFound
		}
		return nil
	}
	if err != nil {
		return err
	}
	mh, err := dir.Checksum()
	if err != nil {
		return err
	}
	if fh.Sum() != mh.Sum() {
		return ErrChecksumMismatch
	}
	return nil
}

// FilesLastIndex returns the index of the last file
// satisfying f(i), or -1 if none do.
func FilesLastIndex(files []File, f func(File) bool) int {
	for i := len(files) - 1; i >= 0; i-- {
		if f(files[i]) {
			return i
		}
	}
	return -1
}

const (
	// atlas:sum directive.
	directiveSum  = "sum"
	sumModeIgnore = "ignore"
	// atlas:delimiter directive.
	directiveDelimiter = "delimiter"
	directivePrefixSQL = "-- "
)

var reDirective = regexp.MustCompile(`^([ -~]*)atlas:(\w+)(?: +([ -~]*))*`)

// directive searches in the content a line that matches a directive
// with the given prefix and name. For example:
//
//	directive(c, "delimiter", "-- ")	// '-- atlas:delimiter.*'
//	directive(c, "sum", "")				// 'atlas:sum.*'
//	directive(c, "sum")					// '.*atlas:sum'
func directive(content, name string, prefix ...string) (string, bool) {
	m := reDirective.FindStringSubmatch(content)
	// In case the prefix was provided ensures it is matched.
	if len(m) == 4 && m[2] == name && (len(prefix) == 0 || prefix[0] == m[1]) {
		return m[3], true
	}
	return "", false
}

// readHashFile reads the HashFile from the given Dir.
func readHashFile(dir Dir) (HashFile, error) {
	f, err := dir.Open(HashFileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var fh HashFile
	if err := fh.UnmarshalText(b); err != nil {
		return nil, err
	}
	return fh, nil
}
