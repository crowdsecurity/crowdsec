package mage

import (
	"bytes"
	"crypto/sha1"
	"errors"
	"flag"
	"fmt"
	"go/build"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/magefile/mage/internal"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/parse"
	"github.com/magefile/mage/sh"
)

// magicRebuildKey is used when hashing the output binary to ensure that we get
// a new binary even if nothing in the input files or generated mainfile has
// changed. This can be used when we change how we parse files, or otherwise
// change the inputs to the compiling process.
const magicRebuildKey = "v0.3"

// (Aaaa)(Bbbb) -> aaaaBbbb
var firstWordRx = regexp.MustCompile(`^([[:upper:]][^[:upper:]]+)([[:upper:]].*)$`)

// (AAAA)(Bbbb) -> aaaaBbbb
var firstAbbrevRx = regexp.MustCompile(`^([[:upper:]]+)([[:upper:]][^[:upper:]].*)$`)

func lowerFirstWord(s string) string {
	if match := firstWordRx.FindStringSubmatch(s); match != nil {
		return strings.ToLower(match[1]) + match[2]
	}
	if match := firstAbbrevRx.FindStringSubmatch(s); match != nil {
		return strings.ToLower(match[1]) + match[2]
	}
	return strings.ToLower(s)
}

var mainfileTemplate = template.Must(template.New("").Funcs(map[string]interface{}{
	"lower": strings.ToLower,
	"lowerFirst": func(s string) string {
		parts := strings.Split(s, ":")
		for i, t := range parts {
			parts[i] = lowerFirstWord(t)
		}
		return strings.Join(parts, ":")
	},
}).Parse(mageMainfileTplString))
var initOutput = template.Must(template.New("").Parse(mageTpl))

const (
	mainfile = "mage_output_file.go"
	initFile = "magefile.go"
)

var debug = log.New(ioutil.Discard, "DEBUG: ", log.Ltime|log.Lmicroseconds)

// set by ldflags when you "mage build"
var (
	commitHash = "<not set>"
	timestamp  = "<not set>"
	gitTag     = "<not set>"
)

//go:generate stringer -type=Command

// Command tracks invocations of mage that run without targets or other flags.
type Command int

// The various command types
const (
	None          Command = iota
	Version               // report the current version of mage
	Init                  // create a starting template for mage
	Clean                 // clean out old compiled mage binaries from the cache
	CompileStatic         // compile a static binary of the current directory
)

// Main is the entrypoint for running mage.  It exists external to mage's main
// function to allow it to be used from other programs, specifically so you can
// go run a simple file that run's mage's Main.
func Main() int {
	return ParseAndRun(os.Stdout, os.Stderr, os.Stdin, os.Args[1:])
}

// Invocation contains the args for invoking a run of Mage.
type Invocation struct {
	Debug      bool          // turn on debug messages
	Dir        string        // directory to read magefiles from
	WorkDir    string        // directory where magefiles will run
	Force      bool          // forces recreation of the compiled binary
	Verbose    bool          // tells the magefile to print out log statements
	List       bool          // tells the magefile to print out a list of targets
	Help       bool          // tells the magefile to print out help for a specific target
	Keep       bool          // tells mage to keep the generated main file after compiling
	Timeout    time.Duration // tells mage to set a timeout to running the targets
	CompileOut string        // tells mage to compile a static binary to this path, but not execute
	GOOS       string        // sets the GOOS when producing a binary with -compileout
	GOARCH     string        // sets the GOARCH when producing a binary with -compileout
	Ldflags    string        // sets the ldflags when producing a binary with -compileout
	Stdout     io.Writer     // writer to write stdout messages to
	Stderr     io.Writer     // writer to write stderr messages to
	Stdin      io.Reader     // reader to read stdin from
	Args       []string      // args to pass to the compiled binary
	GoCmd      string        // the go binary command to run
	CacheDir   string        // the directory where we should store compiled binaries
	HashFast   bool          // don't rely on GOCACHE, just hash the magefiles
}

// MagefilesDirName is the name of the default folder to look for if no directory was specified,
// if this folder exists it will be assumed mage package lives inside it.
const MagefilesDirName = "magefiles"

// UsesMagefiles returns true if we are getting our mage files from a magefiles directory.
func (i Invocation) UsesMagefiles() bool {
	return i.Dir == MagefilesDirName
}

// ParseAndRun parses the command line, and then compiles and runs the mage
// files in the given directory with the given args (do not include the command
// name in the args).
func ParseAndRun(stdout, stderr io.Writer, stdin io.Reader, args []string) int {
	errlog := log.New(stderr, "", 0)
	out := log.New(stdout, "", 0)
	inv, cmd, err := Parse(stderr, stdout, args)
	inv.Stderr = stderr
	inv.Stdin = stdin
	if err == flag.ErrHelp {
		return 0
	}
	if err != nil {
		errlog.Println("Error:", err)
		return 2
	}

	switch cmd {
	case Version:
		out.Println("Mage Build Tool", gitTag)
		out.Println("Build Date:", timestamp)
		out.Println("Commit:", commitHash)
		out.Println("built with:", runtime.Version())
		return 0
	case Init:
		if err := generateInit(inv.Dir); err != nil {
			errlog.Println("Error:", err)
			return 1
		}
		out.Println(initFile, "created")
		return 0
	case Clean:
		if err := removeContents(inv.CacheDir); err != nil {
			out.Println("Error:", err)
			return 1
		}
		out.Println(inv.CacheDir, "cleaned")
		return 0
	case CompileStatic:
		return Invoke(inv)
	case None:
		return Invoke(inv)
	default:
		panic(fmt.Errorf("Unknown command type: %v", cmd))
	}
}

// Parse parses the given args and returns structured data.  If parse returns
// flag.ErrHelp, the calling process should exit with code 0.
func Parse(stderr, stdout io.Writer, args []string) (inv Invocation, cmd Command, err error) {
	inv.Stdout = stdout
	fs := flag.FlagSet{}
	fs.SetOutput(stdout)

	// options flags

	fs.BoolVar(&inv.Force, "f", false, "force recreation of compiled magefile")
	fs.BoolVar(&inv.Debug, "debug", mg.Debug(), "turn on debug messages")
	fs.BoolVar(&inv.Verbose, "v", mg.Verbose(), "show verbose output when running mage targets")
	fs.BoolVar(&inv.Help, "h", false, "show this help")
	fs.DurationVar(&inv.Timeout, "t", 0, "timeout in duration parsable format (e.g. 5m30s)")
	fs.BoolVar(&inv.Keep, "keep", false, "keep intermediate mage files around after running")
	fs.StringVar(&inv.Dir, "d", "", "directory to read magefiles from")
	fs.StringVar(&inv.WorkDir, "w", "", "working directory where magefiles will run")
	fs.StringVar(&inv.GoCmd, "gocmd", mg.GoCmd(), "use the given go binary to compile the output")
	fs.StringVar(&inv.GOOS, "goos", "", "set GOOS for binary produced with -compile")
	fs.StringVar(&inv.GOARCH, "goarch", "", "set GOARCH for binary produced with -compile")
	fs.StringVar(&inv.Ldflags, "ldflags", "", "set ldflags for binary produced with -compile")

	// commands below

	fs.BoolVar(&inv.List, "l", false, "list mage targets in this directory")
	var showVersion bool
	fs.BoolVar(&showVersion, "version", false, "show version info for the mage binary")
	var mageInit bool
	fs.BoolVar(&mageInit, "init", false, "create a starting template if no mage files exist")
	var clean bool
	fs.BoolVar(&clean, "clean", false, "clean out old generated binaries from CACHE_DIR")
	var compileOutPath string
	fs.StringVar(&compileOutPath, "compile", "", "output a static binary to the given path")

	fs.Usage = func() {
		fmt.Fprint(stdout, `
mage [options] [target]

Mage is a make-like command runner.  See https://magefile.org for full docs.

Commands:
  -clean    clean out old generated binaries from CACHE_DIR
  -compile <string>
            output a static binary to the given path
  -h        show this help
  -init     create a starting template if no mage files exist
  -l        list mage targets in this directory
  -version  show version info for the mage binary

Options:
  -d <string> 
            directory to read magefiles from (default "." or "magefiles" if exists)
  -debug    turn on debug messages
  -f        force recreation of compiled magefile
  -goarch   sets the GOARCH for the binary created by -compile (default: current arch)
  -gocmd <string>
		    use the given go binary to compile the output (default: "go")
  -goos     sets the GOOS for the binary created by -compile (default: current OS)
  -ldflags  sets the ldflags for the binary created by -compile (default: "")
  -h        show description of a target
  -keep     keep intermediate mage files around after running
  -t <string>
            timeout in duration parsable format (e.g. 5m30s)
  -v        show verbose output when running mage targets
  -w <string>
            working directory where magefiles will run (default -d value)
`[1:])
	}
	err = fs.Parse(args)
	if err == flag.ErrHelp {
		// parse will have already called fs.Usage()
		return inv, cmd, err
	}
	if err == nil && inv.Help && len(fs.Args()) == 0 {
		fs.Usage()
		// tell upstream, to just exit
		return inv, cmd, flag.ErrHelp
	}

	numCommands := 0
	switch {
	case mageInit:
		numCommands++
		cmd = Init
	case compileOutPath != "":
		numCommands++
		cmd = CompileStatic
		inv.CompileOut = compileOutPath
		inv.Force = true
	case showVersion:
		numCommands++
		cmd = Version
	case clean:
		numCommands++
		cmd = Clean
		if fs.NArg() > 0 {
			// Temporary dupe of below check until we refactor the other commands to use this check
			return inv, cmd, errors.New("-h, -init, -clean, -compile and -version cannot be used simultaneously")
		}
	}
	if inv.Help {
		numCommands++
	}

	if inv.Debug {
		debug.SetOutput(stderr)
	}

	inv.CacheDir = mg.CacheDir()

	if numCommands > 1 {
		debug.Printf("%d commands defined", numCommands)
		return inv, cmd, errors.New("-h, -init, -clean, -compile and -version cannot be used simultaneously")
	}

	if cmd != CompileStatic && (inv.GOARCH != "" || inv.GOOS != "") {
		return inv, cmd, errors.New("-goos and -goarch only apply when running with -compile")
	}

	inv.Args = fs.Args()
	if inv.Help && len(inv.Args) > 1 {
		return inv, cmd, errors.New("-h can only show help for a single target")
	}

	if len(inv.Args) > 0 && cmd != None {
		return inv, cmd, fmt.Errorf("unexpected arguments to command: %q", inv.Args)
	}
	inv.HashFast = mg.HashFast()
	return inv, cmd, err
}

const dotDirectory = "."

// Invoke runs Mage with the given arguments.
func Invoke(inv Invocation) int {
	errlog := log.New(inv.Stderr, "", 0)
	if inv.GoCmd == "" {
		inv.GoCmd = "go"
	}
	var noDir bool
	if inv.Dir == "" {
		noDir = true
		inv.Dir = dotDirectory
		// . will be default unless we find a mage folder.
		mfSt, err := os.Stat(MagefilesDirName)
		if err == nil {
			if mfSt.IsDir() {
				stderrBuf := &bytes.Buffer{}
				inv.Dir = MagefilesDirName // preemptive assignment
				// TODO: Remove this fallback and the above Magefiles invocation when the bw compatibility is removed.
				files, err := Magefiles(dotDirectory, inv.GOOS, inv.GOARCH, inv.GoCmd, stderrBuf, false, inv.Debug)
				if err == nil {
					if len(files) != 0 {
						errlog.Println("[WARNING] You have both a magefiles directory and mage files in the " +
							"current directory, in future versions the files will be ignored in favor of the directory")
						inv.Dir = dotDirectory
					}
				}
			}
		}
	}

	if inv.WorkDir == "" {
		if noDir {
			inv.WorkDir = dotDirectory
		} else {
			inv.WorkDir = inv.Dir
		}
	}

	if inv.CacheDir == "" {
		inv.CacheDir = mg.CacheDir()
	}

	files, err := Magefiles(inv.Dir, inv.GOOS, inv.GOARCH, inv.GoCmd, inv.Stderr, inv.UsesMagefiles(), inv.Debug)
	if err != nil {
		errlog.Println("Error determining list of magefiles:", err)
		return 1
	}

	if len(files) == 0 {
		errlog.Println("No .go files marked with the mage build tag in this directory.")
		return 1
	}
	debug.Printf("found magefiles: %s", strings.Join(files, ", "))
	exePath := inv.CompileOut
	if inv.CompileOut == "" {
		exePath, err = ExeName(inv.GoCmd, inv.CacheDir, files)
		if err != nil {
			errlog.Println("Error getting exe name:", err)
			return 1
		}
	}
	debug.Println("output exe is ", exePath)

	useCache := false
	if inv.HashFast {
		debug.Println("user has set MAGEFILE_HASHFAST, so we'll ignore GOCACHE")
	} else {
		s, err := internal.OutputDebug(inv.GoCmd, "env", "GOCACHE")
		if err != nil {
			errlog.Printf("failed to run %s env GOCACHE: %s", inv.GoCmd, err)
			return 1
		}

		// if GOCACHE exists, always rebuild, so we catch transitive
		// dependencies that have changed.
		if s != "" {
			debug.Println("go build cache exists, will ignore any compiled binary")
			useCache = true
		}
	}

	if !useCache {
		_, err = os.Stat(exePath)
		switch {
		case err == nil:
			if inv.Force {
				debug.Println("ignoring existing executable")
			} else {
				debug.Println("Running existing exe")
				return RunCompiled(inv, exePath, errlog)
			}
		case os.IsNotExist(err):
			debug.Println("no existing exe, creating new")
		default:
			debug.Printf("error reading existing exe at %v: %v", exePath, err)
			debug.Println("creating new exe")
		}
	}

	// parse wants dir + filenames... arg
	fnames := make([]string, 0, len(files))
	for i := range files {
		fnames = append(fnames, filepath.Base(files[i]))
	}
	if inv.Debug {
		parse.EnableDebug()
	}
	debug.Println("parsing files")
	info, err := parse.PrimaryPackage(inv.GoCmd, inv.Dir, fnames)
	if err != nil {
		errlog.Println("Error parsing magefiles:", err)
		return 1
	}

	// reproducible output for deterministic builds
	sort.Sort(info.Funcs)
	sort.Sort(info.Imports)

	main := filepath.Join(inv.Dir, mainfile)
	binaryName := "mage"
	if inv.CompileOut != "" {
		binaryName = filepath.Base(inv.CompileOut)
	}

	err = GenerateMainfile(binaryName, main, info)
	if err != nil {
		errlog.Println("Error:", err)
		return 1
	}
	if !inv.Keep {
		defer os.RemoveAll(main)
	}
	files = append(files, main)
	if err := Compile(inv.GOOS, inv.GOARCH, inv.Ldflags, inv.Dir, inv.GoCmd, exePath, files, inv.Debug, inv.Stderr, inv.Stdout); err != nil {
		errlog.Println("Error:", err)
		return 1
	}
	if !inv.Keep {
		// move aside this file before we run the compiled version, in case the
		// compiled file screws things up.  Yes this doubles up with the above
		// defer, that's ok.
		os.RemoveAll(main)
	} else {
		debug.Print("keeping mainfile")
	}

	if inv.CompileOut != "" {
		return 0
	}

	return RunCompiled(inv, exePath, errlog)
}

type mainfileTemplateData struct {
	Description string
	Funcs       []*parse.Function
	DefaultFunc parse.Function
	Aliases     map[string]*parse.Function
	Imports     []*parse.Import
	BinaryName  string
}

// listGoFiles returns a list of all .go files in a given directory,
// matching the provided tag
func listGoFiles(magePath, goCmd, tag string, envStr []string) ([]string, error) {
	origMagePath := magePath
	if !filepath.IsAbs(magePath) {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("can't get current working directory: %v", err)
		}
		magePath = filepath.Join(cwd, magePath)
	}

	env, err := internal.SplitEnv(envStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing environment variables: %v", err)
	}

	bctx := build.Default
	bctx.BuildTags = []string{tag}

	if _, ok := env["GOOS"]; ok {
		bctx.GOOS = env["GOOS"]
	}

	if _, ok := env["GOARCH"]; ok {
		bctx.GOARCH = env["GOARCH"]
	}

	pkg, err := bctx.Import(".", magePath, 0)
	if err != nil {
		if _, ok := err.(*build.NoGoError); ok {
			return []string{}, nil
		}

		// Allow multiple packages in the same directory
		if _, ok := err.(*build.MultiplePackageError); !ok {
			return nil, fmt.Errorf("failed to parse go source files: %v", err)
		}
	}

	goFiles := make([]string, len(pkg.GoFiles))
	for i := range pkg.GoFiles {
		goFiles[i] = filepath.Join(origMagePath, pkg.GoFiles[i])
	}

	debug.Printf("found %d go files with build tag %s (files: %v)", len(goFiles), tag, goFiles)
	return goFiles, nil
}

// Magefiles returns the list of magefiles in dir.
func Magefiles(magePath, goos, goarch, goCmd string, stderr io.Writer, isMagefilesDirectory, isDebug bool) ([]string, error) {
	start := time.Now()
	defer func() {
		debug.Println("time to scan for Magefiles:", time.Since(start))
	}()

	env, err := internal.EnvWithGOOS(goos, goarch)
	if err != nil {
		return nil, err
	}

	debug.Println("getting all files including those with mage tag in", magePath)
	mageFiles, err := listGoFiles(magePath, goCmd, "mage", env)
	if err != nil {
		return nil, fmt.Errorf("listing mage files: %v", err)
	}

	if isMagefilesDirectory {
		// For the magefiles directory, we always use all go files, both with
		// and without the mage tag, as per normal go build tag rules.
		debug.Println("using all go files in magefiles directory", magePath)
		return mageFiles, nil
	}

	// For folders other than the magefiles directory, we only consider files
	// that have the mage build tag and ignore those that don't.

	debug.Println("getting all files without mage tag in", magePath)
	nonMageFiles, err := listGoFiles(magePath, goCmd, "", env)
	if err != nil {
		return nil, fmt.Errorf("listing non-mage files: %v", err)
	}

	// convert non-Mage list to a map of files to exclude.
	exclude := map[string]bool{}
	for _, f := range nonMageFiles {
		if f != "" {
			debug.Printf("marked file as non-mage: %q", f)
			exclude[f] = true
		}
	}

	// filter out the non-mage files from the mage files.
	var files []string
	for _, f := range mageFiles {
		if f != "" && !exclude[f] {
			files = append(files, f)
		}
	}

	return files, nil
}

// Compile uses the go tool to compile the files into an executable at path.
func Compile(goos, goarch, ldflags, magePath, goCmd, compileTo string, gofiles []string, isDebug bool, stderr, stdout io.Writer) error {
	debug.Println("compiling to", compileTo)
	debug.Println("compiling using gocmd:", goCmd)
	if isDebug {
		internal.RunDebug(goCmd, "version")
		internal.RunDebug(goCmd, "env")
	}
	environ, err := internal.EnvWithGOOS(goos, goarch)
	if err != nil {
		return err
	}
	// strip off the path since we're setting the path in the build command
	for i := range gofiles {
		gofiles[i] = filepath.Base(gofiles[i])
	}
	buildArgs := []string{"build", "-o", compileTo}
	if ldflags != "" {
		buildArgs = append(buildArgs, "-ldflags", ldflags)
	}
	args := append(buildArgs, gofiles...)

	debug.Printf("running %s %s", goCmd, strings.Join(args, " "))
	c := exec.Command(goCmd, args...)
	c.Env = environ
	c.Stderr = stderr
	c.Stdout = stdout
	c.Dir = magePath
	start := time.Now()
	err = c.Run()
	debug.Println("time to compile Magefile:", time.Since(start))
	if err != nil {
		return errors.New("error compiling magefiles")
	}
	return nil
}

// GenerateMainfile generates the mage mainfile at path.
func GenerateMainfile(binaryName, path string, info *parse.PkgInfo) error {
	debug.Println("Creating mainfile at", path)

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("error creating generated mainfile: %v", err)
	}
	defer f.Close()
	data := mainfileTemplateData{
		Description: info.Description,
		Funcs:       info.Funcs,
		Aliases:     info.Aliases,
		Imports:     info.Imports,
		BinaryName:  binaryName,
	}

	if info.DefaultFunc != nil {
		data.DefaultFunc = *info.DefaultFunc
	}

	debug.Println("writing new file at", path)
	if err := mainfileTemplate.Execute(f, data); err != nil {
		return fmt.Errorf("can't execute mainfile template: %v", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("error closing generated mainfile: %v", err)
	}
	// we set an old modtime on the generated mainfile so that the go tool
	// won't think it has changed more recently than the compiled binary.
	longAgo := time.Now().Add(-time.Hour * 24 * 365 * 10)
	if err := os.Chtimes(path, longAgo, longAgo); err != nil {
		return fmt.Errorf("error setting old modtime on generated mainfile: %v", err)
	}
	return nil
}

// ExeName reports the executable filename that this version of Mage would
// create for the given magefiles.
func ExeName(goCmd, cacheDir string, files []string) (string, error) {
	var hashes []string
	for _, s := range files {
		h, err := hashFile(s)
		if err != nil {
			return "", err
		}
		hashes = append(hashes, h)
	}
	// hash the mainfile template to ensure if it gets updated, we make a new
	// binary.
	hashes = append(hashes, fmt.Sprintf("%x", sha1.Sum([]byte(mageMainfileTplString))))
	sort.Strings(hashes)
	ver, err := internal.OutputDebug(goCmd, "version")
	if err != nil {
		return "", err
	}
	hash := sha1.Sum([]byte(strings.Join(hashes, "") + magicRebuildKey + ver))
	filename := fmt.Sprintf("%x", hash)

	out := filepath.Join(cacheDir, filename)
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	return out, nil
}

func hashFile(fn string) (string, error) {
	f, err := os.Open(fn)
	if err != nil {
		return "", fmt.Errorf("can't open input file for hashing: %#v", err)
	}
	defer f.Close()

	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("can't write data to hash: %v", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func generateInit(dir string) error {
	debug.Println("generating default magefile in", dir)
	f, err := os.Create(filepath.Join(dir, initFile))
	if err != nil {
		return fmt.Errorf("could not create mage template: %v", err)
	}
	defer f.Close()

	if err := initOutput.Execute(f, nil); err != nil {
		return fmt.Errorf("can't execute magefile template: %v", err)
	}

	return nil
}

// RunCompiled runs an already-compiled mage command with the given args,
func RunCompiled(inv Invocation, exePath string, errlog *log.Logger) int {
	debug.Println("running binary", exePath)
	c := exec.Command(exePath, inv.Args...)
	c.Stderr = inv.Stderr
	c.Stdout = inv.Stdout
	c.Stdin = inv.Stdin
	c.Dir = inv.Dir
	if inv.WorkDir != inv.Dir {
		c.Dir = inv.WorkDir
	}
	// intentionally pass through unaltered os.Environ here.. your magefile has
	// to deal with it.
	c.Env = os.Environ()
	if inv.Verbose {
		c.Env = append(c.Env, "MAGEFILE_VERBOSE=1")
	}
	if inv.List {
		c.Env = append(c.Env, "MAGEFILE_LIST=1")
	}
	if inv.Help {
		c.Env = append(c.Env, "MAGEFILE_HELP=1")
	}
	if inv.Debug {
		c.Env = append(c.Env, "MAGEFILE_DEBUG=1")
	}
	if inv.GoCmd != "" {
		c.Env = append(c.Env, fmt.Sprintf("MAGEFILE_GOCMD=%s", inv.GoCmd))
	}
	if inv.Timeout > 0 {
		c.Env = append(c.Env, fmt.Sprintf("MAGEFILE_TIMEOUT=%s", inv.Timeout.String()))
	}
	debug.Print("running magefile with mage vars:\n", strings.Join(filter(c.Env, "MAGEFILE"), "\n"))
	err := c.Run()
	if !sh.CmdRan(err) {
		errlog.Printf("failed to run compiled magefile: %v", err)
	}
	return sh.ExitStatus(err)
}

func filter(list []string, prefix string) []string {
	var out []string
	for _, s := range list {
		if strings.HasPrefix(s, prefix) {
			out = append(out, s)
		}
	}
	return out
}

// removeContents removes all files but not any subdirectories in the given
// directory.
func removeContents(dir string) error {
	debug.Println("removing all files in", dir)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		err = os.Remove(filepath.Join(dir, f.Name()))
		if err != nil {
			return err
		}
	}
	return nil
}
