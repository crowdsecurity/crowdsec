package sysfs

import (
	"io/fs"
	"os"
	"syscall"

	"github.com/tetratelabs/wazero/internal/platform"
)

func NewDirFS(dir string) FS {
	return &dirFS{
		dir:        dir,
		cleanedDir: ensureTrailingPathSeparator(dir),
	}
}

func ensureTrailingPathSeparator(dir string) string {
	if !os.IsPathSeparator(dir[len(dir)-1]) {
		return dir + string(os.PathSeparator)
	}
	return dir
}

type dirFS struct {
	UnimplementedFS
	dir string
	// cleanedDir is for easier OS-specific concatenation, as it always has
	// a trailing path separator.
	cleanedDir string
}

// String implements fmt.Stringer
func (d *dirFS) String() string {
	return d.dir
}

// Open implements the same method as documented on fs.FS
func (d *dirFS) Open(name string) (fs.File, error) {
	return fsOpen(d, name)
}

// OpenFile implements FS.OpenFile
func (d *dirFS) OpenFile(path string, flag int, perm fs.FileMode) (fs.File, error) {
	return platform.OpenFile(d.join(path), flag, perm)
}

// Lstat implements FS.Lstat
func (d *dirFS) Lstat(path string, stat *platform.Stat_t) error {
	return platform.Lstat(d.join(path), stat)
}

// Stat implements FS.Stat
func (d *dirFS) Stat(path string, stat *platform.Stat_t) error {
	return platform.Stat(d.join(path), stat)
}

// Mkdir implements FS.Mkdir
func (d *dirFS) Mkdir(path string, perm fs.FileMode) (err error) {
	err = os.Mkdir(d.join(path), perm)
	if err = platform.UnwrapOSError(err); err == syscall.ENOTDIR {
		err = syscall.ENOENT
	}
	return
}

// Chmod implements FS.Chmod
func (d *dirFS) Chmod(path string, perm fs.FileMode) error {
	err := os.Chmod(d.join(path), perm)
	return platform.UnwrapOSError(err)
}

// Chown implements FS.Chown
func (d *dirFS) Chown(path string, uid, gid int) error {
	return platform.Chown(d.join(path), uid, gid)
}

// Lchown implements FS.Lchown
func (d *dirFS) Lchown(path string, uid, gid int) error {
	return platform.Lchown(d.join(path), uid, gid)
}

// Rename implements FS.Rename
func (d *dirFS) Rename(from, to string) error {
	from, to = d.join(from), d.join(to)
	err := platform.Rename(from, to)
	return platform.UnwrapOSError(err)
}

// Readlink implements FS.Readlink
func (d *dirFS) Readlink(path string) (string, error) {
	// Note: do not use syscall.Readlink as that causes race on Windows.
	// In any case, syscall.Readlink does almost the same logic as os.Readlink.
	dst, err := os.Readlink(d.join(path))
	if err != nil {
		return "", platform.UnwrapOSError(err)
	}
	return platform.ToPosixPath(dst), nil
}

// Link implements FS.Link.
func (d *dirFS) Link(oldName, newName string) error {
	err := os.Link(d.join(oldName), d.join(newName))
	return platform.UnwrapOSError(err)
}

// Rmdir implements FS.Rmdir
func (d *dirFS) Rmdir(path string) error {
	err := syscall.Rmdir(d.join(path))
	return platform.UnwrapOSError(err)
}

// Unlink implements FS.Unlink
func (d *dirFS) Unlink(path string) (err error) {
	return platform.Unlink(d.join(path))
}

// Symlink implements FS.Symlink
func (d *dirFS) Symlink(oldName, link string) (err error) {
	// Note: do not resolve `oldName` relative to this dirFS. The link result is always resolved
	// when dereference the `link` on its usage (e.g. readlink, read, etc).
	// https://github.com/bytecodealliance/cap-std/blob/v1.0.4/cap-std/src/fs/dir.rs#L404-L409
	err = os.Symlink(oldName, d.join(link))
	return platform.UnwrapOSError(err)
}

// Utimens implements FS.Utimens
func (d *dirFS) Utimens(path string, times *[2]syscall.Timespec, symlinkFollow bool) error {
	return platform.Utimens(d.join(path), times, symlinkFollow)
}

// Truncate implements FS.Truncate
func (d *dirFS) Truncate(path string, size int64) error {
	// Use os.Truncate as syscall.Truncate doesn't exist on Windows.
	err := os.Truncate(d.join(path), size)
	return platform.UnwrapOSError(err)
}

func (d *dirFS) join(path string) string {
	switch path {
	case "", ".", "/":
		if d.cleanedDir == "/" {
			return "/"
		}
		// cleanedDir includes an unnecessary delimiter for the root path.
		return d.cleanedDir[:len(d.cleanedDir)-1]
	}
	// TODO: Enforce similar to safefilepath.FromFS(path), but be careful as
	// relative path inputs are allowed. e.g. dir or path == ../
	return d.cleanedDir + path
}
