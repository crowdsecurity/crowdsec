//go:build !windows && !freebsd && !openbsd

package types

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Generated with `man statfs | grep _MAGIC | awk '{split(tolower($1),a,"_"); print $2 ": \"" a[1] "\","}'`
// ext2/3/4 duplicates removed to just have ext4
// XIAFS removed as well
var fsTypeMapping = map[int64]string{
	0xadf5:     "adfs",
	0xadff:     "affs",
	0x5346414f: "afs",
	0x09041934: "anon",
	0x0187:     "autofs",
	0x62646576: "bdevfs",
	0x42465331: "befs",
	0x1badface: "bfs",
	0x42494e4d: "binfmtfs",
	0xcafe4a11: "bpf",
	0x9123683e: "btrfs",
	0x73727279: "btrfs",
	0x27e0eb:   "cgroup",
	0x63677270: "cgroup2",
	0xff534d42: "cifs",
	0x73757245: "coda",
	0x012ff7b7: "coh",
	0x28cd3d45: "cramfs",
	0x64626720: "debugfs",
	0x1373:     "devfs",
	0x1cd1:     "devpts",
	0xf15f:     "ecryptfs",
	0xde5e81e4: "efivarfs",
	0x00414a53: "efs",
	0x137d:     "ext",
	0xef51:     "ext2",
	0xef53:     "ext4",
	0xf2f52010: "f2fs",
	0x65735546: "fuse",
	0xbad1dea:  "futexfs",
	0x4244:     "hfs",
	0x00c0ffee: "hostfs",
	0xf995e849: "hpfs",
	0x958458f6: "hugetlbfs",
	0x9660:     "isofs",
	0x72b6:     "jffs2",
	0x3153464a: "jfs",
	0x137f:     "minix",
	0x138f:     "minix",
	0x2468:     "minix2",
	0x2478:     "minix2",
	0x4d5a:     "minix3",
	0x19800202: "mqueue",
	0x4d44:     "msdos",
	0x11307854: "mtd",
	0x564c:     "ncp",
	0x6969:     "nfs",
	0x3434:     "nilfs",
	0x6e736673: "nsfs",
	0x5346544e: "ntfs",
	0x7461636f: "ocfs2",
	0x9fa1:     "openprom",
	0x794c7630: "overlayfs",
	0x50495045: "pipefs",
	0x9fa0:     "proc",
	0x6165676c: "pstorefs",
	0x002f:     "qnx4",
	0x68191122: "qnx6",
	0x858458f6: "ramfs",
	0x52654973: "reiserfs",
	0x7275:     "romfs",
	0x73636673: "securityfs",
	0xf97cff8c: "selinux",
	0x43415d53: "smack",
	0x517b:     "smb",
	0xfe534d42: "smb2",
	0x534f434b: "sockfs",
	0x73717368: "squashfs",
	0x62656572: "sysfs",
	0x012ff7b6: "sysv2",
	0x012ff7b5: "sysv4",
	0x01021994: "tmpfs",
	0x74726163: "tracefs",
	0x15013346: "udf",
	0x00011954: "ufs",
	0x9fa2:     "usbdevice",
	0x01021997: "v9fs",
	0xa501fcf5: "vxfs",
	0xabba1974: "xenfs",
	0x012ff7b4: "xenix",
	0x58465342: "xfs",
	0x2fc12fc1: "zfs",
}

func GetFSType(path string) (string, error) {
	var buf unix.Statfs_t

	err := unix.Statfs(path, &buf)
	if err != nil {
		return "", err
	}

	fsType, ok := fsTypeMapping[int64(buf.Type)] //nolint:unconvert

	if !ok {
		return "", fmt.Errorf("unknown fstype %d", buf.Type)
	}

	return fsType, nil
}
