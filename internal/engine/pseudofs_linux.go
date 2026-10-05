//go:build linux

package engine

import "golang.org/x/sys/unix"

// pseudoTypes are the Linux file systems that the kernel makes up. They
// hold no packages, and some of them are large or never end.
var pseudoTypes = map[int64]bool{
	unix.PROC_SUPER_MAGIC:    true,
	unix.SYSFS_MAGIC:         true,
	unix.DEVPTS_SUPER_MAGIC:  true,
	unix.CGROUP_SUPER_MAGIC:  true,
	unix.CGROUP2_SUPER_MAGIC: true,
	unix.DEBUGFS_MAGIC:       true,
	unix.TRACEFS_MAGIC:       true,
	unix.SECURITYFS_MAGIC:    true,
	unix.PSTOREFS_MAGIC:      true,
	unix.BPF_FS_MAGIC:        true,
	unix.HUGETLBFS_MAGIC:     true,
	unix.BINFMTFS_MAGIC:      true,
	unix.NSFS_MAGIC:          true,
	unix.EFIVARFS_MAGIC:      true,
	unix.AUTOFS_SUPER_MAGIC:  true,
}

// pseudoFS reports a directory on a pseudo file system.
func pseudoFS(dir string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false
	}
	return pseudoTypes[int64(st.Type)]
}
