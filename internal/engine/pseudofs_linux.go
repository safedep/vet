//go:build linux

package engine

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// pseudoTypes are the Linux file systems that the kernel makes up. They
// hold no packages, and some of them are large or never end.
var pseudoTypes = map[string]bool{
	"proc": true, "sysfs": true, "devpts": true, "cgroup": true, "cgroup2": true, "debugfs": true,
	"tracefs": true, "securityfs": true, "pstore": true, "bpf": true, "mqueue": true, "hugetlbfs": true,
	"configfs": true, "binfmt_misc": true, "nsfs": true, "efivarfs": true, "autofs": true, "fusectl": true,
}

// pseudoMounts returns the mount points of the pseudo file systems. It
// reads the mount table once, because a statfs call for each directory is
// a round trip on a network file system.
func pseudoMounts() map[string]bool {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// The fields before " - " hold the mount point at index 4. The
		// first field after it is the file system type.
		before, after, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		fields, rest := strings.Fields(before), strings.Fields(after)
		if len(fields) < 5 || len(rest) < 1 || !pseudoTypes[rest[0]] {
			continue
		}
		out[unescapeMount(fields[4])] = true
	}
	return out
}

// unescapeMount decodes the octal escapes of a mount point, such as \040
// for a space.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
