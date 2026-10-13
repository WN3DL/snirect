//go:build !(linux || android)

package core

import (
	"net"
	"strconv"
)

// uidOfConnectFlow and uidOfTCPFlow are unreachable off-linux: StartEngine is
// only invoked by gomobile (GOOS=android), and the netlink inet_diag interface
// this seams over is linux-only. Exists so host builds for darwin/windows
// type-check.
func uidOfConnectFlow(src, dst string) int {
	return 0
}

func uidOfTCPFlow(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) int {
	return 0
}
