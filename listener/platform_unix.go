//go:build linux || darwin

package listener

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func getSocketFD(conn *net.TCPConn) (int, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return -1, fmt.Errorf("failed to get syscall.RawConn: %v", err)
	}

	var fd int
	controlErr := rawConn.Control(func(s uintptr) {
		fd = int(s)
	})
	if controlErr != nil {
		return -1, fmt.Errorf("failed to get fd: %v", controlErr)
	}

	return fd, nil
}

func duplicateSocket(fd int) (int, error) {
	dupFD, err := unix.Dup(fd)
	if err != nil {
		return -1, fmt.Errorf("failed to duplicate fd: %v", err)
	}

	if err := unix.SetNonblock(dupFD, false); err != nil {
		unix.Close(dupFD)
		return -1, fmt.Errorf("failed to set dupFD to blocking mode: %v", err)
	}

	return dupFD, nil
}

func shutdownSocket(conn *net.TCPConn) error {
	if rawConn, err := conn.SyscallConn(); err == nil {
		rawConn.Control(func(fd uintptr) {
			unix.Shutdown(int(fd), unix.SHUT_RD)
		})
		return nil
	}
	return fmt.Errorf("failed to get raw connection for shutdown")
}

func closeSocket(fd int) error {
	return unix.Close(fd)
}
