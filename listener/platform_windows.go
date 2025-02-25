//go:build windows

package listener

import (
	"fmt"
	"net"
	"syscall"
)

func getSocketFD(conn *net.TCPConn) (int, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return -1, fmt.Errorf("failed to get syscall.RawConn: %v", err)
	}

	var handle syscall.Handle
	controlErr := rawConn.Control(func(s uintptr) {
		handle = syscall.Handle(s)
	})
	if controlErr != nil {
		return -1, fmt.Errorf("failed to get handle: %v", controlErr)
	}

	// Convert Windows HANDLE to int for ASL
	return int(handle), nil
}

func duplicateSocket(fd int) (int, error) {
	handle := syscall.Handle(fd)
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return -1, fmt.Errorf("failed to get current process: %v", err)
	}

	var dupHandle syscall.Handle
	err = syscall.DuplicateHandle(
		process,
		handle,
		process,
		&dupHandle,
		0,
		true,
		syscall.DUPLICATE_SAME_ACCESS,
	)
	if err != nil {
		return -1, fmt.Errorf("failed to duplicate handle: %v", err)
	}

	return int(dupHandle), nil
}

func shutdownSocket(conn *net.TCPConn) error {
	if rawConn, err := conn.SyscallConn(); err == nil {
		rawConn.Control(func(fd uintptr) {
			syscall.Shutdown(syscall.Handle(fd), syscall.SHUT_RD)
		})
		return nil
	}
	return fmt.Errorf("failed to get raw connection for shutdown")
}

func closeSocket(fd int) error {
	return syscall.CloseHandle(syscall.Handle(fd))
}
