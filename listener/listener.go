package listener

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	asl "github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl/logging"
	"golang.org/x/sys/unix"
)

// ASLConn is our custom connection that implements net.Conn and wraps ASL functionality.
// Note: The struct embeds *ASLListener and *net.TCPConn so that these objects are shared by reference.
type ASLConn struct {
	aslSession *asl.ASLSession
	peerCert   *x509.Certificate
	logger     logging.Logger
	TLSState   *tls.ConnectionState

	deadlineMu   sync.Mutex
	readDeadline time.Time
	closeOnce    sync.Once
	readWg       sync.WaitGroup
	closed       int32
	ctx          context.Context
	cancel       context.CancelFunc
	sessionRef   int32

	*ASLListener // Embedded pointer to parent listener.
	*net.TCPConn // Embedded pointer to underlying TCP connection.
}

// Read wraps the blocking asl.ASLReceive call in a goroutine to enforce a deadline.
func (c *ASLConn) Read(b []byte) (int, error) {
	if atomic.LoadInt32(&c.closed) != 0 {
		return 0, errors.New("ASLConn: connection closed")
	}

	c.readWg.Add(1)
	defer c.readWg.Done()

	// Combine the connection context with a deadline (if set)
	c.deadlineMu.Lock()
	deadline := c.readDeadline
	c.deadlineMu.Unlock()

	var ctx context.Context
	var cancel context.CancelFunc
	if deadline.IsZero() {
		ctx, cancel = context.WithCancel(c.ctx)
	} else {
		ctx, cancel = context.WithDeadline(c.ctx, deadline)
	}
	defer cancel()

	type result struct {
		n   int
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		// Increase the reference count to ensure the session remains valid.
		atomic.AddInt32(&c.sessionRef, 1)
		defer atomic.AddInt32(&c.sessionRef, -1)

		n, err := asl.ASLReceive(c.aslSession, b)
		resCh <- result{n: n, err: err}
	}()

	select {
	case <-ctx.Done():
		// This branch covers both timeout and cancellation.
		return 0, ctx.Err()
	case res := <-resCh:
		return res.n, res.err
	}
}

func (c *ASLConn) Write(b []byte) (int, error) {
	err := asl.ASLSend(c.aslSession, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close ensures that the underlying ASL session is closed only once.
func (c *ASLConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.logger.Infof("Closing ASL connection")
		atomic.StoreInt32(&c.closed, 1)

		// Force the underlying TCP socket to abort blocking reads.
		c.TCPConn.SetDeadline(time.Now())
		if rawConn, errRaw := c.TCPConn.SyscallConn(); errRaw == nil {
			rawConn.Control(func(fd uintptr) {
				// Shutdown the read side to force any blocked read to return.
				unix.Shutdown(int(fd), unix.SHUT_RD)
			})
		} else {
			c.logger.Errorf("Failed to get raw connection for shutdown: %v", errRaw)
		}

		// Cancel the context to signal any pending Read operations.
		c.cancel()
		err = c.TCPConn.Close()
		c.readWg.Wait()

		// Wait until all read goroutines have finished using the session.
		for atomic.LoadInt32(&c.sessionRef) != 0 {
			time.Sleep(10 * time.Millisecond)
		}

		// Now it is safe to close and free the session.
		asl.ASLCloseSession(c.aslSession)
		asl.ASLFreeSession(c.aslSession)
		c.aslSession = nil

		// Remove from the parent's active connection registry.
		if c.ASLListener != nil {
			c.ASLListener.activeConns.Delete(c)
		}

		c.logger.Debugf("ASL connection closed")
	})
	return err
}

func (c *ASLConn) LocalAddr() net.Addr {
	return c.TCPConn.LocalAddr()
}

func (c *ASLConn) RemoteAddr() net.Addr {
	return c.TCPConn.RemoteAddr()
}

func (c *ASLConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	return c.TCPConn.SetDeadline(t)
}

func (c *ASLConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	return c.TCPConn.SetReadDeadline(t)
}

func (c *ASLConn) SetWriteDeadline(t time.Time) error {
	return c.TCPConn.SetWriteDeadline(t)
}

// simulateTLSState simulates the TLS connection state by fetching the peer certificate.
func (c *ASLConn) simulateTLSState() {
	peerCert, err := asl.ASLGetPeerCertificate(c.aslSession)
	if err == nil {
		c.peerCert = peerCert
	} else {
		c.logger.Infof("Failed to get peer certificate: %v", err)
	}
	c.logger.Debugf("ASL connection established with peer %v", c.TCPConn.RemoteAddr())

	if c.peerCert == nil {
		c.logger.Debugf("No peer certificate available")
	} else if c.peerCert != nil {
		c.logger.Debugf("Peer certificate details: %v", map[string]interface{}{
			"Subject": c.peerCert.Subject,
			"Issuer":  c.peerCert.Issuer,
		})
		c.TLSState = &tls.ConnectionState{
			HandshakeComplete: true,
			PeerCertificates:  []*x509.Certificate{c.peerCert},
		}
		c.logger.Debugf("Simulated TLS state: %+v", c.TLSState)
	}
}

// ASLListener wraps a net.Listener and handles creating ASL sessions.
type ASLListener struct {
	Endpoint    *asl.ASLEndpoint
	Logger      logging.Logger
	activeConns sync.Map // key: *ASLConn, value: struct{}

	net.Listener // Embedded underlying listener.
}

func (l *ASLListener) Accept() (net.Conn, error) {
	if l.Logger == nil {
		l.Logger = &logging.DefaultLogger{DebugEnabled: false}
	} else {
		l.Logger = logging.NewLogger(l.Logger)
	}

	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tcpConn, ok := c.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("failed to cast connection to *net.TCPConn")
	}

	// Use SyscallConn to get the underlying FD without duplicating it.
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to get syscall.RawConn: %v", err)
	}
	var fd int
	controlErr := rawConn.Control(func(s uintptr) {
		fd = int(s)
	})
	if controlErr != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to get fd: %v", controlErr)
	}

	// Duplicate the FD so we can modify its flags without affecting Go's TCPConn.
	dupFD, err := unix.Dup(fd)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to duplicate fd: %v", err)
	}

	// Set the duplicate FD to blocking mode.
	if err := unix.SetNonblock(dupFD, false); err != nil {
		unix.Close(dupFD)
		tcpConn.Close()
		return nil, fmt.Errorf("failed to set dupFD to blocking mode: %v", err)
	}

	l.Logger.Debugf("Accepting connection from %v using dupFD: %d", tcpConn.RemoteAddr(), dupFD)
	session := asl.ASLCreateSession(l.Endpoint, dupFD)
	if session == nil {
		unix.Close(dupFD)
		tcpConn.Close()
		return nil, fmt.Errorf("failed to create ASL session")
	}

	l.Logger.Debugf("Created ASL session %v", session)
	connCtx, cancel := context.WithCancel(context.Background())
	aslConn := &ASLConn{
		TCPConn:    tcpConn,
		aslSession: session,
		logger:     l.Logger,
		ctx:        connCtx,
		cancel:     cancel,
		// ASLListener will be set below.
	}

	// Optionally set a handshake deadline.
	handshakeDeadline := time.Now().Add(10 * time.Second)
	tcpConn.SetDeadline(handshakeDeadline)

	l.Logger.Debugf("Performing ASL handshake")
	if err := asl.ASLHandshake(aslConn.aslSession); err != nil {
		tcpConn.Close()
		l.Logger.Errorf("ASL handshake failed: %v", err)
	}
	l.Logger.Debugf("ASL handshake complete")
	aslConn.simulateTLSState()

	// Clear the handshake deadline.
	tcpConn.SetDeadline(time.Time{})

	// Register the connection with the listener.
	aslConn.ASLListener = l
	l.activeConns.Store(aslConn, struct{}{})

	return aslConn, nil
}

// Close closes the underlying listener and forces all active connections to close.
func (l *ASLListener) Close() error {
	l.Logger.Debug("Closing listener")
	err := l.Listener.Close()

	// Force-close all active ASL connections.
	l.activeConns.Range(func(key, value interface{}) bool {
		readableKey := key.(*ASLConn).TCPConn.RemoteAddr()
		l.Logger.Debugf("Closing active connection: %v", readableKey)
		if conn, ok := key.(*ASLConn); ok {
			conn.Close()
		}
		return true
	})
	return err
}

// Addr returns the network address of the listener.
func (l *ASLListener) Addr() net.Addr {
	return l.Listener.Addr()
}
