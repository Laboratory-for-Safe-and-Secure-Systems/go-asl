package listener

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl/logging"
)

// ASLTransport is a custom RoundTripper that uses ASL for TLS communication
type ASLTransport struct {
	Endpoint *asl.ASLEndpoint
	Dialer   *net.Dialer // Optional custom dialer for timeouts, etc.
	Logger   logging.Logger
}

// DialContext creates a custom ASL connection instead of using TLS
func (t *ASLTransport) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Dial the TCP connection
	tcpConn, err := t.Dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// Cast to TCPConn
	rawConn, ok := tcpConn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("failed to cast to *net.TCPConn")
	}

	// Get the socket file descriptor using platform-specific code
	fd, err := getSocketFD(rawConn)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	// Duplicate the socket using platform-specific code
	dupFD, err := duplicateSocket(fd)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	aslSession := asl.ASLCreateSession(t.Endpoint, dupFD)
	if aslSession == nil {
		closeSocket(dupFD)
		rawConn.Close()
		return nil, fmt.Errorf("failed to create ASL session")
	}

	connContext, cancel := context.WithCancel(ctx)

	aslConn := &ASLConn{
		TCPConn:     rawConn,
		aslSession:  aslSession,
		ctx:         connContext,
		cancel:      cancel,
		ASLListener: nil,
		logger:      t.Logger,
		TLSState:    nil,
	}

	err = asl.ASLHandshake(aslConn.aslSession)
	if err != nil {
		closeSocket(dupFD)
		rawConn.Close()
		return nil, fmt.Errorf("ASL handshake failed: %v", err)
	}

	// // Set a context for the handshake with a timeout
	// handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	// defer cancel()

	// // Perform ASL handshake
	// done := make(chan error, 1)
	// go func() {
	// 	done <- asl.ASLHandshake(aslConn.aslSession)
	// }()

	// select {
	// case <-handshakeCtx.Done():
	// 	rawConn.Close() // Ensure to close the connection if we timeout
	// 	return nil, fmt.Errorf("ASL handshake timed out")
	// case err := <-done:
	// 	if err != nil {
	// 		rawConn.Close()
	// 		return nil, fmt.Errorf("ASL handshake failed: %v", err)
	// 	}
	// }

	return aslConn, nil
}

// RoundTrip executes a single HTTP transaction
func (t *ASLTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Handle "https" scheme manually with ASL
	if req.URL.Scheme == "https" {
		conn, err := t.DialContext(req.Context(), "tcp", req.URL.Host)
		if err != nil {
			return nil, fmt.Errorf("failed to establish ASL connection: %v", err)
		}

		// Set a timeout for writing the request
		writeDeadline := time.Now().Add(5 * time.Second)
		err = conn.SetWriteDeadline(writeDeadline)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to set write deadline: %v", err)
		}

		// Send the HTTP request manually over the custom connection
		err = req.Write(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to write request: %v", err)
		}

		// Read the HTTP response
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to read response: %v", err)
		}

		// Set the response body to close the connection
		resp.Body = &customReadCloser{
			ReadCloser: resp.Body,
			conn:       conn,
		}

		return resp, nil
	}

	// Fallback for non-https schemes
	return http.DefaultTransport.RoundTrip(req)
}

type customReadCloser struct {
	io.ReadCloser
	conn net.Conn
}

func (c *customReadCloser) Close() error {
	err := c.ReadCloser.Close()
	connErr := c.conn.Close()
	if err != nil {
		return err
	}
	return connErr
}

func Dial(network, addr string, endpoint *asl.ASLEndpoint) (net.Conn, error) {
	// Dial the TCP connection
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	tcpConn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	// Cast to TCPConn
	rawConn, ok := tcpConn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("failed to cast to *net.TCPConn")
	}

	// Get the socket file descriptor using platform-specific code
	fd, err := getSocketFD(rawConn)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	// Duplicate the socket using platform-specific code
	dupFD, err := duplicateSocket(fd)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	aslSession := asl.ASLCreateSession(endpoint, dupFD)
	if aslSession == nil {
		closeSocket(dupFD)
		rawConn.Close()
		return nil, fmt.Errorf("failed to create ASL session")
	}

	// Create context and logger
	ctx, cancel := context.WithCancel(context.Background())
	logger := &logging.DefaultLogger{DebugEnabled: false}
	fmt.Println("dialed")

	// Wrap the TCP connection in an ASLConn, ensuring the context is set.
	aslConn := &ASLConn{
		aslSession:  aslSession,
		ctx:         ctx,
		cancel:      cancel,
		TCPConn:     rawConn,
		ASLListener: nil, // Client connections don't have a listener
		logger:      logger,
	}

	err = asl.ASLHandshake(aslConn.aslSession)
	if err != nil {
		closeSocket(dupFD)
		cancel() // Clean up context if handshake fails
		rawConn.Close()
		return nil, fmt.Errorf("ASL handshake failed: %v", err)
	}

	// Simulate TLS state after successful handshake
	aslConn.simulateTLSState()

	return aslConn, nil
}
