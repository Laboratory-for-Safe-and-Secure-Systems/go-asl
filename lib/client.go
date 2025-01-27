package lib

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl"
)

// ASLTransport is a custom RoundTripper that uses ASL for TLS communication
type ASLTransport struct {
	Endpoint *asl.ASLEndpoint
	Dialer   *net.Dialer // Optional custom dialer for timeouts, etc.
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

	// Set up ASL session using the file descriptor from the TCP connection
	file, _ := rawConn.File()
	fd := int(file.Fd())

	aslSession := asl.ASLCreateSession(t.Endpoint, fd)
	if aslSession == nil {
		return nil, fmt.Errorf("failed to create ASL session")
	}

	aslConn := &ASLConn{
		tcpConn:    rawConn,
		file:       file,
		aslSession: aslSession,
	}

	err = asl.ASLHandshake(aslConn.aslSession)
	if err != nil {
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
