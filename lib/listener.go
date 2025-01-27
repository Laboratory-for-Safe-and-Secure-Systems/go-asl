package lib

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	asl "github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl"
)

type ASLConn struct {
	tcpConn    *net.TCPConn
	file       *os.File
	aslSession *asl.ASLSession
	peerCert   *x509.Certificate // Store the peer's certificate
	TLSState   *tls.ConnectionState
}

func (c ASLConn) Read(b []byte) (n int, err error) {
	return asl.ASLReceive(c.aslSession, b)
}

func (c ASLConn) Write(b []byte) (n int, err error) {
	err = asl.ASLSend(c.aslSession, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c ASLConn) Close() error {
	asl.ASLCloseSession(c.aslSession)
	asl.ASLFreeSession(c.aslSession)
	c.file.Close()
	return c.tcpConn.Close()
}

func (c ASLConn) LocalAddr() net.Addr {
	return c.tcpConn.LocalAddr()
}

func (c ASLConn) RemoteAddr() net.Addr {
	return c.tcpConn.RemoteAddr()
}

func (c ASLConn) SetDeadline(t time.Time) error {
	return c.tcpConn.SetDeadline(t)
}

func (c ASLConn) SetReadDeadline(t time.Time) error {
	return c.tcpConn.SetReadDeadline(t)
}

func (c ASLConn) SetWriteDeadline(t time.Time) error {
	return c.tcpConn.SetWriteDeadline(t)
}

// Simulate a TLS connection state
func (c *ASLConn) simulateTLSState() {
	// Capture and store the peer certificate (if available)
	peerCert, err := asl.ASLGetPeerCertificate(c.aslSession)
	if err == nil {
		c.peerCert = peerCert
	} else {
		log.Printf("Failed to get peer certificate: %v", err)
	}

	// Populate tls.ConnectionState
	if c.peerCert != nil {
		c.TLSState = &tls.ConnectionState{
			HandshakeComplete: true,
			PeerCertificates:  []*x509.Certificate{c.peerCert},
		}
	}
}

//----------------END CONN INTERFACE IMPLEMENTATION---------------------//

// ASLListener wraps a net.TCPListener and handles ASL sessions
type ASLListener struct {
	TcpListener *net.TCPListener
	Endpoint    *asl.ASLEndpoint
}

// Accept accepts a new connection and wraps it with ASLSession
func (l ASLListener) Accept() (net.Conn, error) {
	c, err := l.TcpListener.Accept()
	if err != nil {
		return nil, err
	}

	tcpConn := c.(*net.TCPConn)
	file, _ := tcpConn.File()
	fd := int(file.Fd())

	session := asl.ASLCreateSession(l.Endpoint, fd)
	if session == nil {
		return nil, fmt.Errorf("failed to create ASL session")
	}

	aslConn := &ASLConn{
		tcpConn:    tcpConn,
		file:       file,
		aslSession: session,
	}

	err = asl.ASLHandshake(aslConn.aslSession)
	if err != nil {
		tcpConn.Close()
		log.Printf("ASL handshake failed: %v", err)
	}

	// Simulate a TLS connection state
	aslConn.simulateTLSState()

	return aslConn, nil
}

// Close closes the listener
func (l ASLListener) Close() error {
	asl.ASLFreeEndpoint(l.Endpoint)
	return l.TcpListener.Close()
}

// Addr returns the listener's network address
func (l ASLListener) Addr() net.Addr {
	return l.TcpListener.Addr()
}
