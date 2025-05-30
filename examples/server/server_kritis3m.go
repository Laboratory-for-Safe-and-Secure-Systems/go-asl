package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/go-asl"
)

/* Connection configuration constants */
const (
	CONN_HOST = "localhost"
	CONN_PORT = "12345"
	CONN_TYPE = "tcp"
)

func main() {
	/* Server Key and Certificate paths */
	CERT_FILE := "./certs/chain.pem"
	KEY_FILE := "./certs/privateKey.pem"
	CAFILE := "./certs/root.pem"

	// Create and configure the library configuration
	libConfig := &asl.ASLConfig{
		LoggingEnabled: true,
		LogLevel:       3,
	}

	err := asl.ASLinit(libConfig)
	if err != nil {
		fmt.Println("Error initializing wolfSSL:", err)
		os.Exit(1)
	}

	// Create and configure the endpoint configuration
	endpointConfig := &asl.EndpointConfig{
		MutualAuthentication: true,
		ASLKeyExchangeMethod: asl.KEX_CLASSIC_ECDHE_521,
		Ciphersuites:         []string{"TLS13-AES256-GCM-SHA384", "TLS13-CHACHA20-POLY1305-SHA256", "TLS13-SHA384-SHA384"},
		PreSharedKey: asl.PreSharedKey{
			Enable: false,
		},
		DeviceCertificateChain: asl.DeviceCertificateChain{Path: CERT_FILE},
		PrivateKey: asl.PrivateKey{
			Path: KEY_FILE,
			// only if the keys are in separate files
			AdditionalKeyBuffer: nil,
		},
		RootCertificates: asl.RootCertificates{Paths: []string{CAFILE, CAFILE}},
		KeylogFile:       "/tmp/keylog.txt",
	}

	// Use the cEndpointConfig in C functions...
	serverEndpoint := asl.ASLsetupServerEndpoint(endpointConfig)
	if serverEndpoint == nil {
		fmt.Println("Error setting up server endpoint")
		os.Exit(1)
	}

	fmt.Println("Configuration setup complete")

	/* Listen for incoming connections */
	l, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	/* Close the listener when the application closes */
	defer l.Close()
	fmt.Println("Listening on " + CONN_HOST + ":" + CONN_PORT)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	/* Listen for an incoming connection */
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				fmt.Println("Error accepting: ", err.Error())
				os.Exit(1)
			}
			/* Handle connections concurrently */
			go handleRequest(conn, serverEndpoint)
		}
	}()

	/* Wait for a signal to shutdown */
	got := <-sig
	fmt.Println("Received signal:", got)

	asl.ASLFreeEndpoint(serverEndpoint)
	asl.ASLshutdown()
}

/* Handles incoming requests */
func handleRequest(conn net.Conn, serverEndpoint *asl.ASLEndpoint) {
	/* Close the connection when you're done with it */
	defer conn.Close()

	file, err := conn.(*net.TCPConn).File()
	if err != nil {
		fmt.Println("Error getting file descriptor:", err)
		return
	}

	defer file.Close()

	fd := int(file.Fd())
	ASLSession := asl.ASLCreateSession(serverEndpoint, fd)
	if ASLSession == nil {
		fmt.Println("Error creating session")
		return
	}

	defer asl.ASLFreeSession(ASLSession)

	err = asl.ASLHandshake(ASLSession)
	if err != nil {
		fmt.Println("Error handshaking:", err)
		return
	}

	// Get the peer certificate
	peerCert, err := asl.ASLGetPeerCertificate(ASLSession)
	if err != nil {
		fmt.Println("Error getting peer certificate:", err)
		return
	}

	// peerCert.UnhandledCriticalExtensions
	for _, ext := range peerCert.UnhandledCriticalExtensions {
		fmt.Println(ext)
	}

	// print all the non-critical extensions
	for _, ext := range peerCert.Extensions {
		if !ext.Critical {
			fmt.Println(ext.Id)
		}
	}

	// read
	buffer := make([]byte, 1024)
	n, err := asl.ASLReceive(ASLSession, buffer)
	if err != nil {
		fmt.Println("Error receiving data:", err)
		return
	}

	fmt.Printf("Received: %s\n", buffer[:n])

	/* Send a response back to the client */
	bufSend := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello")
	err = asl.ASLSend(ASLSession, bufSend)
	if err != nil {
		fmt.Println("Error sending data:", err)
		return
	}

	asl.ASLCloseSession(ASLSession)
}
