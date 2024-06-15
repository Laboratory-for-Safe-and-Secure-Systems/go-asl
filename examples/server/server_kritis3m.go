package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/go-wolfssl/asl"
)

/* Connection configuration constants */
const (
	CONN_HOST = "waifu.local"
	CONN_PORT = "12345"
	CONN_TYPE = "tcp"
)

const clientAuth = true

func main() {
	/* Server Key and Certificate paths */
	CERT_FILE := "./certs/server_cert.pem"
	KEY_FILE := "./certs/server_key.pem"
	CAFILE := "./certs/takemepls.pem"

	// Create and configure the library configuration
	libConfig := &asl.ASLConfig{
		LoggingEnabled:       true,
		LogLevel:             3,
		SecureElementSupport: false,
	}

	err := asl.ASLinit(libConfig)
	if err != nil {
		fmt.Println("Error initializing wolfSSL:", err)
		os.Exit(1)
	}

	// Create and configure the endpoint configuration
	endpointConfig := &asl.EndpointConfig{
		MutualAuthentication:    true,
		NoEncryption:            false,
		UseSecureElement:        false,
		SecureElementImportKeys: false,
		HybridSignatureMode:     asl.HYBRID_SIGNATURE_MODE_BOTH,
		DeviceCertificateChain:  asl.DeviceCertificateChain{Path: CERT_FILE},
		PrivateKey: asl.PrivateKey{
      Path: KEY_FILE,
			// only if the keys are in separate files
			AdditionalKeyBuffer: nil,
		},
		RootCertificate: asl.RootCertificate{Path: CAFILE},
		KeylogFile:      "/tmp/keylog.txt",
	}

	// Use the cEndpointConfig in C functions...
	serverEndpoint := asl.ASLsetupServerEndpoint(endpointConfig)
	if serverEndpoint == nil {
		fmt.Println("Error setting up server endpoint")
		os.Exit(1)
	}

	ctx_ := asl.GetWolfSSLContext(serverEndpoint)
	if ctx_ == nil {
		fmt.Println("Error getting wolfSSL context")
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

	session_ := asl.GetWolfSSLSession(ASLSession)
	if session_ == nil {
		fmt.Println("Error getting wolfSSL session")
		return
	}

	err = asl.ASLHandshake(ASLSession)
	if err != nil {
		fmt.Println("Error handshaking:", err)
		return
	}

	// Get the peer certificate
	peerCert, err := asl.WolfSSL_get_peer_certificate(session_)
	if err != nil {
		fmt.Println("Error getting peer certificate:", err)
		return
	}

	// peerCert.UnhandledCriticalExtensions
	for _, ext := range peerCert.UnhandledCriticalExtensions {
		fmt.Println(ext)
	}

	// #define SubjectAltPublicKeyInfoExtension "2.5.29.72"
	// #define AltSignatureAlgorithmExtension "2.5.29.73"
	// #define AltSignatureValueExtension "2.5.29.74"

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
	asl.ASLFreeSession(ASLSession)
}
