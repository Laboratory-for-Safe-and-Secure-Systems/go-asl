package main

import (
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/signal"

	wolfSSL "github.com/ayham291/go-wolfssl"
)

/* Connection configuration constants */
const (
	CONN_HOST = "waifu.local"
	CONN_PORT = "12345"
	CONN_TYPE = "tcp"
)

const clientAuth = true

func main() {
	fmt.Printf("%s\n", wolfSSL.WolfSSL_lib_version())
	/* Server Key and Certificate paths */
	CERT_FILE := "./certs/server_cert.pem"
	KEY_FILE := "./certs/server_key.pem"
	CAFILE := "./certs/takemepls.pem"

	// Create and configure the library configuration
	libConfig := &wolfSSL.ASLConfig{
		LoggingEnabled:       true,
		LogLevel:             3,
		SecureElementSupport: false,
	}

	err := wolfSSL.ASLinit(libConfig)
	if err != nil {
		fmt.Println("Error initializing wolfSSL:", err)
		os.Exit(1)
	}

	// Read the certificate file
	certPEM, err := os.ReadFile(CERT_FILE)
	if err != nil {
		fmt.Println("Error reading certificate file:", err)
		os.Exit(1)
	}

	// Decode the PEM block
	block, rest := pem.Decode(certPEM)
	if block == nil {
		fmt.Println("Failed to decode PEM block containing the certificate")
		os.Exit(1)
	}

	// Check if there are remaining blocks
	if len(rest) > 0 {
		fmt.Println("Warning: additional data found after the first PEM block")
	}

	key, err := os.ReadFile(KEY_FILE)
	if err != nil {
		fmt.Println("Error reading key file:", err)
		os.Exit(1)
	}

	keyBlock, _ := pem.Decode(key)
	if keyBlock == nil {
		fmt.Println("Failed to decode PEM block containing the private key")
		os.Exit(1)
	}

	caPEM, err := os.ReadFile(CAFILE)
	if err != nil {
		fmt.Println("Error reading CA file:", err)
		os.Exit(1)
	}

	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		fmt.Println("Failed to decode PEM block containing the CA certificate")
		os.Exit(1)
	}

	// Create and configure the endpoint configuration
	endpointConfig := &wolfSSL.EndpointConfig{
		MutualAuthentication:    true,
		NoEncryption:            false,
		UseSecureElement:        false,
		SecureElementImportKeys: false,
		HybridSignatureMode:     wolfSSL.HYBRID_SIGNATURE_MODE_NATIVE,
		DeviceCertificateChain:  wolfSSL.Buffer{Buffer: certPEM},
		PrivateKey: wolfSSL.PrivateKey{
			Buffer:              key,
			AdditionalKeyBuffer: key,
		},
		RootCertificate: wolfSSL.Buffer{Buffer: caPEM},
		KeylogFile:      "/tmp/keylog.txt",
	}

	// Use the cEndpointConfig in C functions...
	serverEndpoint := wolfSSL.ASLsetupServerEndpoint(endpointConfig)

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

	wolfSSL.ASLFreeEndpoint(serverEndpoint)
}

/* Handles incoming requests */
func handleRequest(conn net.Conn, serverEndpoint *wolfSSL.ASLEndpoint) {
	/* Close the connection when you're done with it */
	defer conn.Close()

	file, err := conn.(*net.TCPConn).File()
	if err != nil {
		fmt.Println("Error getting file descriptor:", err)
		return
	}

	defer file.Close()

	fd := int(file.Fd())
	ASLSession := wolfSSL.ASLCreateSession(serverEndpoint, fd)
	if ASLSession == nil {
		fmt.Println("Error creating session")
		return
	}

	err = wolfSSL.ASLHandshake(ASLSession)
	if err != nil {
		fmt.Println("Error handshaking:", err)
		return
	}

	// read
	buffer := make([]byte, 1024)
	n, err := wolfSSL.ASLReceive(ASLSession, buffer)
	if err != nil {
		fmt.Println("Error receiving data:", err)
		return
	}

	fmt.Printf("Received: %s\n", buffer[:n])

	/* Send a response back to the client */
	bufSend := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello")
	err = wolfSSL.ASLSend(ASLSession, bufSend)
	if err != nil {
		fmt.Println("Error sending data:", err)
		return
	}

	wolfSSL.ASLCloseSession(ASLSession)
	wolfSSL.ASLFreeSession(ASLSession)
}
