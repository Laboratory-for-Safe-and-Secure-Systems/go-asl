package wolfSSL

// #cgo pkg-config: --static kritis3m
// #include <asl_config.h>
// #include <asl.h>
import "C"
import (
	"crypto/x509"
	"fmt"
	"unsafe"
)

type WOLFSSL_CTX C.struct_WOLFSSL_CTX
type WOLFSSL C.struct_WOLFSSL

func WolfSSL_get_peer_certificate(ssl *WOLFSSL) (*x509.Certificate, error) {
	peerCert := (C.wolfSSL_get_peer_certificate((*C.struct_WOLFSSL)(ssl)))
	sz := C.int(0)
	if peerCert == nil {
		return nil, fmt.Errorf("Peer certificate is nil")
	}

	data := C.wolfSSL_X509_get_der(peerCert, &sz)
	if data == nil {
		return nil, fmt.Errorf("Failed to get peer certificate")
	}

	certX509, err := x509.ParseCertificate(C.GoBytes(unsafe.Pointer(data), sz))
	if err != nil {
		return nil, fmt.Errorf("Failed to parse peer certificate")
	}

	return certX509, nil
}
