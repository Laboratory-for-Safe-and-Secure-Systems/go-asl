package asl

// #cgo pkg-config: --static kritis3m
// #include <asl_config.h>
// #include <asl.h>
// #include <stdlib.h>
import "C"
import (
	"crypto/x509"
	"fmt"
	"unsafe"
)

type WOLFSSL_CTX C.struct_WOLFSSL_CTX
type WOLFSSL C.struct_WOLFSSL
type ASLEndpoint C.asl_endpoint
type ASLSession C.asl_session

// PQ OIDs
const (
	SubjectAltPublicKeyInfoExtension = "2.5.29.72"
	AltSignatureAlgorithmExtension   = "2.5.29.73"
	AltSignatureValueExtension       = "2.5.29.74"
)

// Error codes
const (
	ASL_SUCCESS           = C.ASL_SUCCESS
	ASL_MEMORY_ERROR      = C.ASL_MEMORY_ERROR
	ASL_ARGUMENT_ERROR    = C.ASL_ARGUMENT_ERROR
	ASL_INTERNAL_ERROR    = C.ASL_INTERNAL_ERROR
	ASL_CERTIFICATE_ERROR = C.ASL_CERTIFICATE_ERROR
	ASL_PKCS11_ERROR      = C.ASL_PKCS11_ERROR
	ASL_CONN_CLOSED       = C.ASL_CONN_CLOSED
	ASL_WANT_READ         = C.ASL_WANT_READ
	ASL_WANT_WRITE        = C.ASL_WANT_WRITE
)

// Logging levels
const (
	ASL_LOG_LEVEL_ERR = C.ASL_LOG_LEVEL_ERR
	ASL_LOG_LEVEL_WRN = C.ASL_LOG_LEVEL_WRN
	ASL_LOG_LEVEL_INF = C.ASL_LOG_LEVEL_INF
	ASL_LOG_LEVEL_DBG = C.ASL_LOG_LEVEL_DBG
)

// Hybrid signature modes
type HybridSignatureMode int

const (
	HYBRID_SIGNATURE_MODE_NATIVE      HybridSignatureMode = C.HYBRID_SIGNATURE_MODE_NATIVE
	HYBRID_SIGNATURE_MODE_ALTERNATIVE HybridSignatureMode = C.HYBRID_SIGNATURE_MODE_ALTERNATIVE
	HYBRID_SIGNATURE_MODE_BOTH        HybridSignatureMode = C.HYBRID_SIGNATURE_MODE_BOTH
)

type Buffer struct {
	Buffer []byte
}

type PrivateKey struct {
	Buffer []byte
	// only if the keys are in separate files
	AdditionalKeyBuffer []byte
}

type CustomLogCallback C.asl_custom_log_callback

type EndpointConfig struct {
	MutualAuthentication    bool
	NoEncryption            bool
	UseSecureElement        bool
	SecureElementImportKeys bool
	HybridSignatureMode     HybridSignatureMode
	DeviceCertificateChain  Buffer
	PrivateKey              PrivateKey
	RootCertificate         Buffer
	KeylogFile              string
}

func (ec *EndpointConfig) toC() *C.asl_endpoint_configuration {
	config := C.asl_endpoint_configuration{
		mutual_authentication:      C.bool(ec.MutualAuthentication),
		no_encryption:              C.bool(ec.NoEncryption),
		use_secure_element:         C.bool(ec.UseSecureElement),
		secure_element_import_keys: C.bool(ec.SecureElementImportKeys),
		hybrid_signature_mode:      C.enum_asl_hybrid_signature_mode(ec.HybridSignatureMode),
		keylog_file:                C.CString(ec.KeylogFile),
	}

	// Allocate and set the device certificate chain
	config.device_certificate_chain.buffer = (*C.uint8_t)(C.CBytes(ec.DeviceCertificateChain.Buffer))
	config.device_certificate_chain.size = C.size_t(len(ec.DeviceCertificateChain.Buffer))

	// Allocate and set the private key
	config.private_key.buffer = (*C.uint8_t)(C.CBytes(ec.PrivateKey.Buffer))
	config.private_key.size = C.size_t(len(ec.PrivateKey.Buffer))
	if ec.PrivateKey.AdditionalKeyBuffer == nil {
		// NULL
		ec.PrivateKey.AdditionalKeyBuffer = []byte{}
	} else {
		config.private_key.additional_key_buffer = (*C.uint8_t)(C.CBytes(ec.PrivateKey.AdditionalKeyBuffer))
		config.private_key.additional_key_size = C.size_t(len(ec.PrivateKey.AdditionalKeyBuffer))
	}

	// Allocate and set the root certificate
	config.root_certificate.buffer = (*C.uint8_t)(C.CBytes(ec.RootCertificate.Buffer))
	config.root_certificate.size = C.size_t(len(ec.RootCertificate.Buffer))

	return &config
}

func (ec *EndpointConfig) Free() {
	C.free(unsafe.Pointer(ec.toC().device_certificate_chain.buffer))
	C.free(unsafe.Pointer(ec.toC().private_key.buffer))
	C.free(unsafe.Pointer(ec.toC().private_key.additional_key_buffer))
	C.free(unsafe.Pointer(ec.toC().root_certificate.buffer))
	C.free(unsafe.Pointer(ec.toC().keylog_file))
}

type ASLConfig struct {
	LoggingEnabled              bool
	LogLevel                    int32
	CustomLogCallback           CustomLogCallback
	SecureElementSupport        bool
	SecureElementMiddlewarePath string
}

func (lc *ASLConfig) toC() *C.asl_configuration {
	config := C.asl_configuration{
		logging_enabled:                C.bool(lc.LoggingEnabled),
		log_level:                      C.int32_t(lc.LogLevel),
		custom_log_callback:            (C.asl_custom_log_callback)(lc.CustomLogCallback),
		secure_element_support:         C.bool(lc.SecureElementSupport),
		secure_element_middleware_path: C.CString(lc.SecureElementMiddlewarePath),
	}

	return &config
}

func (lc *ASLConfig) Free() {
	C.free(unsafe.Pointer(lc.toC().secure_element_middleware_path))
}

type HandshakeMetrics struct {
	DurationMicroS uint32
	TxBytes        uint32
	RxBytes        uint32
}

func (hm *HandshakeMetrics) toC() *C.asl_handshake_metrics {
	return &C.asl_handshake_metrics{
		duration_us: C.uint32_t(hm.DurationMicroS),
		tx_bytes:    C.uint32_t(hm.TxBytes),
		rx_bytes:    C.uint32_t(hm.RxBytes),
	}
}

func ASLErrorMessage(err int) string {
	return C.GoString(C.asl_error_message(C.int(err)))
}

func ASLinit(config *ASLConfig) error {
	ret := int(C.asl_init(config.toC()))
	if ret != ASL_SUCCESS {
		return fmt.Errorf("Failed to initialize ASL: %s", ASLErrorMessage(ret))
	}
	return nil
}

func ASLsetupServerEndpoint(config *EndpointConfig) *ASLEndpoint {
	return (*ASLEndpoint)(C.asl_setup_server_endpoint(config.toC()))
}

func ASLsetupClientEndpoint(config *EndpointConfig) *ASLEndpoint {
	return (*ASLEndpoint)(C.asl_setup_client_endpoint(config.toC()))
}

func ASLCreateSession(endpoint *ASLEndpoint, fileDescriptor int) *ASLSession {
	return (*ASLSession)(C.asl_create_session((*C.asl_endpoint)(endpoint), C.int(fileDescriptor)))
}

func ASLHandshake(session *ASLSession) error {
	ret := int(C.asl_handshake((*C.asl_session)(session)))
	if ret != ASL_SUCCESS {
		return fmt.Errorf("Failed to handshake: %s", ASLErrorMessage(ret))
	}
	return nil
}

func ASLReceive(session *ASLSession, buffer []byte) (int, error) {
	ret := int(C.asl_receive((*C.asl_session)(session), (*C.uint8_t)(&buffer[0]), C.int(len(buffer))))
	if ret == ASL_WANT_READ {
		// This is not an error, just a signal that we need to read more data
		return 0, nil
	} else if ret < 0 {
		return 0, fmt.Errorf("Failed to receive: %s", ASLErrorMessage(ret))
	}
	return ret, nil
}

func ASLSend(session *ASLSession, buffer []byte) error {
	ret := int(C.asl_send((*C.asl_session)(session), (*C.uint8_t)(&buffer[0]), C.int(len(buffer))))
	if ret == ASL_WANT_WRITE {
		// This is not an error, just a signal that we need to write more data
		return nil
	} else if ret != ASL_SUCCESS {
		return fmt.Errorf("Failed to send: %s", ASLErrorMessage(ret))
	}
	return nil
}

func HandshakeMetricsFromC(cMetrics *C.asl_handshake_metrics) *HandshakeMetrics {
	return &HandshakeMetrics{
		DurationMicroS: uint32(cMetrics.duration_us),
		TxBytes:        uint32(cMetrics.tx_bytes),
		RxBytes:        uint32(cMetrics.rx_bytes),
	}
}

func ASLGetHandshakeMetrics(session *ASLSession) *HandshakeMetrics {
	cMetrics := C.asl_get_handshake_metrics((*C.asl_session)(session))
	return HandshakeMetricsFromC(&cMetrics)
}

func ASLCloseSession(session *ASLSession) {
	C.asl_close_session((*C.asl_session)(session))
}

func ASLFreeSession(session *ASLSession) {
	C.asl_free_session((*C.asl_session)(session))
}

func ASLFreeEndpoint(endpoint *ASLEndpoint) {
	C.asl_free_endpoint((*C.asl_endpoint)(endpoint))
}

func GetWolfSSLSession(session *ASLSession) *WOLFSSL {
	return (*WOLFSSL)(unsafe.Pointer(C.asl_get_wolfssl_session((*C.asl_session)(session))))
}

func GetWolfSSLContext(context *ASLEndpoint) *WOLFSSL_CTX {
	return (*WOLFSSL_CTX)(unsafe.Pointer(C.asl_get_wolfssl_context((*C.asl_endpoint)(context))))
}

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
