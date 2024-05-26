package wolfSSL

// #cgo pkg-config: --static kritis3m
// #include <kritis3m_asl/asl.h>
// #include <stdlib.h>
import "C"
import (
	"fmt"
	"unsafe"
)

type ASLEndpoint C.asl_endpoint
type ASLSession C.asl_session

// Error codes
const (
	ASL_SUCCESS        = C.ASL_SUCCESS
	ASL_MEMORY_ERROR   = C.ASL_MEMORY_ERROR
	ASL_ARGUMENT_ERROR = C.ASL_ARGUMENT_ERROR
	ASL_WANT_READ      = C.ASL_WANT_READ
	ASL_WANT_WRITE     = C.ASL_WANT_WRITE
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
	Buffer              []byte
	AdditionalKeyBuffer []byte
}

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
	config.private_key.additional_key_buffer = (*C.uint8_t)(C.CBytes(ec.PrivateKey.AdditionalKeyBuffer))
	config.private_key.additional_key_size = C.size_t(len(ec.PrivateKey.AdditionalKeyBuffer))

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
	SecureElementSupport        bool
	SecureElementMiddlewarePath string
}

func (lc *ASLConfig) toC() *C.asl_configuration {
	config := C.asl_configuration{
		loggingEnabled:                 C.bool(lc.LoggingEnabled),
		logLevel:                       C.int32_t(lc.LogLevel),
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
		txBytes:     C.uint32_t(hm.TxBytes),
		rxBytes:     C.uint32_t(hm.RxBytes),
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
		TxBytes:        uint32(cMetrics.txBytes),
		RxBytes:        uint32(cMetrics.rxBytes),
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
