package asl

// #cgo pkg-config: --static kritis3m_asl
// #include <asl_config.h>
// #include <asl.h>
// #include <stdlib.h>
import "C"

import (
	"crypto/x509"
	"fmt"
	"os"
	"unsafe"
)

type (
	WOLFSSL_CTX C.struct_WOLFSSL_CTX
	WOLFSSL     C.struct_WOLFSSL
	ASLEndpoint C.asl_endpoint
	ASLSession  C.asl_session
)

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

type ASLKeyExchangeMethod int

const (
	KEX_DEFAULT                     ASLKeyExchangeMethod = C.ASL_KEX_DEFAULT
	KEX_CLASSIC_ECDHE_256           ASLKeyExchangeMethod = C.ASL_KEX_CLASSIC_SECP256
	KEX_CLASSIC_ECDHE_384           ASLKeyExchangeMethod = C.ASL_KEX_CLASSIC_SECP384
	KEX_CLASSIC_ECDHE_521           ASLKeyExchangeMethod = C.ASL_KEX_CLASSIC_SECP521
	KEX_CLASSIC_X25519              ASLKeyExchangeMethod = C.ASL_KEX_CLASSIC_X25519
	KEX_CLASSIC_X448                ASLKeyExchangeMethod = C.ASL_KEX_CLASSIC_X448
	KEX_PQC_MLKEM_512               ASLKeyExchangeMethod = C.ASL_KEX_PQC_MLKEM512
	KEX_PQC_MLKEM_768               ASLKeyExchangeMethod = C.ASL_KEX_PQC_MLKEM768
	KEX_PQC_MLKEM_1024              ASLKeyExchangeMethod = C.ASL_KEX_PQC_MLKEM1024
	KEX_HYBRID_ECDHE_256_MLKEM_512  ASLKeyExchangeMethod = C.ASL_KEX_HYBRID_SECP256_MLKEM512
	KEX_HYBRID_ECDHE_384_MLKEM_768  ASLKeyExchangeMethod = C.ASL_KEX_HYBRID_SECP384_MLKEM768
	KEX_HYBRID_ECDHE_521_MLKEM_1024 ASLKeyExchangeMethod = C.ASL_KEX_HYBRID_SECP521_MLKEM1024
	KEX_HYBRID_X25519_MLKEM_512     ASLKeyExchangeMethod = C.ASL_KEX_HYBRID_X25519_MLKEM512
	KEX_HYBRID_X25519_MLKEM_768     ASLKeyExchangeMethod = C.ASL_KEX_HYBRID_X25519_MLKEM768
	KEX_HYBRID_X448_MLKEM_768       ASLKeyExchangeMethod = C.ASL_KEX_HYBRID_X448_MLKEM768
)

type PKCS11ASL struct {
	Path string
	Pin  string
}

type PreSharedKeyClientCallback C.asl_psk_client_callback_t
type PreSharedKeyServerCallback C.asl_psk_server_callback_t

type PreSharedKey struct {
	MasterKey            string
	Enable               bool
	UseExternalCallbacks bool
	EnableCertAuth       bool
	CallbackContext      unsafe.Pointer
	ClientCallback       PreSharedKeyClientCallback
	ServerCallback       PreSharedKeyServerCallback
}

type DeviceCertificateChain struct {
	Path   string
	buffer []byte
}

type RootCertificate struct {
	Path   string
	buffer []byte
}

type PrivateKey struct {
	Path   string
	buffer []byte
	// only if the keys are in separate files
	AdditionalKeyBuffer []byte
}

type CustomLogCallback C.asl_log_callback_t

type EndpointConfig struct {
	MutualAuthentication   bool
	NoEncryption           bool
	ASLKeyExchangeMethod   ASLKeyExchangeMethod
	PKCS11                 PKCS11ASL
	PreSharedKey           PreSharedKey
	DeviceCertificateChain DeviceCertificateChain
	PrivateKey             PrivateKey
	RootCertificate        RootCertificate
	KeylogFile             string
}

func (ec *EndpointConfig) toC() *C.asl_endpoint_configuration {
	config := C.asl_endpoint_configuration{
		mutual_authentication: C.bool(ec.MutualAuthentication),
		no_encryption:         C.bool(ec.NoEncryption),
		key_exchange_method:   C.enum_asl_key_exchange_method(ec.ASLKeyExchangeMethod),
		keylog_file:           C.CString(ec.KeylogFile),
	}

	// PKCS11
	if ec.PKCS11.Path != "" {
		config.pkcs11.module_path = C.CString(ec.PKCS11.Path)
	}

	if ec.PKCS11.Pin != "" {
		config.pkcs11.module_pin = C.CString(ec.PKCS11.Pin)
	}

	// PreSharedKey
	config.psk.enable_psk = C.bool(ec.PreSharedKey.Enable)
	config.psk.use_external_callbacks = C.bool(ec.PreSharedKey.UseExternalCallbacks)
	config.psk.enable_certWithExternPsk = C.bool(ec.PreSharedKey.EnableCertAuth)
	config.psk.callback_ctx = ec.PreSharedKey.CallbackContext
	config.psk.psk_client_cb = (C.asl_psk_client_callback_t)(ec.PreSharedKey.ClientCallback)
	config.psk.psk_server_cb = (C.asl_psk_server_callback_t)(ec.PreSharedKey.ServerCallback)

	if ec.PreSharedKey.MasterKey != "" {
		config.psk.master_key = C.CString(ec.PreSharedKey.MasterKey)
	}

	// read the device certificate chain from file
	if ec.DeviceCertificateChain.Path != "" {
		deviceCertChain, err := os.ReadFile(ec.DeviceCertificateChain.Path)
		if err != nil {
			panic(err)
		}
		ec.DeviceCertificateChain.buffer = deviceCertChain
	}

	// read the private key from file
	if ec.PrivateKey.Path != "" {
		privateKey, err := os.ReadFile(ec.PrivateKey.Path)
		if err != nil {
			panic(err)
		}
		ec.PrivateKey.buffer = privateKey
	}

	// read the root certificate from file
	if ec.RootCertificate.Path != "" {
		rootCert, err := os.ReadFile(ec.RootCertificate.Path)
		if err != nil {
			panic(err)
		}
		ec.RootCertificate.buffer = rootCert
	}

	// Allocate and set the device certificate chain
	config.device_certificate_chain.buffer = (*C.uint8_t)(C.CBytes(ec.DeviceCertificateChain.buffer))
	config.device_certificate_chain.size = C.size_t(len(ec.DeviceCertificateChain.buffer))

	// Allocate and set the private key
	config.private_key.buffer = (*C.uint8_t)(C.CBytes(ec.PrivateKey.buffer))
	config.private_key.size = C.size_t(len(ec.PrivateKey.buffer))
	if ec.PrivateKey.AdditionalKeyBuffer == nil {
		// NULL
		ec.PrivateKey.AdditionalKeyBuffer = []byte{}
	} else {
		config.private_key.additional_key_buffer = (*C.uint8_t)(C.CBytes(ec.PrivateKey.AdditionalKeyBuffer))
		config.private_key.additional_key_size = C.size_t(len(ec.PrivateKey.AdditionalKeyBuffer))
	}

	// Allocate and set the root certificate
	config.root_certificate.buffer = (*C.uint8_t)(C.CBytes(ec.RootCertificate.buffer))
	config.root_certificate.size = C.size_t(len(ec.RootCertificate.buffer))

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
	LoggingEnabled    bool
	LogLevel          int32
	CustomLogCallback CustomLogCallback
}

func (lc *ASLConfig) toC() *C.asl_configuration {
	config := C.asl_configuration{
		logging_enabled: C.bool(lc.LoggingEnabled),
		log_level:       C.int32_t(lc.LogLevel),
		log_callback:    (C.asl_log_callback_t)(lc.CustomLogCallback),
	}

	return &config
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

func ASLGetPeerCertificate(session *ASLSession) (*x509.Certificate, error) {
	certBuffer := make([]byte, 16384)
	certSize := C.size_t(len(certBuffer))
	ret := C.asl_get_peer_certificate((*C.asl_session)(session), (*C.uint8_t)(&certBuffer[0]), &certSize)
	if ret != ASL_SUCCESS {
		return nil, fmt.Errorf("Failed to get peer certificate: %s", ASLErrorMessage(int(ret)))
	}

	certBuffer = certBuffer[:certSize]

	certX509, err := x509.ParseCertificate(certBuffer)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse peer certificate: %s", err)
	}

	return certX509, nil
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
