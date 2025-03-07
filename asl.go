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

// Error codes
const (
	ASL_SUCCESS             = C.ASL_SUCCESS
	ASL_MEMORY_ERROR        = C.ASL_MEMORY_ERROR
	ASL_ARGUMENT_ERROR      = C.ASL_ARGUMENT_ERROR
	ASL_INTERNAL_ERROR      = C.ASL_INTERNAL_ERROR
	ASL_CERTIFICATE_ERROR   = C.ASL_CERTIFICATE_ERROR
	ASL_PKCS11_ERROR        = C.ASL_PKCS11_ERROR
	ASL_CONN_CLOSED         = C.ASL_CONN_CLOSED
	ASL_WANT_READ           = C.ASL_WANT_READ
	ASL_WANT_WRITE          = C.ASL_WANT_WRITE
	ASL_PSK_ERROR           = C.ASL_PSK_ERROR
	ASL_NO_PEER_CERTIFICATE = C.ASL_NO_PEER_CERTIFICATE
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
	Key                  string
	Identity             string
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

type RootCertificates struct {
	Paths  []string
	buffer []byte
}

type PrivateKey struct {
	Path   string
	buffer []byte
	// only if the keys are in separate files
	AdditionalKeyPath   string
	AdditionalKeyBuffer []byte
}

type CustomLogCallback C.asl_log_callback_t

type EndpointConfig struct {
	MutualAuthentication   bool
	ASLKeyExchangeMethod   ASLKeyExchangeMethod
	Ciphersuites           []string
	PKCS11                 PKCS11ASL
	PreSharedKey           PreSharedKey
	DeviceCertificateChain DeviceCertificateChain
	PrivateKey             PrivateKey
	RootCertificates       RootCertificates
	KeylogFile             string
}

func (ec *EndpointConfig) toC() *C.asl_endpoint_configuration {
	config := C.asl_endpoint_configuration{
		mutual_authentication: C.bool(ec.MutualAuthentication),
		key_exchange_method:   C.enum_asl_key_exchange_method(ec.ASLKeyExchangeMethod),
		keylog_file:           C.CString(ec.KeylogFile),
	}

	// Ciphersuites
	if len(ec.Ciphersuites) > 0 {
		suites := ec.Ciphersuites[0]
		// Concatenate the strings into a single string, separated by a colon
		for i := 1; i < len(ec.Ciphersuites); i++ {
			suites += ":" + ec.Ciphersuites[i]
		}
		config.ciphersuites = C.CString(suites)
	} else {
		config.ciphersuites = nil
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
	config.psk.enable_cert_auth = C.bool(ec.PreSharedKey.EnableCertAuth)
	config.psk.callback_ctx = ec.PreSharedKey.CallbackContext
	config.psk.psk_client_cb = (C.asl_psk_client_callback_t)(ec.PreSharedKey.ClientCallback)
	config.psk.psk_server_cb = (C.asl_psk_server_callback_t)(ec.PreSharedKey.ServerCallback)

	if ec.PreSharedKey.Key != "" {
		config.psk.key = C.CString(ec.PreSharedKey.Key)
	}
	if ec.PreSharedKey.Identity != "" {
		config.psk.identity = C.CString(ec.PreSharedKey.Identity)
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
	if ec.PrivateKey.AdditionalKeyPath != "" {
		additionalKey, err := os.ReadFile(ec.PrivateKey.AdditionalKeyPath)
		if err != nil {
			panic(err)
		}
		ec.PrivateKey.AdditionalKeyBuffer = additionalKey
	}

	// read the root certificate from file
	if len(ec.RootCertificates.Paths) > 0 && ec.RootCertificates.Paths[0] != "" {
		// Read the first root certificate
		rootCert, err := os.ReadFile(ec.RootCertificates.Paths[0])
		if err != nil {
			panic(err)
		}
		for i := 1; i < len(ec.RootCertificates.Paths); i++ {
			if ec.RootCertificates.Paths[i] != "" {

				// Read the next root certificate
				nextRootCert, err := os.ReadFile(ec.RootCertificates.Paths[i])
				if err != nil {
					panic(err)
				}
				rootCert = append(rootCert, nextRootCert...)
			}
		}
		ec.RootCertificates.buffer = rootCert
	}

	// Allocate and set the device certificate chain
	config.device_certificate_chain.buffer = (*C.uint8_t)(C.CBytes(ec.DeviceCertificateChain.buffer))
	config.device_certificate_chain.size = C.size_t(len(ec.DeviceCertificateChain.buffer))

	// Allocate and set the private key
	config.private_key.buffer = (*C.uint8_t)(C.CBytes(ec.PrivateKey.buffer))
	config.private_key.size = C.size_t(len(ec.PrivateKey.buffer))
	if ec.PrivateKey.AdditionalKeyBuffer != nil {
		config.private_key.additional_key_buffer = (*C.uint8_t)(C.CBytes(ec.PrivateKey.AdditionalKeyBuffer))
		config.private_key.additional_key_size = C.size_t(len(ec.PrivateKey.AdditionalKeyBuffer))
	}

	// Allocate and set the root certificate
	config.root_certificate.buffer = (*C.uint8_t)(C.CBytes(ec.RootCertificates.buffer))
	config.root_certificate.size = C.size_t(len(ec.RootCertificates.buffer))

	return &config
}

func FreeEndpointConfiguration(cfg *C.asl_endpoint_configuration) {
	if cfg.device_certificate_chain.buffer != nil {
		C.free(unsafe.Pointer(cfg.device_certificate_chain.buffer))
	}
	if cfg.private_key.buffer != nil {
		C.free(unsafe.Pointer(cfg.private_key.buffer))
	}
	if cfg.private_key.additional_key_buffer != nil {
		C.free(unsafe.Pointer(cfg.private_key.additional_key_buffer))
	}
	if cfg.root_certificate.buffer != nil {
		C.free(unsafe.Pointer(cfg.root_certificate.buffer))
	}
	if cfg.ciphersuites != nil {
		C.free(unsafe.Pointer(cfg.ciphersuites))
	}
	if cfg.keylog_file != nil {
		C.free(unsafe.Pointer(cfg.keylog_file))
	}
	if cfg.pkcs11.module_path != nil {
		C.free(unsafe.Pointer(cfg.pkcs11.module_path))
	}
	if cfg.pkcs11.module_pin != nil {
		C.free(unsafe.Pointer(cfg.pkcs11.module_pin))
	}
	if cfg.psk.key != nil {
		C.free(unsafe.Pointer(cfg.psk.key))
	}
	if cfg.psk.identity != nil {
		C.free(unsafe.Pointer(cfg.psk.identity))
	}
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
		return fmt.Errorf("failed to initialize ASL: %s", ASLErrorMessage(ret))
	}
	return nil
}

func ASLsetupServerEndpoint(config *EndpointConfig) *ASLEndpoint {
	cfg := config.toC()
	defer FreeEndpointConfiguration(cfg)
	return (*ASLEndpoint)(C.asl_setup_server_endpoint(cfg))
}

func ASLsetupClientEndpoint(config *EndpointConfig) *ASLEndpoint {
	cfg := config.toC()
	defer FreeEndpointConfiguration(cfg)
	return (*ASLEndpoint)(C.asl_setup_client_endpoint(cfg))
}

func ASLCreateSession(endpoint *ASLEndpoint, fileDescriptor int) *ASLSession {
	return (*ASLSession)(C.asl_create_session((*C.asl_endpoint)(endpoint), C.int(fileDescriptor)))
}

func ASLHandshake(session *ASLSession) error {
	ret := int(C.asl_handshake((*C.asl_session)(session)))
	if ret != ASL_SUCCESS {
		return fmt.Errorf("failed to handshake: %s", ASLErrorMessage(ret))
	}
	return nil
}

func ASLReceive(session *ASLSession, buffer []byte) (int, error) {
	ret := int(C.asl_receive((*C.asl_session)(session), (*C.uint8_t)(&buffer[0]), C.int(len(buffer))))
	if ret == ASL_WANT_READ {
		// This is not an error, just a signal that we need to read more data
		return 0, nil
	} else if ret < 0 {
		return 0, fmt.Errorf("failed to receive: %s", ASLErrorMessage(ret))
	}
	return ret, nil
}

func ASLSend(session *ASLSession, buffer []byte) error {
	ret := int(C.asl_send((*C.asl_session)(session), (*C.uint8_t)(&buffer[0]), C.int(len(buffer))))
	if ret == ASL_WANT_WRITE {
		// This is not an error, just a signal that we need to write more data
		return nil
	} else if ret != ASL_SUCCESS {
		return fmt.Errorf("failed to send: %s", ASLErrorMessage(ret))
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
		return nil, fmt.Errorf("failed to get peer certificate: %s", ASLErrorMessage(int(ret)))
	}

	certBuffer = certBuffer[:certSize]

	certX509, err := x509.ParseCertificate(certBuffer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer certificate: %s", err)
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

func ASLshutdown() {
	C.asl_cleanup()
}
