package wolfSSL

// #cgo pkg-config: --static kritis3m
// #include <wolfssl/options.h>
// #include <wolfssl/ssl.h>
import "C"
import (
	"fmt"
	"log"
	"unsafe"
)

type WOLFSSL_CTX C.struct_WOLFSSL_CTX
type WOLFSSL C.struct_WOLFSSL

type METHOD C.struct_WOLFSSL_METHOD
type Method struct {
	Name string
}

const SSL_FILETYPE_PEM = 1
const WOLFSSL_SUCCESS = 1

func WolfSSL_ERR_print(ssl *WOLFSSL, ret int) {
	WolfSSL_get_error(ssl, ret)
	message := make([]byte, 64)
	WolfSSL_ERR_error_string(ret, message)
	log.Println("WolfSSL Error:", string(message))
}

func WolfSSL_get_error(ssl *WOLFSSL, ret int) int {
	return int(C.wolfSSL_get_error((*C.struct_WOLFSSL)(ssl), C.int(ret)))
}

func WolfSSL_ERR_error_string(ret int, data []byte) string {
	return C.GoString(C.wolfSSL_ERR_error_string(C.ulong(ret), (*C.char)(unsafe.Pointer(&data[0]))))
}

func WolfSSL_Init() {
	C.wolfSSL_Init()
}

func WolfSSL_Debugging_ON() {
	C.wolfSSL_Debugging_ON()
}

func WolfSSL_Cleanup() {
	C.wolfSSL_Cleanup()
}

func WolfSSL_CTX_new(method *C.struct_WOLFSSL_METHOD) *C.struct_WOLFSSL_CTX {
	return C.wolfSSL_CTX_new(method)
}

func WolfSSL_CTX_free(ctx *WOLFSSL_CTX) {
	C.wolfSSL_CTX_free((*C.struct_WOLFSSL_CTX)(ctx))
}

func WolfSSL_CTX_set_cipher_list(ctx *C.struct_WOLFSSL_CTX, list string) int {
	c_list := C.CString(list)
	defer C.free(unsafe.Pointer(c_list))
	return int(C.wolfSSL_CTX_set_cipher_list(ctx, c_list))
}

func WolfSSL_new(ctx *WOLFSSL_CTX) *WOLFSSL {
	return (*WOLFSSL)(C.wolfSSL_new((*C.struct_WOLFSSL_CTX)(ctx)))
}

func WolfSSL_connect(ssl *C.struct_WOLFSSL) int {
	return int(C.wolfSSL_connect(ssl))
}

func WolfSSL_shutdown(ssl *WOLFSSL) {
	C.wolfSSL_shutdown((*C.struct_WOLFSSL)(ssl))
}

func WolfSSL_free(ssl *WOLFSSL) {
	C.wolfSSL_free((*C.struct_WOLFSSL)(ssl))
}

func WolfTLSv1_2_server_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfTLSv1_2_server_method()
}

func WolfTLSv1_2_client_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfTLSv1_2_client_method()
}

func WolfTLSv1_3_server_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfTLSv1_3_server_method()
}

func WolfTLSv1_3_client_method() *C.struct_WOLFSSL_METHOD {
	return C.wolfTLSv1_3_client_method()
}

func WolfSSL_CTX_load_verify_locations(ctx *C.struct_WOLFSSL_CTX, cert string,
	path []byte) int {
	cert_file := C.CString(cert)
	defer C.free(unsafe.Pointer(cert_file))
	/* TODO: HANDLE NON NIL PATH */
	return int(C.wolfSSL_CTX_load_verify_locations(ctx, cert_file,
		(*C.char)(unsafe.Pointer(nil))))
}

func WolfSSL_CTX_use_certificate_file(ctx *C.struct_WOLFSSL_CTX, cert string,
	format int) int {
	cert_file := C.CString(cert)
	defer C.free(unsafe.Pointer(cert_file))
	return int(C.wolfSSL_CTX_use_certificate_file(ctx, cert_file, C.int(format)))
}

func WolfSSL_CTX_use_PrivateKey_file(ctx *C.struct_WOLFSSL_CTX, key string,
	format int) int {
	key_file := C.CString(key)
	defer C.free(unsafe.Pointer(key_file))
	return int(C.wolfSSL_CTX_use_PrivateKey_file(ctx, key_file, C.int(format)))
}

func WolfSSL_set_fd(ssl *WOLFSSL, fd int) error {
	ret := int(C.wolfSSL_set_fd((*C.struct_WOLFSSL)(ssl), C.int(fd)))
	if ret != WOLFSSL_SUCCESS {
		WolfSSL_ERR_print(ssl, ret)
		return fmt.Errorf("Failed to set file descriptor")
	}
	return nil
}

func WolfSSL_accept(ssl *WOLFSSL) int {
	return int(C.wolfSSL_accept((*C.struct_WOLFSSL)(ssl)))
}

func WolfSSL_read(ssl *WOLFSSL, data []byte, sz uintptr) int {
	return int(C.wolfSSL_read((*C.struct_WOLFSSL)(ssl), unsafe.Pointer(&data[0]), C.int(sz)))
}

func WolfSSL_write(ssl *WOLFSSL, data []byte, sz uintptr) int {
	return int(C.wolfSSL_write((*C.struct_WOLFSSL)(ssl), unsafe.Pointer(&data[0]), C.int(sz)))
}

func WolfSSL_get_cipher_name(ssl *C.struct_WOLFSSL) string {
	return C.GoString(C.wolfSSL_get_cipher_name(ssl))
}

func WolfSSL_get_version(ssl *C.struct_WOLFSSL) string {
	return C.GoString(C.wolfSSL_get_version(ssl))
}

func WolfSSL_lib_version() string {
	return C.GoString(C.wolfSSL_lib_version())
}

func InitWolfSSL(certFile, keyFile string, debug bool, method Method) *WOLFSSL_CTX {
	WolfSSL_Init()
	if debug {
		WolfSSL_Debugging_ON()
	}

	var ctx *C.struct_WOLFSSL_CTX
	switch method.Name {
	case "TLSv1.2":
		fmt.Println("TLSv1.2")
		ctx = WolfSSL_CTX_new(WolfTLSv1_2_server_method())
		if ctx == nil {
			log.Fatal("Failed to create WolfSSL context")
		}
	case "TLSv1.3":
		fmt.Println("TLSv1.3")
		ctx = WolfSSL_CTX_new(WolfTLSv1_3_server_method())
		if ctx == nil {
			log.Fatal("Failed to create WolfSSL context")
		}
	default:
		log.Fatal("Invalid method")
	}

	if WolfSSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) != 1 {
		log.Fatal("Failed to load server certificate")
	}
	if WolfSSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) != 1 {
		log.Fatal("Failed to load server private key")
	}

	WolfSSL_set_callbaks((*WOLFSSL_CTX)(ctx))

	return (*WOLFSSL_CTX)(ctx)
}
