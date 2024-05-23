package wolfSSL

/*
#cgo pkg-config: kritis3m
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include "callbacks/callbacks.h"
*/
import "C"

func WolfSSL_set_callbaks(ctx *WOLFSSL_CTX) {
	C.wolfSSL_CTX_SetIOSend((*C.struct_WOLFSSL_CTX)(ctx), (*[0]byte)(C.wolfssl_write_callback))
  C.wolfSSL_CTX_SetIORecv((*C.struct_WOLFSSL_CTX)(ctx), (*[0]byte)(C.wolfssl_read_callback))
}


