package msspi

/*
#include <memory.h> // memcpy
int cgo_msspi_read_cb( void * goPointer, void * buf, int len );
int cgo_msspi_write_cb( void * goPointer, void * buf, int len );
int cgo_msspi_cert_cb( void * goPointer );
*/
import "C"

import (
	"unsafe"

	"go-pointer"
)

// MSSPI callbacks are synchronous: C calls them from inside C.msspi_* while
// Conn.mu is already held. They must not take Conn.mu and must not perform
// blocking socket I/O; they only drain/stage bounded Go buffers.

//export cgo_msspi_read_cb
func cgo_msspi_read_cb(goPointer, buffer unsafe.Pointer, length C.int) C.int {
	c := pointer.Restore(goPointer).(*Conn)
	if c == nil {
		return 0
	}

	inputLen := len(c.input)
	if inputLen == 0 {
		return -1
	}
	n := int(length)
	if n > inputLen {
		n = inputLen
	}
	if n > 0 {
		C.memcpy(buffer, unsafe.Pointer(&c.input[0]), C.size_t(n))
		if n == inputLen {
			c.input = nil
		} else {
			c.input = c.input[n:]
		}
		return C.int(n)
	}

	return -1
}

//export cgo_msspi_write_cb
func cgo_msspi_write_cb(goPointer, buffer unsafe.Pointer, length C.int) C.int {
	c := pointer.Restore(goPointer).(*Conn)
	if c == nil {
		return 0
	}

	n := int(length)
	if n > msspiBufferSize {
		n = msspiBufferSize
	}
	if n <= 0 {
		return 0
	}

	if len(c.output) != 0 {
		return -1
	}

	C.memcpy(unsafe.Pointer(&c.outputBuf[0]), buffer, C.size_t(n))
	c.output = c.outputBuf[:n]
	return C.int(n)
}

// cgo_msspi_cert_cb is invoked by msspi during the handshake when the peer
// (server) certificate is available and a client certificate is requested
// (MSSPI_X509_LOOKUP). It verifies the server first and only then presents the
// deferred client certificate; returning 0 aborts the handshake without ever
// sending the client certificate. The verify hook must not call methods that
// lock Conn.mu (for example State), because callbacks run while Conn.mu is held.
//
//export cgo_msspi_cert_cb
func cgo_msspi_cert_cb(goPointer unsafe.Pointer) C.int {
	c := pointer.Restore(goPointer).(*Conn)
	if c == nil {
		return 0
	}

	if c.verify != nil {
		if err := c.verify(); err != nil {
			return 0
		}
	}

	c.addMyCert()
	return 1
}
