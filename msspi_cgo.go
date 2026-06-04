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

//export cgo_msspi_read_cb
func cgo_msspi_read_cb(goPointer, buffer unsafe.Pointer, length C.int) C.int {
	c := pointer.Restore(goPointer).(*Conn)
	if c == nil {
		return 0
	}

	b := make([]byte, length)
	n, err := (*c.conn).Read(b)
	c.rerr = err

	if n > 0 {
		C.memcpy(buffer, unsafe.Pointer(&b[0]), C.size_t(n))
		return C.int(n)
	}

	return 0
}

//export cgo_msspi_write_cb
func cgo_msspi_write_cb(goPointer, buffer unsafe.Pointer, length C.int) C.int {
	c := pointer.Restore(goPointer).(*Conn)
	if c == nil {
		return 0
	}

	b := C.GoBytes(buffer, length)
	n, err := (*c.conn).Write(b)
	c.werr = err

	if n > 0 {
		return C.int(n)
	}

	return 0
}

// cgo_msspi_cert_cb is invoked by msspi during the handshake when the peer
// (server) certificate is available and a client certificate is requested
// (MSSPI_X509_LOOKUP). It verifies the server first and only then presents the
// deferred client certificate; returning 0 aborts the handshake without ever
// sending the client certificate.
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
