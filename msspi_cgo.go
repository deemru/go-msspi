package msspi

/*
#include <memory.h> // memcpy
int cgo_msspi_read( void * goPointer, void * buf, int len );
int cgo_msspi_write( void * goPointer, void * buf, int len );
*/
import "C"

import (
	"io"
	"os"
	"unsafe"

	"github.com/mattn/go-pointer"
)

//export cgo_msspi_read
func cgo_msspi_read(goPointer, buffer unsafe.Pointer, length C.int) C.int {
	c := pointer.Restore(goPointer).(*Conn)
	if c == nil {
		return 0
	}

	b := make([]byte, length)
	n, err := c.conn.Read(b)

	// Read can be made to time out and return a net.Error with Timeout() == true
	// after a fixed time limit; see SetDeadline and SetReadDeadline.

	if n > 0 {
		c.rerr = nil
		C.memcpy(buffer, unsafe.Pointer(&b[0]), C.size_t(n))
		b = C.GoBytes(buffer, C.int(n))
		return C.int(n)
	}

	// RFC 8446, Section 6.1 suggests that EOF without an alertCloseNotify
	// is an error, but popular web sites seem to do this, so we accept it
	// if and only if at the record boundary.
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	c.rerr = err
	if os.IsTimeout(err) {
		return -1
	}
	return 0
}

//export cgo_msspi_write
func cgo_msspi_write(goPointer, buffer unsafe.Pointer, length C.int) C.int {
	c := pointer.Restore(goPointer).(*Conn)
	if c == nil {
		return 0
	}

	b := C.GoBytes(buffer, length)
	n, err := c.conn.Write(b)

	if n > 0 {
		c.werr = nil
		return C.int(n)
	}

	// RFC 8446, Section 6.1 suggests that EOF without an alertCloseNotify
	// is an error, but popular web sites seem to do this, so we accept it
	// if and only if at the record boundary.
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	c.werr = err
	if os.IsTimeout(err) {
		return -1
	}
	return 0
}
