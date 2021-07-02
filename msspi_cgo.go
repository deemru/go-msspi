package msspi

/*
#include <memory.h> // memcpy
int cgo_msspi_read( void * goPointer, void * buf, int len );
int cgo_msspi_write( void * goPointer, void * buf, int len );
*/
import "C"

import (
	"unsafe"

	"go-pointer"
)

//export cgo_msspi_read
func cgo_msspi_read(goPointer, buffer unsafe.Pointer, length C.int) C.int {
	c := pointer.Restore(goPointer).(*Handler)
	if c == nil {
		return 0
	}

	b := make([]byte, length)
	n, err := (*c.conn).Read(b)
	c.rerr = err

	if n > 0 {
		C.memcpy(buffer, unsafe.Pointer(&b[0]), C.size_t(n))
		b = C.GoBytes(buffer, C.int(n))
		return C.int(n)
	}

	return 0
}

//export cgo_msspi_write
func cgo_msspi_write(goPointer, buffer unsafe.Pointer, length C.int) C.int {
	c := pointer.Restore(goPointer).(*Handler)
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
