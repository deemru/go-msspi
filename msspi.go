package msspi

/*
#cgo windows LDFLAGS: -Lmsspi/build_linux -lmsspi -lstdc++ -lcrypt32
#cgo linux LDFLAGS: -Lmsspi/build_linux -lmsspi-capix -lstdc++ -ldl
#include "msspi/src/msspi.h"
extern int cgo_msspi_read( void * goPointer, void * buf, int len );
extern int cgo_msspi_write( void * goPointer, void * buf, int len );
MSSPI_HANDLE cgo_msspi_open( void * goPointer ) {
	return msspi_open( goPointer, (msspi_read_cb)cgo_msspi_read, (msspi_write_cb)cgo_msspi_write );
}
*/
import "C"

import (
	"crypto/tls"
	"io"
	"net"
	"runtime"
	"sync"
	"unsafe"

	"github.com/mattn/go-pointer"
)

// Conn with MSSPI
type Conn struct {
	conn net.Conn
	tls  *tls.Conn
	// MSSPI
	handle    C.MSSPI_HANDLE
	rerr      error
	werr      error
	isClient  bool
	goPointer unsafe.Pointer
	mu        sync.Mutex
}

func (c *Conn) error() (err error) {
	state := C.msspi_state(c.handle)
	if state&C.MSSPI_ERROR != 0 || state&(C.MSSPI_SENT_SHUTDOWN|C.MSSPI_RECEIVED_SHUTDOWN) != 0 {
		err = io.EOF
	}
	return nil
}

func (c *Conn) Read(b []byte) (int, error) {
	n := (int)(C.msspi_read(c.handle, unsafe.Pointer(&b[0]), C.int(len(b))))
	if n > 0 {
		return n, nil
	}
	return 0, c.error()
}

func (c *Conn) Write(b []byte) (int, error) {
	len := len(b)
	sent := 0
	for len > 0 {
		n := int(C.msspi_write(c.handle, unsafe.Pointer(&b[sent]), C.int(len)))
		if n > 0 {
			sent += n
			len -= n
			continue
		}

		return sent, c.error()
	}
	return sent, nil
}

// Close with MSSPI
func (c *Conn) Close() (err error) {
	if c.handle != nil {
		C.msspi_shutdown(c.handle)
		pointer.Unref(c.goPointer)
	}
	return c.conn.Close()
}

// Finalizer with MSSPI
func (c *Conn) Finalizer() {
	if c.handle != nil {
		C.msspi_close(c.handle)
	}
}

// Client with MSSPI
func Client(conn net.Conn, config *tls.Config) *Conn {
	c := &Conn{conn: conn, isClient: true}
	c.tls = tls.Client(conn, config)

	c.goPointer = pointer.Save(c)
	c.handle = C.cgo_msspi_open(c.goPointer)

	if c.handle != nil {
		C.msspi_set_client(c.handle)
		runtime.SetFinalizer(c, (*Conn).Finalizer)
	} else {
		pointer.Unref(c.goPointer)
	}
	return c
}

// Server with MSSPI (not implemented)
func Server(conn net.Conn, config *tls.Config) *Conn {
	c := &Conn{conn: conn, isClient: false}
	c.tls = tls.Server(conn, config)
	return nil
}
