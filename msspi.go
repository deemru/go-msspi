package msspi

/*
#cgo windows LDFLAGS: -Lmsspi/build_linux -lmsspi -lstdc++ -lcrypt32
#cgo linux LDFLAGS: -Lmsspi/build_linux -lmsspi-capix -lstdc++ -ldl
#define NO_MSSPI_CERT
#include "msspi/src/msspi.h"
extern int cgo_msspi_read( void * goPointer, void * buf, int len );
extern int cgo_msspi_write( void * goPointer, void * buf, int len );
MSSPI_HANDLE cgo_msspi_open( void * goPointer ) {
	return msspi_open( goPointer, (msspi_read_cb)cgo_msspi_read, (msspi_write_cb)cgo_msspi_write );
}
*/
import "C"

import (
	"errors"
	"net"
	"runtime"
	"unsafe"

	"go-pointer"
)

const ByDefault = true

//const ByDefault = false

// Conn with MSSPI
type Handler struct {
	conn      *net.Conn
	handle    C.MSSPI_HANDLE
	rerr      error
	werr      error
	isClient  bool
	goPointer unsafe.Pointer
}

func (c *Handler) Read(b []byte) (int, error) {
	n := (int)(C.msspi_read(c.handle, unsafe.Pointer(&b[0]), C.int(len(b))))
	return n, c.rerr
}

func (c *Handler) State(val int) bool {
	state := C.msspi_state(c.handle)
	if val == 1 {
		return state&C.MSSPI_ERROR != 0
	}
	if val == 2 {
		return state&(C.MSSPI_SENT_SHUTDOWN|C.MSSPI_RECEIVED_SHUTDOWN) != 0
	}
	return false
}

func (c *Handler) Write(b []byte) (int, error) {
	len := len(b)
	sent := 0
	for len > 0 {
		n := int(C.msspi_write(c.handle, unsafe.Pointer(&b[sent]), C.int(len)))
		if n > 0 {
			sent += n
			len -= n
			continue
		}

		break
	}

	return sent, c.werr
}

func (h *Handler) VersionTLS() uint16 {
	info := C.msspi_get_cipherinfo(h.handle)
	return uint16(info.dwProtocol)
}

func (h *Handler) CipherSuite() uint16 {
	info := C.msspi_get_cipherinfo(h.handle)
	return uint16(info.dwCipherSuite)
}

func (c *Handler) PeerCertificates() (certificates [][]byte) {
	count := C.size_t(0)

	if 0 == C.msspi_get_peercerts(c.handle, nil, nil, &count) {
		return nil
	}

	gocount := int(count)
	bufs := make([]*C.char, count)
	lens := make([]C.int, count)

	if 0 == C.msspi_get_peercerts(c.handle, &bufs[0], &lens[0], &count) {
		return nil
	}

	for i := 0; i < gocount; i++ {
		certificates = append(certificates, C.GoBytes(unsafe.Pointer(bufs[i]), lens[i]))
	}

	return certificates
}

func (c *Handler) VerifiedChains() (certificates [][]byte) {
	if C.MSSPI_VERIFY_OK != C.msspi_verify(c.handle) {
		return nil
	}

	count := C.size_t(0)

	if 0 == C.msspi_get_peerchain(c.handle, 0, nil, nil, &count) {
		return nil
	}

	gocount := int(count)
	bufs := make([]*C.char, count)
	lens := make([]C.int, count)

	if 0 == C.msspi_get_peerchain(c.handle, 0, &bufs[0], &lens[0], &count) {
		return nil
	}

	for i := 0; i < gocount; i++ {
		certificates = append(certificates, C.GoBytes(unsafe.Pointer(bufs[i]), lens[i]))
	}

	return certificates
}

func (c *Handler) Handshake() error {
	n := -1
	for n < 0 {
		if c.isClient {
			n = (int)(C.msspi_connect(c.handle))
		} else {
			n = (int)(C.msspi_accept(c.handle))
		}
	}

	if n == 1 {
		return nil
	}

	if c.rerr != nil {
		return c.rerr
	}
	if c.werr != nil {
		return c.werr
	}
	return net.ErrClosed
}

// Close with MSSPI
func (c *Handler) Close() (err error) {
	if c.handle != nil {
		C.msspi_shutdown(c.handle)
	}

	if c.goPointer != nil {
		pointer.Unref(c.goPointer)
		c.goPointer = nil
	}

	return (*c.conn).Close()
}

// Shutdown with MSSPI
func (c *Handler) Shutdown() (err error) {
	if c.handle != nil {
		C.msspi_shutdown(c.handle)
	}

	if !c.State(1) && c.State(2) {
		return nil
	}

	return net.ErrClosed
}

// Finalizer with MSSPI
func (c *Handler) Finalizer() {
	if c.handle != nil {
		C.msspi_close(c.handle)
		c.handle = nil
	}
}

// Client with MSSPI
func Client(conn *net.Conn, CertificateBytes [][]byte, hostname string) (c *Handler, err error) {
	c = &Handler{conn: conn, isClient: true}
	runtime.SetFinalizer(c, (*Handler).Finalizer)

	c.goPointer = pointer.Save(c)
	c.handle = C.cgo_msspi_open(c.goPointer)

	if c.handle == nil {
		return nil, errors.New("Client msspi_open() failed")
	}

	C.msspi_set_client(c.handle)

	if hostname != "" {
		hostnameBytes := []byte(hostname)
		hostnameBytes = append(hostnameBytes, 0)
		C.msspi_set_hostname(c.handle, (*C.char)(unsafe.Pointer(&hostnameBytes[0])))
	}

	for _, cbs := range CertificateBytes {
		ok := int(C.msspi_add_mycert(c.handle, (*C.char)(unsafe.Pointer(&cbs[0])), C.int(len(cbs))))
		if ok != 1 {
			return nil, errors.New("Client msspi_add_mycert() failed")
		}
		break
	}

	return c, nil
}

// Server with MSSPI
func Server(conn *net.Conn, CertificateBytes [][]byte, clientAuth bool) (c *Handler, err error) {
	c = &Handler{conn: conn, isClient: false}
	runtime.SetFinalizer(c, (*Handler).Finalizer)

	c.goPointer = pointer.Save(c)
	c.handle = C.cgo_msspi_open(c.goPointer)

	if c.handle == nil {
		return nil, errors.New("Server msspi_open() failed")
	}

	if clientAuth {
		C.msspi_set_peerauth(c.handle, 1)
	}

	srv := []byte("srv")
	C.msspi_set_hostname(c.handle, (*C.char)(unsafe.Pointer(&srv[0])))

	for _, cbs := range CertificateBytes {
		ok := int(C.msspi_add_mycert(c.handle, (*C.char)(unsafe.Pointer(&cbs[0])), C.int(len(cbs))))
		if ok != 1 {
			return nil, errors.New("Server msspi_add_mycert() failed")
		}
		break
	}

	return c, nil
}
