package msspi

/*
#cgo windows LDFLAGS: -Lmsspi/build_linux -lmsspi -lstdc++ -lcrypt32 -static-libgcc -static -lpthread
#cgo linux LDFLAGS: -Lmsspi/build_linux -lmsspi-capix -lstdc++ -ldl
#cgo darwin LDFLAGS: -Lmsspi/build_linux -lmsspi-capix -lstdc++ -ldl
#include "msspi/src/msspi.h"
extern int cgo_msspi_read_cb( void * goPointer, void * buf, int len );
extern int cgo_msspi_write_cb( void * goPointer, void * buf, int len );
extern int cgo_msspi_cert_cb( void * goPointer );
MSSPI_HANDLE cgo_msspi_open( void * goPointer ) {
	return msspi_open( goPointer, (msspi_read_cb)cgo_msspi_read_cb, (msspi_write_cb)cgo_msspi_write_cb );
}
void cgo_msspi_set_cert_cb( MSSPI_HANDLE h ) {
	msspi_set_cert_cb( h, (msspi_cert_cb)cgo_msspi_cert_cb );
}
*/
import "C"

import (
	"bytes"
	"errors"
	"net"
	"runtime"
	"time"
	"unsafe"

	"go-pointer"
)

// closeNotifyTimeout bounds the close_notify send during shutdown, matching
// crypto/tls.Conn.closeNotify which wraps it in a 5s write deadline so a stuck
// peer cannot block Close/CloseWrite forever.
const closeNotifyTimeout = 5 * time.Second

// Conn is a TLS connection whose handshake and record protection are handled by
// msspi (CryptoPro CSP), supporting GOST as well as foreign algorithms.
type Conn struct {
	conn      *net.Conn
	handle    C.MSSPI_HANDLE
	rerr      error
	werr      error
	isClient  bool
	goPointer unsafe.Pointer

	// clientCert is presented only from cgo_msspi_cert_cb, i.e. after verify has
	// accepted the server, so the client identity is never sent to a server that
	// fails verification. verify performs the peer check (provided by crypto/tls);
	// it is invoked during the handshake on MSSPI_X509_LOOKUP (mutual TLS).
	clientCert []byte
	verify     func() error
}

func (c *Conn) Read(b []byte) (int, error) {
	if c == nil || c.handle == nil {
		return 0, net.ErrClosed
	}
	n := (int)(C.msspi_read(c.handle, unsafe.Pointer(&b[0]), C.int(len(b))))
	return n, c.rerr
}

func (c *Conn) State(val int) bool {
	if c == nil || c.handle == nil {
		return false
	}
	state := C.msspi_state(c.handle)
	if val == 1 {
		return state&C.MSSPI_ERROR != 0
	}
	if val == 2 {
		return state&(C.MSSPI_SENT_SHUTDOWN|C.MSSPI_RECEIVED_SHUTDOWN) != 0
	}
	return false
}

func (c *Conn) Write(b []byte) (int, error) {
	if c == nil || c.handle == nil {
		return 0, net.ErrClosed
	}
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

func (c *Conn) VersionTLS() uint16 {
	if c == nil || c.handle == nil {
		return 0
	}
	var info *C.SecPkgContext_CipherInfo
	if C.msspi_get_cipherinfo(c.handle, &info) != 1 || info == nil {
		return 0
	}
	return uint16(info.dwProtocol)
}

func (c *Conn) CipherSuite() uint16 {
	if c == nil || c.handle == nil {
		return 0
	}
	var info *C.SecPkgContext_CipherInfo
	if C.msspi_get_cipherinfo(c.handle, &info) != 1 || info == nil {
		return 0
	}
	return uint16(info.dwCipherSuite)
}

func (c *Conn) ClientProtocol() string {
	if c == nil || c.handle == nil {
		return ""
	}
	var alpn *C.uint8_t
	var alpnLen C.size_t
	if C.msspi_get_alpn(c.handle, &alpn, &alpnLen) != 1 || alpn == nil {
		return ""
	}
	return C.GoStringN((*C.char)(unsafe.Pointer(alpn)), C.int(alpnLen))
}

func (c *Conn) PeerCertificates() (certificates [][]byte) {
	if c == nil || c.handle == nil {
		return nil
	}

	count := C.size_t(0)

	if C.msspi_get_peercerts(c.handle, nil, nil, &count) != 1 || count == 0 {
		return nil
	}

	gocount := int(count)
	bufs := make([]*C.uint8_t, count)
	lens := make([]C.size_t, count)

	if C.msspi_get_peercerts(c.handle, &bufs[0], &lens[0], &count) != 1 {
		return nil
	}

	for i := 0; i < gocount; i++ {
		certificates = append(certificates, C.GoBytes(unsafe.Pointer(bufs[i]), C.int(lens[i])))
	}

	return certificates
}

// VerifyStatus runs CSP certificate-chain verification and returns its result
// code (0 == verified). ok is false if verification could not be run at all.
func (c *Conn) VerifyStatus() (status uint32, ok bool) {
	if c == nil || c.handle == nil {
		return 0, false
	}
	var s C.uint32_t
	if C.msspi_get_verify_status(c.handle, &s) != 1 {
		return 0, false
	}
	return uint32(s), true
}

// PeerChain returns the peer certificate chain (leaf first) built by the CSP,
// independent of the verification verdict.
func (c *Conn) PeerChain() (certificates [][]byte) {
	if c == nil || c.handle == nil {
		return nil
	}

	count := C.size_t(0)

	if C.msspi_get_peerchain(c.handle, nil, nil, &count) != 1 || count == 0 {
		return nil
	}

	gocount := int(count)
	bufs := make([]*C.uint8_t, count)
	lens := make([]C.size_t, count)

	if C.msspi_get_peerchain(c.handle, &bufs[0], &lens[0], &count) != 1 {
		return nil
	}

	for i := 0; i < gocount; i++ {
		certificates = append(certificates, C.GoBytes(unsafe.Pointer(bufs[i]), C.int(lens[i])))
	}

	return certificates
}

func (c *Conn) Handshake() error {
	if c == nil || c.handle == nil {
		return net.ErrClosed
	}
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
func (c *Conn) Close() (err error) {
	if c == nil {
		return net.ErrClosed
	}
	if c.handle != nil {
		// Bound the close_notify send like crypto/tls; the transport is closed
		// right after, so the deadline does not need restoring.
		(*c.conn).SetWriteDeadline(time.Now().Add(closeNotifyTimeout))
		C.msspi_shutdown(c.handle)
	}

	if c.goPointer != nil {
		pointer.Unref(c.goPointer)
		c.goPointer = nil
	}

	return (*c.conn).Close()
}

// Shutdown with MSSPI
func (c *Conn) Shutdown() (err error) {
	if c == nil {
		return net.ErrClosed
	}
	if c.handle != nil {
		// Half-close (CloseWrite): bound the close_notify send, then forbid any
		// further writes, exactly as crypto/tls.Conn.closeNotify does.
		(*c.conn).SetWriteDeadline(time.Now().Add(closeNotifyTimeout))
		C.msspi_shutdown(c.handle)
		(*c.conn).SetWriteDeadline(time.Now())
	}

	if !c.State(1) && c.State(2) {
		return nil
	}

	return net.ErrClosed
}

// Finalizer with MSSPI
func (c *Conn) Finalizer() {
	if c.handle != nil {
		C.msspi_close(c.handle)
		c.handle = nil
	}
}

// SetNextProtos with MSSPI
func (c *Conn) SetNextProtos(NextProtos []string) error {

	// https://github.com/golang/go/blob/dc00dc6c6bf3b5554e37f60799aec092276ff807/src/crypto/tls/handshake_client.go#L43-L53
	nextProtosLength := 0
	for _, proto := range NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}
	if nextProtosLength > 0xffff {
		return errors.New("tls: NextProtos values too large")
	}
	if nextProtosLength == 0 || c == nil || c.handle == nil {
		return nil
	}

	var alpns bytes.Buffer
	for _, proto := range NextProtos {
		alpns.WriteByte(byte(len(proto)))
		alpns.WriteString(proto)
	}

	C.msspi_set_alpn(c.handle, (*C.uint8_t)(unsafe.Pointer(&alpns.Bytes()[0])), C.size_t(alpns.Len()))
	return nil
}

// addMyCert presents the deferred client certificate. It is called from
// cgo_msspi_cert_cb after the server has been accepted by verify.
func (c *Conn) addMyCert() {
	if c == nil || c.handle == nil || c.clientCert == nil {
		return
	}
	C.msspi_add_mycert(c.handle, (*C.uint8_t)(unsafe.Pointer(&c.clientCert[0])), C.size_t(len(c.clientCert)))
}

// Client with MSSPI. verify, if non-nil, checks the server certificate; it is
// run during the handshake before the client certificate (if any) is presented,
// so a client never reveals its identity to a server it does not trust.
func Client(conn *net.Conn, CertificateBytes [][]byte, hostname string, verify func() error) (c *Conn, err error) {
	c = &Conn{conn: conn, isClient: true, verify: verify}
	runtime.SetFinalizer(c, (*Conn).Finalizer)

	c.goPointer = pointer.Save(c)
	c.handle = C.cgo_msspi_open(c.goPointer)

	if c.handle == nil {
		return nil, errors.New("Client msspi_open() failed")
	}

	C.msspi_set_client(c.handle, 1)

	if hostname != "" {
		hostnameBytes := []byte(hostname)
		C.msspi_set_hostname(c.handle, (*C.uint8_t)(unsafe.Pointer(&hostnameBytes[0])), C.size_t(len(hostnameBytes)))
	}

	// Defer the client certificate: it is added from cgo_msspi_cert_cb once the
	// server has been verified. Leaving the credential without a certificate is
	// what makes SChannel surface MSSPI_X509_LOOKUP (and thus call cert_cb) when
	// the server requests one.
	for _, cbs := range CertificateBytes {
		c.clientCert = cbs
		break // only 1 cert for client
	}

	C.cgo_msspi_set_cert_cb(c.handle)

	return c, nil
}

// Server with MSSPI
func Server(conn *net.Conn, CertificateBytes [][]byte, clientAuth bool) (c *Conn, err error) {
	c = &Conn{conn: conn, isClient: false}
	runtime.SetFinalizer(c, (*Conn).Finalizer)

	c.goPointer = pointer.Save(c)
	c.handle = C.cgo_msspi_open(c.goPointer)

	if c.handle == nil {
		return nil, errors.New("Server msspi_open() failed")
	}

	if clientAuth {
		C.msspi_set_peerauth(c.handle, 1)
	}

	srv := []byte("srv")
	C.msspi_set_hostname(c.handle, (*C.uint8_t)(unsafe.Pointer(&srv[0])), C.size_t(len(srv)))

	for _, cbs := range CertificateBytes {
		ok := int(C.msspi_add_mycert(c.handle, (*C.uint8_t)(unsafe.Pointer(&cbs[0])), C.size_t(len(cbs))))
		if ok != 1 {
			return nil, errors.New("Server msspi_add_mycert() failed")
		}
	}

	return c, nil
}
