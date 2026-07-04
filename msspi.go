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
	"io"
	"net"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"go-pointer"
)

// closeNotifyTimeout bounds the close_notify send during shutdown, matching
// crypto/tls.Conn.closeNotify which wraps it in a 5s write deadline so a stuck
// peer cannot block Close/CloseWrite forever.
const closeNotifyTimeout = 5 * time.Second

// Keep this chunk aligned with MSSPI_BASE_BUFFER_SIZE in msspi.cpp.
const msspiBufferSize = 0x4800

// Conn is a TLS connection whose handshake and record protection are handled by
// msspi (CryptoPro CSP), supporting GOST as well as foreign algorithms.
type Conn struct {
	conn   *net.Conn
	handle C.MSSPI_HANDLE
	// mu serializes the C.msspi_* calls that drive the record/handshake state
	// machine. MSSPI callbacks run synchronously while mu is held, so callbacks
	// and code reachable from them must never lock mu. The msspi_get_* accessors
	// are intentionally lock-free so verify hooks can call them from callbacks.
	mu sync.Mutex
	// readMu preserves the single transport reader/inputBuf invariant while
	// mu is released for blocking socket reads. Lock order is readMu -> mu;
	// stepMSSPI always releases mu before calling readTransport.
	readMu sync.Mutex
	// input is filled by readTransport and drained by cgo_msspi_read_cb.
	input    []byte
	inputBuf [msspiBufferSize]byte
	// output is staged by cgo_msspi_write_cb and flushed by flushTransportLocked.
	output    []byte
	outputBuf [msspiBufferSize]byte
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
	if len(b) == 0 {
		return 0, nil
	}
	n, err := c.stepMSSPI(func() int {
		return int(C.msspi_read(c.handle, unsafe.Pointer(&b[0]), C.int(len(b))))
	})
	if n == 0 && err == nil {
		return 0, c.rerr
	}
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	if c == nil || c.handle == nil {
		return 0, net.ErrClosed
	}
	sent := 0
	for sent < len(b) {
		n, err := c.stepMSSPI(func() int {
			return int(C.msspi_write(c.handle, unsafe.Pointer(&b[sent]), C.int(len(b)-sent)))
		})
		if n > 0 {
			sent += n
		}
		if err != nil || n <= 0 {
			return sent, err
		}
	}
	return sent, c.werr
}

// stepMSSPI drives one MSSPI operation until it returns a non-negative result
// or a transport error. Blocking socket reads are performed outside mu; socket
// writes are flushed outside cgo callbacks by afterMSSPILocked.
func (c *Conn) stepMSSPI(op func() int) (int, error) {
	for {
		c.mu.Lock()
		n := op()
		needRead, err := c.afterMSSPILocked(n)
		c.mu.Unlock()

		if err != nil || n >= 0 {
			return n, err
		}
		if needRead {
			if err := c.readTransport(); err != nil {
				return 0, err
			}
		}
	}
}

// afterMSSPILocked runs under mu after every op(). It always flushes output
// staged by the write callback; a successful op can have produced a full TLS
// record. If the result was negative, it then reports whether stepMSSPI should
// re-drive MSSPI immediately (WANT_WRITE or already-staged input) or call
// readTransport to fetch more input bytes.
func (c *Conn) afterMSSPILocked(n int) (bool, error) {
	if err := c.flushTransportLocked(); err != nil {
		return false, err
	}
	if n >= 0 {
		return false, nil
	}
	state := C.msspi_state(c.handle)
	if state&C.MSSPI_WRITING != 0 && state&C.MSSPI_READING == 0 {
		return false, nil
	}
	if len(c.input) != 0 {
		return false, nil
	}
	return true, nil
}

// readTransport is the only place that blocks on transport reads. It holds
// readMu across the socket read so renegotiation cannot start two concurrent
// reads into inputBuf; it holds mu only while checking or publishing input.
func (c *Conn) readTransport() error {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	c.mu.Lock()
	if len(c.input) != 0 {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	n, err := (*c.conn).Read(c.inputBuf[:])

	c.mu.Lock()
	defer c.mu.Unlock()
	c.rerr = err
	if n > 0 {
		c.input = c.inputBuf[:n]
		return nil
	}
	if err != nil {
		return err
	}
	return io.ErrNoProgress
}

// flushTransportLocked writes outbound TLS record bytes staged by
// cgo_msspi_write_cb. The write is intentionally outside the cgo callback;
// blocking here parks a Go goroutine in netpoll instead of pinning an OS thread
// in cgo. It runs under mu, so backpressure stalls this Conn until the caller's
// write deadline.
func (c *Conn) flushTransportLocked() error {
	for len(c.output) != 0 {
		n, err := (*c.conn).Write(c.output)
		c.werr = err
		if n > 0 {
			c.output = c.output[n:]
			continue
		}
		if err != nil {
			return err
		}
		return io.ErrNoProgress
	}
	c.output = nil
	return nil
}

func (c *Conn) stateLocked(val int) bool {
	state := C.msspi_state(c.handle)
	if val == 1 {
		return state&C.MSSPI_ERROR != 0
	}
	if val == 2 {
		return state&(C.MSSPI_SENT_SHUTDOWN|C.MSSPI_RECEIVED_SHUTDOWN) != 0
	}
	return false
}

func (c *Conn) State(val int) bool {
	if c == nil || c.handle == nil {
		return false
	}
	// Do not call State from MSSPI callbacks or verify hooks: callbacks are
	// synchronous and run while mu is already held by stepMSSPI.
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stateLocked(val)
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
	n, err := c.stepMSSPI(func() int {
		if c.isClient {
			return int(C.msspi_connect(c.handle))
		}
		return int(C.msspi_accept(c.handle))
	})
	if err != nil {
		return err
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
		c.mu.Lock()
		C.msspi_shutdown(c.handle)
		if err = c.flushTransportLocked(); err != nil {
			c.mu.Unlock()
			return err
		}
		c.mu.Unlock()
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
		c.mu.Lock()
		C.msspi_shutdown(c.handle)
		if err = c.flushTransportLocked(); err != nil {
			c.mu.Unlock()
			return err
		}
		ok := !c.stateLocked(1) && c.stateLocked(2)
		c.mu.Unlock()
		(*c.conn).SetWriteDeadline(time.Now())
		if ok {
			return nil
		}
	}

	return net.ErrClosed
}

// Finalizer with MSSPI
func (c *Conn) Finalizer() {
	if c.handle != nil {
		c.mu.Lock()
		C.msspi_close(c.handle)
		c.handle = nil
		c.mu.Unlock()
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
