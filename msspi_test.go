package msspi

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestMsspiClient(t *testing.T) {
	for i := 0; i < 2; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", "tls.cryptopro.ru", 443), 2*time.Second)
		if err != nil {
			t.Fatalf("Unexpected error on dial: %v", err)
		}
		defer conn.Close()

		var tlsConn net.Conn
		if i == 0 {
			// crypto/tls
			tlsConn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		} else {
			// github.com/deemru/go-msspi
			tlsConn = /*msspi.*/ Client(conn, &tls.Config{InsecureSkipVerify: true})
		}
		defer tlsConn.Close()

		wbuf := []byte("GET / HTTP/1.1\r\nHost: tls.cryptopro.ru\r\n\r\n")
		if wlen, err := tlsConn.Write(wbuf); wlen != len(wbuf) || err != nil {
			t.Fatalf("Error sending: %v", err)
		}

		rbuf := make([]byte, 16384)
		if rlen, err := tlsConn.Read(rbuf); rlen == 0 || err != nil {
			t.Fatalf("Error reading: %v", err)
		} else {
			s := string(rbuf[:rlen])
			ms := "ssl_cipher</td><td class=\"wr\"><b>"
			me := "</b>"
			c1 := strings.Index(s, ms)
			if c1 == -1 {
				t.Fatalf("Marker not found")
			}
			c2 := strings.Index(s[c1:], me)
			if c2 == -1 {
				t.Fatalf("Marker not found")
			}
			fmt.Printf("%v) Cipher: %v\n", i+1, string(rbuf[c1+len(ms):c1+c2]))
		}
	}
}
