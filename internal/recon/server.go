/// recon は偽TLS証明書をオンデマンドで発行し TLS をしゃべる Listener / Conn 出せるやつ
package recon

import (
	"crypto/tls"
	"net"

	"github.com/nakanokurenai/uec-autologon/internal/lpki"
	"golang.org/x/xerrors"
)

const addr = "127.0.0.1:1081"

type TLSListener struct {
	ca lpki.CA

	// inner は TLS じゃないとダメ
	inner net.Listener
}

// Accept waits for and returns the next connection to the listener.
func (l *TLSListener) Accept() (net.Conn, error) {
	return l.inner.Accept()
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l *TLSListener) Close() error {
	return l.inner.Close()
}

// Addr returns the listener's network address.
func (l *TLSListener) Addr() net.Addr {
	return l.inner.Addr()
}

// Dial opens client-site connection to Listener self
func (l *TLSListener) Dial() (net.Conn, error) {
	return net.Dial("tcp", addr)
}

func New() (*TLSListener, error) {
	// github.com/akutz/memconn を使いたかったがうまく動かなかったので TCP でやっている
	// github.com/armon/go-socks5 ではどこかで TCPAddr を要求するコードがあって破滅
	// github.com/thinkgos/go-socks5 (Fork) だと動きそうだが curl で "Can't complete SOCKS5 connection to 0.0.0.0:0." のようなエラーが起きる
	// 接続先情報とかめちゃめちゃになっちゃうからかなあ…
	// net.Addr を fake したらいい感じかもしれん
	// FIXME: うまく閉じないといけない…
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, xerrors.Errorf("failed to listening tcp port: %w", err)
	}
	ca, err := lpki.LoadOrInitializeCA(".")
	if err != nil {
		return nil, xerrors.Errorf("failed to initialize ca: %w", err)
	}

	tl := TLSListener{
		ca: ca,
	}
	tl.inner = tls.NewListener(l, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			dnsName := hello.ServerName
			if dnsName == "" {
				return nil, xerrors.Errorf("sni only supported")
			}
			k, c, err := ca.IssueServerCert(dnsName)
			if err != nil {
				return nil, xerrors.Errorf("failed to issue certificate for %s: %w", dnsName, err)
			}
			return &tls.Certificate{
				Certificate: [][]byte{
					c.Raw,
					// CA 証明書を含むチェーンにしないといけないっぽい
					ca.Cert.Raw,
				},
				PrivateKey: k,
			}, nil
		},
	})

	return &tl, nil
}
