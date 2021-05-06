package lpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"sync"
	"time"

	"golang.org/x/xerrors"
)

var scCache sync.Map

func lookupCache(dnsName string) (scPair, bool) {
	if p, ok := scCache.Load(dnsName); ok {
		// TODO: 期限切れしそうであれば削除して新規作成させる
		return p.(scPair), true
	}
	return scPair{}, false
}

func lookupOrStoreCache(dnsName string, pair scPair) scPair {
	ac, _ := scCache.LoadOrStore(dnsName, pair)
	return ac.(scPair)
}

func ClearServerCertCache() {
	scCache.Range(func(key interface{}, _ interface{}) bool {
		scCache.Delete(key)
		return true
	})
}

type scPair struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func (c *CA) IssueServerCert(dnsName string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	if dnsName == "" {
		return nil, nil, xerrors.New("empty dns name given")
	}
	if p, ok := lookupCache(dnsName); ok {
		return p.key, p.cert, nil
	}

	dnsNames := []string{dnsName}

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to generate key: %w", err)
	}

	certTpl := x509.Certificate{
		SerialNumber: getSerial(),
		Subject: pkix.Name{
			CommonName:         dnsNames[0],
			OrganizationalUnit: []string{ou},
			Organization:       []string{org},
			Country:            []string{ctry},
		},
		NotAfter:    time.Now().Add(time.Hour * 24 * 10), // いったん 10 days
		NotBefore:   time.Now(),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &certTpl, c.Cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to create cert: %w", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		panic(fmt.Errorf("failed to parse generated certificate, something wrong: %w", err))
	}

	// 同時に証明書が発行されていたとしたら先に作成したほうを優先する
	p := lookupOrStoreCache(dnsName, scPair{key: key, cert: cert})
	return p.key, p.cert, nil
}
