package lpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"
)

const (
	publicKeyFileName  = "cacert.der"
	privateKeyFileName = "cakey.der"

	ou   = "U-AULO"
	org  = "N Org"
	ctry = "JP"
)

type CA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

// 証明書が存在しなければ os.ErrNotExist を返します
func loadCA(dir string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	privDerFp, err := os.Open(filepath.Join(dir, privateKeyFileName))
	if err != nil {
		return nil, nil, xerrors.Errorf("no ca key: %w", err)
	}
	defer privDerFp.Close()
	privDer, err := ioutil.ReadAll(privDerFp)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to load ca key: %w", err)
	}
	pubDerFp, err := os.Open(filepath.Join(dir, publicKeyFileName))
	if err != nil {
		return nil, nil, xerrors.Errorf("no ca cert: %w", err)
	}
	defer pubDerFp.Close()
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to load ca cert: %w", err)
	}
	pubDer, err := ioutil.ReadAll(pubDerFp)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to load ca cert: %w", err)
	}

	priv, err := x509.ParseECPrivateKey(privDer)
	if err != nil {
		return nil, nil, xerrors.Errorf("invalid ca key: %w", err)
	}

	pub, err := x509.ParseCertificate(pubDer)
	if err != nil {
		return nil, nil, xerrors.Errorf("invalid ca cert: %w", err)
	}

	return priv, pub, nil
}

func initRootCA(dir string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to generate key: %w", err)
	}

	cert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			OrganizationalUnit: []string{ou},
			Organization:       []string{org},
			Country:            []string{ctry},
		},
		NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 10),
		NotBefore: time.Now(),

		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	finalCert, err := x509.CreateCertificate(rand.Reader, &cert, &cert, &key.PublicKey, key)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to create certificate: %w", err)
	}

	// write files
	privDerFp, err := os.OpenFile(filepath.Join(dir, privateKeyFileName), os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to open new ca key file: %w", err)
	}
	defer privDerFp.Close()
	privDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to marshal ca key: %w", err)
	}
	if _, err := privDerFp.Write(privDer); err != nil {
		return nil, nil, xerrors.Errorf("failed to write new ca key: %w", err)
	}

	pubDerFp, err := os.OpenFile(filepath.Join(dir, publicKeyFileName), os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to open new ca cert file: %w", err)
	}
	defer pubDerFp.Close()
	if _, err := pubDerFp.Write(finalCert); err != nil {
		return nil, nil, xerrors.Errorf("failed to write new ca cert: %w", err)
	}

	readCert, err := x509.ParseCertificate(finalCert)
	if err != nil {
		panic(fmt.Errorf("failed to parse generated certificate, something wrong: %w", err))
	}

	return key, readCert, nil
}

func LoadOrInitializeCA(dir string) (CA, error) {
	k, c, err := loadCA(dir)
	if err == nil {
		return CA{key: k, cert: c}, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return CA{}, xerrors.Errorf("failed to load ca: %w", err)
	}

	k, c, err = initRootCA(dir)
	if err != nil {
		return CA{}, xerrors.Errorf("failed to init ca: %w", err)
	}
	return CA{key: k, cert: c}, nil
}
