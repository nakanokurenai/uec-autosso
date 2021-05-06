package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"

	"github.com/nakanokurenai/uec-autologon/internal/lpki"
)

func realMain() error {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)

	ca, err := lpki.LoadOrInitializeCA(".")
	if err != nil {
		return xerrors.Errorf("wrap: %w", err)
	}

	k, c, err := ca.IssueServerCert("hey.n11i.jp")
	if err != nil {
		return xerrors.Errorf("wrap: %w", err)
	}
	k1, c1, err := ca.IssueServerCert("hey.n11i.jp")
	if err != nil {
		return xerrors.Errorf("wrap: %w", err)
	}

	fmt.Println(k.Equal(k1))
	fmt.Println(c.Equal(c1))

	n, err := ioutil.TempDir("", "")
	if err != nil {
		return xerrors.Errorf("wrap: %w", err)
	}
	defer os.RemoveAll(n)

	sockFile := filepath.Join(n, "0.sock")
	fmt.Println(sockFile)
	l, err := net.Listen("unix", sockFile)
	if err != nil {
		return xerrors.Errorf("wrap: %w", err)
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	tl := tls.NewListener(l, &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{
					c.Raw,
				},
				PrivateKey: k,
			},
		},
	})

	var h http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello!"))
	}
	s := &http.Server{
		Handler:        h,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	if err := s.Serve(tl); err != nil {
		return xerrors.Errorf("wrap: %w", err)
	}

	return nil
}
