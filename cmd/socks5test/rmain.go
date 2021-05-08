package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/nakanokurenai/uec-autologon/internal/recon"
	"github.com/thinkgos/go-socks5"
	"golang.org/x/xerrors"
)

// reserved address for documentation
var mustMuskAddress = net.ParseIP("192.0.2.1")

const targetHostname = "thissitedoesnotexist.example.com"

func listenHTTPServer(ctx context.Context) (func(), func() (net.Conn, error), error) {
	hl, err := recon.New(targetHostname, fmt.Sprintf("yo.%s", targetHostname))
	if err != nil {
		return nil, nil, xerrors.Errorf("recon failed: %w", err)
	}
	go func() {
		<-ctx.Done()
		hl.Close()
	}()

	var h http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/html")
		w.Write([]byte("<marquee>Welcome to socks5 test!</marquee>"))
	}
	s := &http.Server{
		Handler:        h,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		if err := s.Serve(hl); err != nil {
			fmt.Println(err)
		}
		wg.Done()
	}()

	return func() { wg.Wait() }, func() (net.Conn, error) {
		return hl.Dial()
	}, nil
}

type myResolver struct{}

func (*myResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	fmt.Println(name)
	if name == targetHostname {
		return ctx, net.ParseIP(mustMuskAddress.String()), nil
	}
	return socks5.DNSResolver{}.Resolve(ctx, name)
}

func realMain() error {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)

	close, open, err := listenHTTPServer(ctx)
	if err != nil {
		return xerrors.Errorf("w: %w", err)
	}
	defer close()

	server := socks5.NewServer(
		socks5.WithResolver(&myResolver{}),
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			defer fmt.Printf("%s/%s\n", network, addr)
			if network == "tcp" && addr == fmt.Sprintf("%s:443", mustMuskAddress.String()) {
				fmt.Printf("! ")
				return open()
			}
			return net.Dial(network, addr)
		}),
	)

	lis, err := net.Listen("tcp", "127.0.0.1:1080")
	if err != nil {
		return xerrors.Errorf("w: %w", err)
	}

	go func() {
		<-ctx.Done()
		lis.Close()
	}()

	if err := server.Serve(lis); err != nil {
		return xerrors.Errorf("w: %w", err)
	}

	return nil
}
