package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}

var flags struct {
	domain   string
	acme     string
	tlsProxy string
	minTLS13 bool
	staging  bool
	cache    string
	pprof    string
}

func parseFlags() {
	args := os.Args[1:]
	if len(args) >= 1 && !strings.HasPrefix(args[0], "-") {
		flags.domain = args[0]
		args = args[1:]
	}
	var noDomain bool
	if flags.domain == "" {
		flags.domain = "example.com"
		noDomain = true
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "."
	}
	fs := flag.NewFlagSet("", flag.ExitOnError)
	fs.StringVar(&flags.acme, "acme", ":80", "listen interface for ACME challenge\n"+
		"must be reachable at port 80 from internet")
	fs.StringVar(&flags.tlsProxy, "tlsproxy", "", "comma separated external=internal listen addresses")
	fs.BoolVar(&flags.minTLS13, "mintls1.3", false, "require minimum TLS 1.3")
	fs.BoolVar(&flags.staging, "staging", false, "use LetsEncrypt staging server")
	fs.StringVar(&flags.cache, "cache", filepath.Join(home, flags.domain), "directory for certificate cache")
	fs.StringVar(&flags.pprof, "pprof", "", "listen address of pprof server")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s example.com [flags]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
		os.Exit(2)
	}
	fs.Parse(args)
	if noDomain {
		fs.Usage()
	}
}

func main() {
	parseFlags()

	err := os.MkdirAll(flags.cache, 0700)
	if err != nil {
		log.Fatal(err)
	}
	unveil("/etc/resolv.conf", "r")
	unveil("/etc/ssl/cert.pem", "r")
	unveil(flags.cache, "rwc")
	unveilBlock()

	log.Printf("Starting domain proxy for %v", flags.domain)
	log.Printf("Go version %s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)

	if flags.pprof != "" {
		mux := http.NewServeMux()
		mux.Handle("/", http.RedirectHandler("/debug/pprof/", http.StatusSeeOther))
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		lis, err := net.Listen("tcp", flags.pprof)
		if err != nil {
			log.Panic(err)
		}
		log.Printf("pprof server listening on %s", lis.Addr())
		s := http.Server{Handler: mux}
		go func() { log.Println(s.Serve(lis)) }()
	}

	tc := setupTLS(flags.domain)
	for _, pair := range strings.Split(flags.tlsProxy, ",") {
		pos := strings.Index(pair, "=")
		switch pos {
		case -1, 0, len(pair) - 1:
			log.Fatalf("bad -tlsproxy pair %q", pair)
		}
		extAddr, intAddr := pair[:pos], pair[pos+1:]

		lis, err := tls.Listen("tcp", extAddr, tc)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("accepting TLS connections on %v", lis.Addr())
		go func() {
			for {
				extConn, err := lis.Accept()
				if err != nil {
					log.Panic(err)
				}
				go proxyTLS(extConn, intAddr)
			}
		}()
	}
	select {}
}

var errClosed = errors.New("closed")

func proxyTLS(extConn net.Conn, intAddr string) {
	defer extConn.Close()
	err := extConn.(*tls.Conn).Handshake()
	if err != nil {
		log.Printf("%v: %v", extConn.RemoteAddr(), err)
		return
	}
	intConn, err := net.Dial("tcp", intAddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer intConn.Close()
	log.Printf("proxying %v->%v", extConn.RemoteAddr(), intConn.RemoteAddr())
	var recv, sent int64
	errs := make(chan error, 2)
	halfProxy := func(to, from net.Conn, copied *int64) {
		n, err := io.Copy(to, from)
		*copied = n
		errs <- err
		to.Close()
	}
	go halfProxy(intConn, extConn, &recv)
	go halfProxy(extConn, intConn, &sent)
	err = <-errs // Read first error
	_ = <-errs   // Discard second but wait for copy to complete
	if err == nil {
		err = errClosed
	}
	log.Printf("%v->%v (recv=%v sent=%v): %v", extConn.RemoteAddr(), intConn.RemoteAddr(), recv, sent, err)
}

const letsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

func setupTLS(domain string) (tc *tls.Config) {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(flags.cache),
		HostPolicy: autocert.HostWhitelist(domain),
	}
	if flags.staging {
		log.Printf("using LetsEncrypt staging environment")
		m.Client = &acme.Client{DirectoryURL: letsEncryptStagingURL}
	}
	tc = m.TLSConfig()
	tc.ServerName = domain
	tc.NextProtos = []string{"http/1.1", acme.ALPNProto}
	tc.MinVersion = tls.VersionTLS12
	switch {
	case flags.minTLS13:
		tc.MinVersion = tls.VersionTLS13
	}
	tc.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	tc.PreferServerCipherSuites = true
	tc.CipherSuites = []uint16{ // Only applies to TLS 1.2. TLS 1.3 ciphersuites are not configurable.
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
	lis, err := net.Listen("tcp", flags.acme)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ACME client listening on %s", lis.Addr())
	s := http.Server{Handler: m.HTTPHandler(nil)}
	go func() { log.Panic(s.Serve(lis)) }()
	return
}
