package main

import (
	"crypto/tls"
	"flag"
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
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("no home directory for cert cache: %v", err)
	}
	crtDir = home
}

var (
	crtDir       string
	fs           = flag.NewFlagSet("", flag.ExitOnError)
	domainFlag   = fs.String("domain", "", "external dns name")
	acmeFlag     = fs.String("acme", ":80", "listen interface for ACME challenge\nmust be reachable at port 80 from internet")
	tlsProxyFlag = fs.String("tlsproxy", "", "comma separated external=internal listen addresses")
	stagingFlag  = fs.Bool("staging", false, "use LetsEncrypt staging server")
	crtDirFlag   = fs.String("crtdir", crtDir, "directory to store certificate cache in")
	pprofFlag    = fs.String("pprof", "", "listen address of pprof server")
)

func main() {
	fs.Parse(os.Args[1:])

	if *crtDirFlag != "" {
		crtDir = *crtDirFlag
	}

	unix.Unveil(crtDir, "rwc")
	unix.UnveilBlock()

	log.Printf("Starting domain proxy for %v", *domainFlag)
	log.Printf("Go version %s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)

	if *pprofFlag != "" {
		mux := http.NewServeMux()
		mux.Handle("/", http.RedirectHandler("/debug/pprof/", http.StatusSeeOther))
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		lis, err := net.Listen("tcp", *pprofFlag)
		if err != nil {
			log.Panic(err)
		}
		log.Printf("pprof server listening on %s", lis.Addr())
		s := http.Server{Handler: mux}
		go func() { log.Println(s.Serve(lis)) }()
	}

	tc := setupTLS(*domainFlag)
	for _, pair := range strings.Split(*tlsProxyFlag, ",") {
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
	halfProxy := func(to, from net.Conn, copied *int64) func() error {
		return func() error {
			n, err := io.CopyBuffer(to, from, nil)
			*copied = n
			return err
		}
	}
	var g errgroup.Group
	g.Go(halfProxy(intConn, extConn, &recv))
	g.Go(halfProxy(extConn, intConn, &sent))
	err = g.Wait()
	if err != nil {
		log.Printf("%v (recv=%v sent=%v): %v", extConn.RemoteAddr(), recv, sent, err)
	} else {
		log.Printf("%v (recv=%v sent=%v): closed", extConn.RemoteAddr(), recv, sent)
	}
}

const letsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

func setupTLS(domain string) (tc *tls.Config) {

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(filepath.Join(crtDir, ".domain")),
		HostPolicy: autocert.HostWhitelist(domain),
	}
	if *stagingFlag {
		log.Printf("using LetsEncrypt staging environment")
		m.Client = &acme.Client{DirectoryURL: letsEncryptStagingURL}
	}
	tc = m.TLSConfig()
	tc.ServerName = domain
	tc.NextProtos = []string{"http/1.1", acme.ALPNProto}
	tc.MinVersion = tls.VersionTLS12
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
	lis, err := net.Listen("tcp", *acmeFlag)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ACME client listening on %s", lis.Addr())
	s := http.Server{Handler: m.HTTPHandler(nil)}
	go func() { log.Panic(s.Serve(lis)) }()
	return
}
