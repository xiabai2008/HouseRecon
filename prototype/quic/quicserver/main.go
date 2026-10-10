// QUIC 真栈靶场服务端
// ====================
//
// 用途：用真正的 QUIC 实现（quic-go）在本地起一个 HTTP/3 服务端，
//       验证 Python 探测器面对**真实协议栈**时能否正确判定。
//
// ⚠️ 这是比自建靶场强得多的验证：quic-go 是生产级实现，
//    它的 Version Negotiation 行为遵循 RFC 9000，
//    不像手写靶场可以"作弊"。
//
// 依赖：github.com/quic-go/quic-go
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
}

func selfSignedCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0x5748_4B41_4E01),
		Subject:               pkix.Name{Organization: []string{"wukan quic range"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"localhost", "quic.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func main() {
	addr := os.Getenv("QUIC_ADDR")
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	cert := selfSignedCert()
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{http3.NextProtoH3},
		MinVersion:   tls.VersionTLS13,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "wukan-quic-range/0.1")
		_, p, _ := net.SplitHostPort(r.Host)
		if p == "" {
			p = "443"
		}
		w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%s"; ma=2592000`, p))
		fmt.Fprintf(w, "QUIC OK  proto=%s  host=%s\n", r.Proto, r.Host)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "ok %s\n", r.Proto)
	})

	// ⭐ 关键：用 http3.Server 起真正的 HTTP/3（QUIC）服务
	h3 := &http3.Server{
		Addr:       addr,
		Handler:    mux,
		TLSConfig:  tlsConf,
		QUICConfig: nil, // 用默认 QUIC 配置（支持版本协商）
	}

	// 提前占位，让监听就绪后再打印（供测试脚本解析）
	go func() {
		if err := h3.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "serve error: %v\n", err)
		}
	}()

	// 探测实际监听地址
	var realAddr string
	for i := 0; i < 60; i++ {
		ln, err := net.ListenPacket("udp", addr)
		if err == nil {
			realAddr = ln.LocalAddr().String()
			ln.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if realAddr == "" {
		realAddr = "127.0.0.1" + addr
	}

	fmt.Printf("QUICSERVER_READY|%s\n", realAddr)
	os.Stdout.Sync()

	// 等信号退出
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = h3.Shutdown(ctx)
}
