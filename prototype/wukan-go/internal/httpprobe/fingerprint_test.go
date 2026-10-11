package httpprobe

import (
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ⭐ JARM 对本地 TLS 服务器：格式正确 + 确定性 + 非全零
func TestJARM_LocalTLSServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port, _ := strconv.Atoi(portStr)

	j1 := JARMFingerprint(host, port, host, 2*time.Second)
	if len(j1) != 62 {
		t.Fatalf("JARM 应为 62 字符，实际 %d：%q", len(j1), j1)
	}
	if !regexp.MustCompile(`^[0-9a-f]{62}$`).MatchString(j1) {
		t.Errorf("JARM 应为 62 位十六进制：%q", j1)
	}
	if j1 == strings.Repeat("0", 62) {
		t.Error("本地 TLS 服务器不应是全 0（Go server 会正常响应多个探测）")
	}
	// 确定性：同服务器两次探测必须一致（GREASE 随机不影响结果）
	j2 := JARMFingerprint(host, port, host, 2*time.Second)
	if j1 != j2 {
		t.Errorf("JARM 应确定（同服务器两次不同）：%q vs %q", j1, j2)
	}
}

// 连接被拒 → 62 个 0（与参考实现一致）
func TestJARM_Refused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	got := JARMFingerprint("127.0.0.1", port, "", time.Second)
	if got != strings.Repeat("0", 62) {
		t.Errorf("连接被拒应返回 62 个 0，实际 %q", got)
	}
}

// ⭐ H2 SETTINGS 对本地 h2 服务器：格式 + 关键设置 + 确定性
func TestH2_LocalServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port, _ := strconv.Atoi(portStr)

	fp := H2Fingerprint(host, port, host, 3*time.Second)
	if fp == "" {
		t.Fatal("Go h2 服务器应有 SETTINGS 指纹")
	}
	// 格式：id:value;id:value|window（window 可空）
	if !regexp.MustCompile(`^\d+:\d+(;\d+:\d+)*\|(\d+)?$`).MatchString(fp) {
		t.Errorf("指纹格式不符：%q", fp)
	}
	// Go http2 服务器会通告 MAX_CONCURRENT_STREAMS（id=3）
	if !strings.Contains(fp, "3:") {
		t.Errorf("Go 服务器指纹应包含 MAX_CONCURRENT_STREAMS(3)：%q", fp)
	}
	// 确定性
	if fp2 := H2Fingerprint(host, port, host, 3*time.Second); fp2 != fp {
		t.Errorf("H2 指纹应确定：%q vs %q", fp, fp2)
	}
}

// 不支持 h2 的 TLS 服务器 → 空（ALPN 协商不到）
func TestH2_NonH2Server(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port, _ := strconv.Atoi(portStr)

	if fp := H2Fingerprint(host, port, host, 2*time.Second); fp != "" {
		t.Errorf("不支持 h2 的服务器应返回空，实际 %q", fp)
	}
}

// 连接被拒 → 空
func TestH2_Refused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	if fp := H2Fingerprint("127.0.0.1", port, "", time.Second); fp != "" {
		t.Errorf("连接被拒应返回空，实际 %q", fp)
	}
}
