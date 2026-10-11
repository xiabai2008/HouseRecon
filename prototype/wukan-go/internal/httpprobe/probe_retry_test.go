package httpprobe

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newRetryProber 测试用探针：快超时、不抓 favicon/证书（避免额外请求）
func newRetryProber(t *testing.T, cache TechCache) *Prober {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Timeout = 2 * time.Second
	cfg.GrabFavicon = false
	cfg.GrabCert = false
	cfg.GrabTLS = false
	cfg.Cache = cache
	return New(cfg)
}

// ⭐⭐ https 失败 → 改试 http（"子域只跑 HTTP"场景）
//
// 用纯 HTTP 的 httptest 服务器模拟：对 https 请求它无法完成 TLS 握手
// （快速失败），降级重试应该改走 http 并拿到结果。
func TestProbeURL_FallbackToHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "fallback-test")
		_, _ = w.Write([]byte("hello from http"))
	}))
	defer srv.Close()
	httpsURL := strings.Replace(srv.URL, "http://", "https://", 1) + "/"

	cache, _ := NewFileTechCache("", time.Minute, false)
	p := newRetryProber(t, cache)

	// 第一次：https 失败 → http 回退成功
	r := p.ProbeURL(httpsURL)
	if r.Err != "" {
		t.Fatalf("应有 http 回退成功，实际失败: %s", r.Err)
	}
	if r.RetriedWith != "http" {
		t.Errorf("RetriedWith 应为 http，实际 %q", r.RetriedWith)
	}
	if r.StatusCode != 200 {
		t.Errorf("状态码应为 200，实际 %d", r.StatusCode)
	}
	if r.Server != "fallback-test" {
		t.Errorf("应拿到 http 侧的 Server 头，实际 %q", r.Server)
	}
	// ⭐ 身份保留原 URL（https），不能让报告以为探的是 http URL
	if r.URL != httpsURL {
		t.Errorf("URL 应保留原 https 地址，实际 %q", r.URL)
	}
	if !strings.HasPrefix(r.FinalURL, "http://") {
		t.Errorf("FinalURL 应记录实际探测的 http 地址，实际 %q", r.FinalURL)
	}
	if r.RetryLabel() != "http 回退" {
		t.Errorf("RetryLabel 应为 http 回退，实际 %q", r.RetryLabel())
	}

	// ⭐ 回退结果按**原 URL 的键**写缓存：第二次探测直接命中
	r2 := p.ProbeURL(httpsURL)
	if !r2.Cached {
		t.Error("第二次探测应命中缓存")
	}
	if r2.RetriedWith != "http" {
		t.Errorf("缓存应保留 RetriedWith 标注，实际 %q", r2.RetriedWith)
	}
}

// ⭐⭐ 重定向链路超时 → 跳过重定向重试（原始 301/302 本身就是有效指纹）
func TestProbeURL_FallbackNoFollow(t *testing.T) {
	// 黑洞：接受连接但永不响应 → 跟随重定向必然超时
	blackhole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	go func() {
		for {
			c, err := blackhole.Accept()
			if err != nil {
				return
			}
			defer c.Close() // 持有连接不响应
		}
	}()

	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+blackhole.Addr().String()+"/", http.StatusFound)
	}))
	defer redirectSrv.Close()

	p := newRetryProber(t, nil)
	r := p.ProbeURL(redirectSrv.URL + "/")

	if r.Err != "" {
		t.Fatalf("跳过重定向重试应成功，实际失败: %s", r.Err)
	}
	if r.RetriedWith != "no-follow" {
		t.Errorf("RetriedWith 应为 no-follow，实际 %q", r.RetriedWith)
	}
	if r.StatusCode != 302 {
		t.Errorf("应拿到原始的 302 响应，实际 %d", r.StatusCode)
	}
	if !strings.Contains(r.Location, blackhole.Addr().String()) {
		t.Errorf("Location 应指向黑洞地址，实际 %q", r.Location)
	}
	if r.RetryLabel() != "跳过重定向" {
		t.Errorf("RetryLabel 应为 跳过重定向，实际 %q", r.RetryLabel())
	}
}

// ⭐ RetryFallback 关闭时行为与旧版一致：失败就是失败
func TestProbeURL_NoRetryWhenDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	httpsURL := strings.Replace(srv.URL, "http://", "https://", 1) + "/"

	cfg := DefaultConfig()
	cfg.Timeout = 2 * time.Second
	cfg.GrabFavicon = false
	cfg.GrabCert = false
	cfg.RetryFallback = false
	p := New(cfg)

	r := p.ProbeURL(httpsURL)
	if r.Err == "" {
		t.Fatal("关闭重试后 https 探测应失败（TLS 握手错误）")
	}
	if r.RetriedWith != "" {
		t.Errorf("关闭重试后 RetriedWith 应为空，实际 %q", r.RetriedWith)
	}
}

// 正常成功不打重试标记
func TestProbeURL_NoRetryMarkOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	p := newRetryProber(t, nil)
	r := p.ProbeURL(srv.URL + "/")
	if r.Err != "" {
		t.Fatalf("正常探测不应失败: %s", r.Err)
	}
	if r.RetriedWith != "" || r.RetryLabel() != "" {
		t.Errorf("正常成功不应有重试标记，实际 %q", r.RetriedWith)
	}
}

// ⭐ 全部回退都失败 → 返回**首次**结果（主 URL 的真实失败原因），
// 且 RetriedWith 保持为空（没成功过，不能标成"重试成功"）
func TestProbeURL_AllFallbacksFail(t *testing.T) {
	// 拿一个确定没人监听的端口
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	p := newRetryProber(t, nil)
	r := p.ProbeURL("https://" + addr + "/")
	if r.Err == "" {
		t.Fatal("端口已关闭，探测应失败")
	}
	if r.RetriedWith != "" {
		t.Errorf("全部失败时不应有重试成功标记，实际 %q", r.RetriedWith)
	}
	// 首次结果的身份是原 URL
	if r.URL != "https://"+addr+"/" {
		t.Errorf("失败时应返回首次结果（原 URL），实际 %q", r.URL)
	}
}

// ⭐ 配置了 FollowRedirect=false 时：回退 1 无意义（主客户端已不跟随），
// 但回退 2（http）仍然工作
func TestProbeURL_HTTPFallbackWhenNoFollowConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "no-follow-fallback")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	httpsURL := strings.Replace(srv.URL, "http://", "https://", 1) + "/"

	cfg := DefaultConfig()
	cfg.Timeout = 2 * time.Second
	cfg.GrabFavicon = false
	cfg.GrabCert = false
	cfg.FollowRedirect = false // 主客户端不跟随
	cfg.RetryFallback = true
	p := New(cfg)

	r := p.ProbeURL(httpsURL)
	if r.Err != "" {
		t.Fatalf("https 失败后应尝试 http 回退: %s", r.Err)
	}
	if r.RetriedWith != "http" {
		t.Errorf("RetriedWith 应为 http，实际 %q", r.RetriedWith)
	}
}
