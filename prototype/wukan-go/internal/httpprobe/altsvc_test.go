package httpprobe

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ⭐ Alt-Svc 响应头必须被捕获（P2-4：与 QUIC 探活交叉验证的输入）
func TestProbeURL_CapturesAltSvc(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.GrabFavicon = false
	cfg.GrabCert = false
	cfg.RetryFallback = false
	p := New(cfg)
	r := p.ProbeURL(srv.URL + "/")
	if r.Err != "" {
		t.Fatalf("探测不应失败: %s", r.Err)
	}
	if r.AltSvc != `h3=":443"; ma=86400` {
		t.Errorf("应捕获 Alt-Svc 头，实际 %q", r.AltSvc)
	}

	// 无 Alt-Svc 时为空（不能误填）
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv2.Close()
	r2 := p.ProbeURL(srv2.URL + "/")
	if r2.AltSvc != "" {
		t.Errorf("无 Alt-Svc 时应为空，实际 %q", r2.AltSvc)
	}
}
