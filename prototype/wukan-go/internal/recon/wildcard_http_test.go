package recon

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/wukan/wukan/internal/httpprobe"
)

func namesOf(subs []*SubdomainInfo) []string {
	var out []string
	for _, s := range subs {
		out = append(out, s.Name)
	}
	return out
}

func TestSelectWildcardConfirmTargets(t *testing.T) {
	rep := &Report{
		Target: "example.com",
		CT: &SubdomainResult{Subdomains: []*SubdomainInfo{
			{Name: "b.example.com", Resolves: true, ResolveIPs: []string{"1.1.1.1"}},
			{Name: "a.example.com", Resolves: true, ResolveIPs: []string{"1.1.1.1"}},
			{Name: "dead.example.com", Resolves: false},
			{Name: "*.example.com", IsWildcard: true, Resolves: true, ResolveIPs: []string{"1.1.1.1"}},
			{Name: "example.com", Resolves: true, ResolveIPs: []string{"1.1.1.1"}},
			{Name: "noip.example.com", Resolves: true},
			nil,
		}},
	}

	got := selectWildcardConfirmTargets(rep, 10)
	if len(got) != 2 {
		t.Fatalf("期望选出 2 个子域，实际 %d 个: %v", len(got), namesOf(got))
	}
	// 按名字排序，选择稳定（多次运行集合一致）
	if got[0].Name != "a.example.com" || got[1].Name != "b.example.com" {
		t.Fatalf("应按名字排序: %v", namesOf(got))
	}

	if got := selectWildcardConfirmTargets(rep, 1); len(got) != 1 || got[0].Name != "a.example.com" {
		t.Fatalf("限量 1 应返回 a.example.com: %v", namesOf(got))
	}
	if got := selectWildcardConfirmTargets(rep, 0); got != nil {
		t.Fatalf("max=0 应返回 nil，实际 %v", namesOf(got))
	}
	if got := selectWildcardConfirmTargets(&Report{}, 5); got != nil {
		t.Fatalf("无 CT 数据应返回 nil，实际 %v", namesOf(got))
	}
	if got := selectWildcardConfirmTargets(nil, 5); got != nil {
		t.Fatalf("nil Report 应返回 nil")
	}
}

func TestBodyLenClose(t *testing.T) {
	cases := []struct {
		a, b int
		want bool
	}{
		{0, 0, true},
		{100, 100, true},
		{100, 101, true},  // 1% 抖动
		{100, 102, true},  // 恰 2%
		{100, 103, false}, // 3% 超出
		{0, 50, false},
		{1000, 980, true},
		{1000, 970, false},
	}
	for _, c := range cases {
		if got := bodyLenClose(c.a, c.b); got != c.want {
			t.Errorf("bodyLenClose(%d,%d)=%v，期望 %v", c.a, c.b, got, c.want)
		}
	}
}

func TestSameWildcardSite(t *testing.T) {
	base := &httpprobe.ProbeResult{StatusCode: 404, Title: "Not Found", BodyLen: 1000}
	cases := []struct {
		name string
		got  *httpprobe.ProbeResult
		want bool
	}{
		{"完全一致", &httpprobe.ProbeResult{StatusCode: 404, Title: "Not Found", BodyLen: 1000}, true},
		{"长度 2% 内抖动", &httpprobe.ProbeResult{StatusCode: 404, Title: "Not Found", BodyLen: 1015}, true},
		{"状态码不同", &httpprobe.ProbeResult{StatusCode: 200, Title: "Not Found", BodyLen: 1000}, false},
		{"标题不同", &httpprobe.ProbeResult{StatusCode: 404, Title: "Welcome", BodyLen: 1000}, false},
		{"长度差异过大", &httpprobe.ProbeResult{StatusCode: 404, Title: "Not Found", BodyLen: 1200}, false},
		{"favicon 不同", &httpprobe.ProbeResult{StatusCode: 404, Title: "Not Found", BodyLen: 1000, FaviconMurmur: 12345}, false},
		{"一方无响应", &httpprobe.ProbeResult{StatusCode: 0, Err: "connection refused"}, false},
		{"nil 结果", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sameWildcardSite(base, c.got); got != c.want {
				t.Errorf("sameWildcardSite()=%v，期望 %v", got, c.want)
			}
		})
	}

	// favicon 两边都拿到且一致 → 不影响判定
	baseFav := &httpprobe.ProbeResult{StatusCode: 200, Title: "T", BodyLen: 500, FaviconMurmur: 999}
	gotFav := &httpprobe.ProbeResult{StatusCode: 200, Title: "T", BodyLen: 500, FaviconMurmur: 999}
	if !sameWildcardSite(baseFav, gotFav) {
		t.Errorf("favicon 一致时应判为同站")
	}
}

func TestClassifyWildcardHTTP(t *testing.T) {
	cases := []struct {
		name                            string
		baselineOK, sameSite, gotOK, ip bool
		want                            string
	}{
		{"基线与子域同站 → 泛域名", true, true, true, true, ConfirmWildcard},
		{"基线可用且响应不同 → 独立", true, false, true, true, ConfirmReal},
		{"基线不可用但有响应 → 独立（能力降级）", false, false, true, true, ConfirmReal},
		{"无响应+同泛域IP+基线也不可用 → 疑似泛域名", false, false, false, true, ConfirmWildcardNoHTTP},
		{"无响应+不同IP → 无法判定", false, false, false, false, ConfirmInconclusive},
		{"无响应+同IP但基线可用 → 保守：无法判定", true, false, false, true, ConfirmInconclusive},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyWildcardHTTP(c.baselineOK, c.sameSite, c.gotOK, c.ip); got != c.want {
				t.Errorf("classify()=%q，期望 %q", got, c.want)
			}
		})
	}
}

func TestConfirmLabel(t *testing.T) {
	var nilSub *SubdomainInfo
	if nilSub.ConfirmLabel() != "" {
		t.Errorf("nil 接收者应返回空标签")
	}
	cases := map[string]string{
		ConfirmReal:           "✓ 独立响应",
		ConfirmWildcard:       "✗ 泛域名一致",
		ConfirmWildcardNoHTTP: "⚠ 疑似泛域名",
		ConfirmInconclusive:   "? 无HTTP响应",
		"":                    "",
		"unknown-future":      "",
	}
	for in, want := range cases {
		sb := &SubdomainInfo{HTTPConfirm: in}
		if got := sb.ConfirmLabel(); got != want {
			t.Errorf("ConfirmLabel(%q)=%q，期望 %q", in, got, want)
		}
	}
}

// TestConfirmWildcardHTTPE2E 端到端验证（需要公网 DNS + 本机 80 端口可绑定）。
//
// ⭐ 用公开的 lvh.me 泛域名服务（任意子域 → 127.0.0.1）模拟真实泛域名场景；
// 本地起一个按 Host 路由的 vhost 服务：
//   - 随机/未知子域 → 默认站点（模拟"泛域名默认页"）
//   - real-e2e.lvh.me → 内容明显不同的真实页面（应判 real）
//   - fake-e2e.lvh.me → 默认站点（应判 wildcard）
//
// 探测路径：https（443 无服务 → 快速失败）→ http 回退（P0-3 降级链）→ 本地 :80。
// 无法绑定 80 或 DNS 不可用时自动跳过（离线环境不误报失败）。
func TestConfirmWildcardHTTPE2E(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:80")
	if err != nil {
		t.Skipf("无法绑定 127.0.0.1:80（被占用或权限不足），跳过 E2E: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if host == "real-e2e.lvh.me" {
			fmt.Fprint(w, "<html><head><title>Real E2E Service</title></head><body>"+
				strings.Repeat("real-service-content ", 40)+"</body></html>")
			return
		}
		fmt.Fprint(w, "<html><head><title>Wildcard Default Site</title></head><body>"+
			"default wildcard page</body></html>")
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	// DNS 预检：lvh.me 泛域名必须可用（离线环境跳过）
	if _, err := net.LookupHost("dns-check.lvh.me"); err != nil {
		t.Skipf("lvh.me 泛域名 DNS 不可用，跳过 E2E: %v", err)
	}

	rep := &Report{
		Target: "lvh.me",
		DNS:    &DNSResult{Wildcard: "127.0.0.1"},
		CT: &SubdomainResult{Subdomains: []*SubdomainInfo{
			{Name: "real-e2e.lvh.me", Resolves: true, ResolveIPs: []string{"127.0.0.1"}},
			{Name: "fake-e2e.lvh.me", Resolves: true, ResolveIPs: []string{"127.0.0.1"}},
		}},
	}

	runner := NewRunner(DefaultOptions())
	chk := runner.confirmWildcardSubdomains(rep)

	if chk.Probed != 2 {
		t.Fatalf("应确认 2 个子域，实际 %d（基线 %s err=%q）", chk.Probed, chk.ProbeHost, chk.BaselineErr)
	}
	if chk.BaselineErr != "" || chk.BaselineStatus != 200 {
		t.Fatalf("基线应拿到 HTTP 200：status=%d err=%q", chk.BaselineStatus, chk.BaselineErr)
	}

	byName := map[string]*SubdomainInfo{}
	for _, sb := range rep.CT.Subdomains {
		byName[sb.Name] = sb
	}
	if got := byName["real-e2e.lvh.me"]; got.HTTPConfirm != ConfirmReal {
		t.Errorf("real-e2e.lvh.me 应判为 %s，实际 %q（HTTP %d）", ConfirmReal, got.HTTPConfirm, got.HTTPStatus)
	}
	if got := byName["fake-e2e.lvh.me"]; got.HTTPConfirm != ConfirmWildcard {
		t.Errorf("fake-e2e.lvh.me 应判为 %s，实际 %q（HTTP %d）", ConfirmWildcard, got.HTTPConfirm, got.HTTPStatus)
	}
	if chk.Real != 1 || chk.Wildcard != 1 || chk.WildcardNoHTTP != 0 || chk.Inconclusive != 0 {
		t.Fatalf("汇总计数错误: real=%d wildcard=%d no_http=%d inconclusive=%d",
			chk.Real, chk.Wildcard, chk.WildcardNoHTTP, chk.Inconclusive)
	}
}
