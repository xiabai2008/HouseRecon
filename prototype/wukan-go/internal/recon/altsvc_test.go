package recon

import (
	"strings"
	"testing"

	"github.com/wukan/wukan/internal/httpprobe"
	"github.com/wukan/wukan/internal/quic"
)

// ⭐⭐ P2-4：Alt-Svc 声明 × QUIC 实际的配置漂移检测
//
// 两个独立来源交叉验证：
//   - Alt-Svc 头 = 服务"声明"支持 HTTP/3
//   - QUIC 探活 = UDP/443 的"实际"响应
func TestAnalyze_AltSvcVsQUIC(t *testing.T) {
	rep := &Report{
		Target: "example.com",
		QUIC: []quic.Result{
			{Host: "1.2.3.4", Port: 443, State: quic.StateQuicConfirmed, StackHint: "Cloudflare"},
			{Host: "5.6.7.8", Port: 443, State: quic.StateOpenFiltered}, // 无响应
		},
		Tech: []*httpprobe.ProbeResult{
			// QUIC 活但未声明 → altsvc_missing
			{URL: "https://1.2.3.4:443", IP: "1.2.3.4", AltSvc: ""},
			// 声明 h3 但 QUIC 无响应 → altsvc_unreachable
			{URL: "https://5.6.7.8:443", IP: "5.6.7.8", AltSvc: `h3=":443"; ma=86400`},
			// QUIC 未探测该 IP → 不参与判定（防误报）
			{URL: "https://9.9.9.9:443", IP: "9.9.9.9", AltSvc: `h3=":443"`},
		},
	}
	findings := Analyze(rep)

	var unreachable, missing *Finding
	for i := range findings {
		switch findings[i].Type {
		case "altsvc_unreachable":
			unreachable = &findings[i]
		case "altsvc_missing":
			missing = &findings[i]
		}
	}
	if unreachable == nil {
		t.Fatal("应报 altsvc_unreachable（声明 h3 但 QUIC 无响应）")
	}
	if missing == nil {
		t.Fatal("应报 altsvc_missing（QUIC 活但未声明）")
	}
	// 证据必须指向正确 IP，且不能误伤未探测的 9.9.9.9
	if !strings.Contains(strings.Join(unreachable.Evidence, ","), "5.6.7.8") {
		t.Errorf("unreachable 证据应含 5.6.7.8：%v", unreachable.Evidence)
	}
	if strings.Contains(strings.Join(unreachable.Evidence, ","), "9.9.9.9") {
		t.Errorf("未探测的 IP 不得出现在证据里：%v", unreachable.Evidence)
	}
	if !strings.Contains(strings.Join(missing.Evidence, ","), "1.2.3.4") {
		t.Errorf("missing 证据应含 1.2.3.4：%v", missing.Evidence)
	}
	// 判读必须提示"本地 UDP 探测失败也可能是路径阻断"（防过度断言）
	if !strings.Contains(unreachable.Detail, "路径") && !strings.Contains(unreachable.Detail, "阻断") {
		t.Errorf("判读应说明 UDP 路径阻断的可能：%s", unreachable.Detail)
	}
	// 级别：声明不可达 = medium；未声明 = info
	if unreachable.Level != "medium" {
		t.Errorf("altsvc_unreachable 级别应为 medium，实际 %s", unreachable.Level)
	}
	if missing.Level != "info" {
		t.Errorf("altsvc_missing 级别应为 info，实际 %s", missing.Level)
	}
}

// 无 QUIC 结果或无 tech 结果时静默（不产生任何 Alt-Svc 相关发现）
func TestAnalyze_AltSvcNoDataNoNoise(t *testing.T) {
	// 只有 tech，没有 QUIC
	rep := &Report{
		Target: "example.com",
		Tech: []*httpprobe.ProbeResult{
			{URL: "https://1.2.3.4:443", IP: "1.2.3.4", AltSvc: `h3=":443"`},
		},
	}
	for _, f := range Analyze(rep) {
		if f.Type == "altsvc_unreachable" || f.Type == "altsvc_missing" {
			t.Errorf("没有 QUIC 数据时不应有 Alt-Svc 发现：%+v", f)
		}
	}
	// 声明与事实一致 → 无发现
	rep2 := &Report{
		Target: "example.com",
		QUIC:   []quic.Result{{Host: "1.2.3.4", Port: 443, State: quic.StateQuicConfirmed}},
		Tech: []*httpprobe.ProbeResult{
			{URL: "https://1.2.3.4:443", IP: "1.2.3.4", AltSvc: `h3=":443"`},
		},
	}
	for _, f := range Analyze(rep2) {
		if f.Type == "altsvc_unreachable" || f.Type == "altsvc_missing" {
			t.Errorf("声明与事实一致时不应有发现：%+v", f)
		}
	}
}

// ⭐ M2：Alt-Svc 声明非 443 端口时不与 UDP/443 探测做交叉判定
func TestAnalyze_AltSvcOtherPortNoCrossCheck(t *testing.T) {
	rep := &Report{
		Target: "example.com",
		QUIC:   []quic.Result{{Host: "5.6.7.8", Port: 443, State: quic.StateOpenFiltered}},
		Tech: []*httpprobe.ProbeResult{
			// 声明的是 8443 —— 与 UDP/443 探测无关，不应触发"配置漂移"
			{URL: "https://5.6.7.8:443", IP: "5.6.7.8", AltSvc: `h3=":8443"; ma=86400`},
		},
	}
	for _, f := range Analyze(rep) {
		if f.Type == "altsvc_unreachable" {
			t.Errorf("声明 :8443 不应触发 UDP/443 判定：%+v", f)
		}
	}
}
