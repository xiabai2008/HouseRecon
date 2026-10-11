package recon

import (
	"strings"
	"testing"

	"github.com/wukan/wukan/internal/portscan"
)

// ⭐ P1-2：子域批量扫描的目标选择（纯函数，覆盖边界）
func TestSelectSubScanTargets(t *testing.T) {
	rep := &Report{
		Target: "example.com",
		CT: &SubdomainResult{Subdomains: []*SubdomainInfo{
			{Name: "b.example.com", Resolves: true, ResolveIPs: []string{"2.2.2.2"}},
			{Name: "a.example.com", Resolves: true, ResolveIPs: []string{"1.1.1.1"}},
			{Name: "dead.example.com", Resolves: false},                                                // 不解析 → 跳过
			{Name: "*.example.com", IsWildcard: true, Resolves: true, ResolveIPs: []string{"3.3.3.3"}}, // 泛域 → 跳过
			{Name: "example.com", Resolves: true, ResolveIPs: []string{"9.9.9.9"}},                     // 根域 → 跳过
			{Name: "shared.example.com", Resolves: true, ResolveIPs: []string{"1.1.1.1"}},              // 与 a 同 IP
			{Name: "multi.example.com", Resolves: true, ResolveIPs: []string{"4.4.4.4", "2.2.2.2"}},    // 部分新 IP
		}},
	}
	scanned := map[string]bool{"8.8.8.8": true} // 根域已扫过的 IP

	got := selectSubScanTargets(rep, scanned, 10)
	// 按名字排序：a → b → multi（shared 的 IP 已被 a 占用 → 跳过）
	if len(got) != 3 {
		t.Fatalf("应选中 3 个子域，实际 %d：%+v", len(got), got)
	}
	if got[0].Name != "a.example.com" || got[0].IPs[0] != "1.1.1.1" {
		t.Errorf("第一个应为 a.example.com/1.1.1.1，实际 %+v", got[0])
	}
	if got[1].Name != "b.example.com" {
		t.Errorf("第二个应为 b.example.com，实际 %+v", got[1])
	}
	// multi 的 2.2.2.2 已被 b 占用 → 只扫新增的 4.4.4.4
	if got[2].Name != "multi.example.com" || len(got[2].IPs) != 1 || got[2].IPs[0] != "4.4.4.4" {
		t.Errorf("multi 应只扫新增 IP 4.4.4.4，实际 %+v", got[2])
	}
	// scanned 应被更新（防跨子域重复扫描）
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "4.4.4.4"} {
		if !scanned[ip] {
			t.Errorf("scanned 应记录 %s", ip)
		}
	}
	if scanned["3.3.3.3"] || scanned["9.9.9.9"] {
		t.Error("泛域/根域 IP 不应被标记")
	}
}

// 限量：max 生效且只标记被选中的 IP
func TestSelectSubScanTargets_Limit(t *testing.T) {
	rep := &Report{
		Target: "example.com",
		CT: &SubdomainResult{Subdomains: []*SubdomainInfo{
			{Name: "a.example.com", Resolves: true, ResolveIPs: []string{"1.1.1.1"}},
			{Name: "b.example.com", Resolves: true, ResolveIPs: []string{"2.2.2.2"}},
			{Name: "c.example.com", Resolves: true, ResolveIPs: []string{"3.3.3.3"}},
		}},
	}
	scanned := map[string]bool{}
	got := selectSubScanTargets(rep, scanned, 2)
	if len(got) != 2 || got[0].Name != "a.example.com" || got[1].Name != "b.example.com" {
		t.Fatalf("max=2 应选 a、b，实际 %+v", got)
	}
	if scanned["3.3.3.3"] {
		t.Error("未选中的 c 的 IP 不应被标记（下次调用仍可选）")
	}

	// max=0 → 关闭
	if got := selectSubScanTargets(rep, map[string]bool{}, 0); got != nil {
		t.Errorf("max=0 应返回 nil，实际 %+v", got)
	}
	// nil 防御
	if got := selectSubScanTargets(nil, map[string]bool{}, 5); got != nil {
		t.Error("nil report 应返回 nil")
	}
	if got := selectSubScanTargets(rep, nil, 5); got != nil {
		t.Error("nil scanned 应返回 nil")
	}
}

// ⭐ M6：每子域最多取 2 个新 IP（多 A/AAAA 记录会成倍放大连接数）
func TestSelectSubScanTargets_IPCap(t *testing.T) {
	rep := &Report{
		Target: "example.com",
		CT: &SubdomainResult{Subdomains: []*SubdomainInfo{
			{Name: "multi.example.com", Resolves: true,
				ResolveIPs: []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}},
		}},
	}
	got := selectSubScanTargets(rep, map[string]bool{}, 10)
	if len(got) != 1 {
		t.Fatalf("应选中 1 个子域，实际 %+v", got)
	}
	if len(got[0].IPs) != 2 {
		t.Errorf("每子域应最多取 2 个新 IP，实际 %d 个：%+v", len(got[0].IPs), got[0].IPs)
	}
}

// ⭐⭐ 子域扫描结果（Host=子域名）不得混入 tech 的"根域 CDN 节点"选择 ——
//
//	否则会用根域 Host 头去探子域 IP，拿到错误站点（与项目最重的
//	"CDN 返回默认站点"教训同源）。
func TestTechTargets_FiltersSubdomainPortResults(t *testing.T) {
	r := NewRunner(DefaultOptions())
	rep := &Report{
		Target: "example.com",
		DNS:    &DNSResult{IPs: []string{"1.2.3.4"}},
		Ports: []portscan.PortResult{
			{Host: "1.2.3.4", IP: "1.2.3.4", Port: 443, State: portscan.StateOpen},
			{Host: "sub.example.com", IP: "5.6.7.8", Port: 443, State: portscan.StateOpen},
		},
		CT: &SubdomainResult{Subdomains: []*SubdomainInfo{
			{Name: "sub.example.com", Resolves: true, ResolveIPs: []string{"5.6.7.8"}},
		}},
	}
	targets := r.techTargets(rep)
	sawRoot, sawSub := false, false
	for _, tt := range targets {
		if tt.URL == "https://5.6.7.8:443" {
			t.Errorf("⭐ 子域扫描结果不得当根域 CDN 节点（Host 头会错）：%+v", tt)
		}
		if tt.URL == "https://1.2.3.4:443" && tt.HostHeader == "example.com" {
			sawRoot = true
		}
		if tt.URL == "https://sub.example.com" && tt.HostHeader == "sub.example.com" {
			sawSub = true
		}
	}
	if !sawRoot {
		t.Error("根域节点应保留")
	}
	if !sawSub {
		t.Error("子域目标应由 ② 生成")
	}
}

// ⭐ 子域扫描的风险端口，证据里必须标注来源子域（否则用户不知道是哪台机器）
func TestAnalyze_PortFindingsShowSubdomainHost(t *testing.T) {
	rep := &Report{
		Target: "example.com",
		Ports: []portscan.PortResult{
			{Host: "db.example.com", IP: "5.6.7.8", Port: 3306,
				State: portscan.StateOpen, Service: "mysql", Confidence: 80},
		},
	}
	findings := Analyze(rep)
	found := false
	for _, f := range findings {
		if f.Type == "risky_ports" {
			for _, e := range f.Evidence {
				if strings.Contains(e, "db.example.com") {
					found = true
				}
			}
		}
	}
	if !found {
		t.Errorf("风险端口证据应标注来源子域，实际 findings：%+v", findings)
	}
}
