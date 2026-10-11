package recon

import (
	"strings"
	"testing"
	"time"

	"github.com/wukan/wukan/internal/httpprobe"
	"github.com/wukan/wukan/internal/portscan"
)

// mkReportFixture 构造覆盖各数据段的报告
func mkReportFixture() *Report {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return &Report{
		Target: "example.com",
		Findings: []Finding{
			{Level: "high", Type: "risky_ports", Title: "发现高风险端口 | 含竖线",
				Detail: "判读文本", Evidence: []string{"3306/tcp mysql"}},
			{Level: "info", Type: "wildcard", Title: "泛域名"},
		},
		Diff: &SnapshotDiff{
			Target: "example.com", PrevAt: now, CurrAt: now.Add(24 * time.Hour),
			Changes: []Change{{Kind: "port_added", Level: "high", Target: "1.2.3.4:8443",
				Detail: "新暴露端口判读"}},
		},
		DNS: &DNSResult{
			Resolver: "doh:aliyun",
			Records: map[RecordType][]DNSRecord{
				TypeA: {{Type: TypeA, Name: "example.com", Value: "93.184.216.34"}},
			},
			IPs: []string{"93.184.216.34"},
		},
		Domain: &DomainInfo{
			Registrar: "RESERVED-Internet Assigned Numbers Authority",
			Events:    map[string]string{"registration": "1995-08-14"},
			SecureDNS: true,
		},
		CT: &SubdomainResult{Subdomains: []*SubdomainInfo{
			{Name: "www.example.com", Resolves: true, FirstSeen: now, LastSeen: now, CertCount: 3},
		}},
		Passive: &PassiveDNSResult{
			Records: map[string][]string{"www.example.com": {"93.184.216.34"}},
			Timeline: []PDNSTimelineEntry{
				{Hostname: "example.com", IP: "1.1.1.1", FirstSeen: now.AddDate(-5, 0, 0), LastSeen: now.AddDate(-2, 0, 0)},
				{Hostname: "example.com", IP: "2.2.2.2", FirstSeen: now.AddDate(-2, 0, 0), LastSeen: now},
			},
		},
		Ports: []portscan.PortResult{
			{Host: "example.com", IP: "93.184.216.34", Port: 443, State: portscan.StateOpen,
				Service: "https", Confidence: 90, Banner: "Server: nginx | extra"},
			{Host: "example.com", IP: "93.184.216.34", Port: 22, State: portscan.StateClosed},
		},
		Tech: []*httpprobe.ProbeResult{
			{URL: "https://example.com", StatusCode: 200, Server: "nginx",
				JARM:         "27d40d40d00040d1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c",
				BodyKeywords: []string{"nginx"}},
		},
		TechConflicts: []*httpprobe.ConflictReport{{}},
	}
}

// ⭐ Markdown 报告：结构完整 + 表格转义
func TestWriteMarkdown(t *testing.T) {
	rep := mkReportFixture()
	var b strings.Builder
	if err := WriteMarkdown(&b, rep); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# 屋勘 HouseRecon",
		"## 摘要",
		"## ⭐ 可行动发现",
		"## 与上次快照的差异",
		"## DNS 解析",
		"## 域名注册信息",
		"## 证书透明度",
		"## 被动 DNS 时间线",
		"## 端口扫描",
		"## HTTP 指纹与冲突检测",
		"risky_ports",
		"port_added",
		"www.example.com",
		"93.184.216.34",
		"由 屋勘 HouseRecon",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Markdown 缺少 %q", want)
		}
	}
	// ⭐ 表格单元格里的竖线必须被转义（否则破坏表格结构）
	if !strings.Contains(out, `Server: nginx \| extra`) {
		t.Error("表格单元格中的竖线应转义为 \\|")
	}
	// 标题（heading）不需要转义，原样出现即可
	if !strings.Contains(out, "发现高风险端口 | 含竖线") {
		t.Error("标题应原样呈现")
	}
	// 关闭的端口不应出现在端口表
	if strings.Contains(out, "| 22 |") {
		t.Error("未开放端口不应进端口表")
	}
}

// ⭐⭐ HTML 报告：结构完整 + XSS 转义（html/template 保证）
func TestWriteHTML(t *testing.T) {
	rep := mkReportFixture()
	// 注入恶意标题验证转义
	rep.Findings = append(rep.Findings, Finding{
		Level: "low", Type: "xss_test",
		Title: `<script>alert("xss")</script>`,
	})
	var b strings.Builder
	if err := WriteHTML(&b, rep); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"<!DOCTYPE html>", "屋勘 HouseRecon", "摘要", "可行动发现",
		"与上次快照的差异", "DNS 解析", "被动 DNS 时间线",
		"HTTP 指纹与冲突检测", "port_added", "www.example.com",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML 缺少 %q", want)
		}
	}
	// ⭐ XSS：脚本标签必须被转义，绝不能原样出现
	if strings.Contains(out, `<script>alert("xss")</script>`) {
		t.Error("⭐ HTML 未转义脚本标签（XSS）")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("脚本标签应被转义为 &lt;script&gt;")
	}
}

// nil 安全：返回错误而不是 panic
func TestReport_NilSafety(t *testing.T) {
	if err := WriteMarkdown(&strings.Builder{}, nil); err == nil {
		t.Error("nil report 应返回错误")
	}
	if err := WriteHTML(&strings.Builder{}, nil); err == nil {
		t.Error("nil report 应返回错误")
	}
}

// 最小报告（只有目标名）也要能渲染
func TestReport_Minimal(t *testing.T) {
	rep := &Report{Target: "example.com"}
	var md, htm strings.Builder
	if err := WriteMarkdown(&md, rep); err != nil {
		t.Fatal(err)
	}
	if err := WriteHTML(&htm, rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "example.com") || !strings.Contains(htm.String(), "example.com") {
		t.Error("最小报告应包含目标名")
	}
}
