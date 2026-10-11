package recon

import (
	"strings"
	"testing"
	"time"

	"github.com/wukan/wukan/internal/ipinfo"
)

// ⭐ P2-1：根域迁移轨迹发现
func TestAnalyze_PDNMigration(t *testing.T) {
	now := time.Now()
	rep := &Report{
		Target: "example.com",
		Passive: &PassiveDNSResult{Timeline: []PDNSTimelineEntry{
			{Hostname: "example.com", IP: "93.184.216.34",
				FirstSeen: now.AddDate(-10, 0, 0), LastSeen: now.AddDate(-2, 0, 0)},
			{Hostname: "example.com", IP: "104.20.23.154",
				FirstSeen: now.AddDate(-2, 0, 0), LastSeen: now},
			{Hostname: "www.example.com", IP: "104.20.23.155",
				FirstSeen: now, LastSeen: now},
		}},
	}
	var found *Finding
	findings := Analyze(rep)
	for i := range findings {
		if findings[i].Type == "pdn_migration" {
			found = &findings[i]
		}
	}
	if found == nil {
		t.Fatal("根域有 2+ 条时间线记录时应报 pdn_migration")
	}
	ev := strings.Join(found.Evidence, "|")
	if !strings.Contains(ev, "93.184.216.34") || !strings.Contains(ev, "104.20.23.154") {
		t.Errorf("证据应包含迁移轨迹的 IP：%v", found.Evidence)
	}
	if !strings.Contains(ev, "→") {
		t.Errorf("证据应呈现 first → last 时间区间：%v", found.Evidence)
	}
	if found.Level != "info" {
		t.Errorf("pdn_migration 应为 info，实际 %s", found.Level)
	}

	// 只有 1 条记录 → 不报（没有迁移可言）
	rep2 := &Report{
		Target: "example.com",
		Passive: &PassiveDNSResult{Timeline: []PDNSTimelineEntry{
			{Hostname: "example.com", IP: "1.2.3.4", FirstSeen: now, LastSeen: now},
		}},
	}
	for _, f := range Analyze(rep2) {
		if f.Type == "pdn_migration" {
			t.Errorf("单条记录不应报迁移：%+v", f)
		}
	}
}

// ⭐⭐ P2-2：源站候选推断（仅 CDN 场景 + 只给线索不探测）
func TestAnalyze_OriginCandidate(t *testing.T) {
	rep := &Report{
		Target: "example.com",
		DNS:    &DNSResult{IPs: []string{"1.1.1.1"}},
		IPInfo: []*ipinfo.Info{
			{IP: "1.1.1.1", Valid: true, Flags: []string{"cdn"}, FlagSources: []string{"org"}},
		},
		Passive: &PassiveDNSResult{
			Records: map[string][]string{"example.com": {"1.1.1.1", "9.9.9.9"}},
			Timeline: []PDNSTimelineEntry{
				{Hostname: "example.com", IP: "9.9.9.9",
					LastSeen: time.Date(2023, 5, 1, 0, 0, 0, 0, time.UTC)},
			},
		},
		ReverseIP: []*ReverseIPResult{
			{IP: "9.9.9.9", Hostnames: []string{"a.com", "b.com"}},
		},
	}
	var found *Finding
	for _, f := range Analyze(rep) {
		if f.Type == "origin_candidate" {
			found = &f
		}
	}
	if found == nil {
		t.Fatal("CDN 场景 + 非当前历史 IP 应报 origin_candidate")
	}
	ev := strings.Join(found.Evidence, "|")
	if !strings.Contains(ev, "9.9.9.9") {
		t.Errorf("证据应含候选 IP：%v", found.Evidence)
	}
	if !strings.Contains(ev, "2023-05") {
		t.Errorf("证据应含最后出现时间（来自 P2-1 时间线）：%v", found.Evidence)
	}
	if !strings.Contains(ev, "2 个域名") {
		t.Errorf("证据应含反查数据：%v", found.Evidence)
	}
	// ⭐ 判读必须包含"不要直接探测归属不明的 IP"的合规提醒
	if !strings.Contains(found.Detail, "不要直接探测") {
		t.Errorf("判读必须包含合规提醒：%s", found.Detail)
	}
	// 当前 IP 不应成为候选
	if strings.Contains(ev, "1.1.1.1") {
		t.Errorf("当前解析中的 IP 不应是候选：%v", found.Evidence)
	}

	// 无 CDN → 不推断（当前 IP 就是源站）
	rep2 := &Report{
		Target: "example.com",
		DNS:    &DNSResult{IPs: []string{"1.1.1.1"}},
		IPInfo: []*ipinfo.Info{
			{IP: "1.1.1.1", Valid: true, Flags: []string{"cloud"}, FlagSources: []string{"org"}},
		},
		Passive: &PassiveDNSResult{
			Records: map[string][]string{"example.com": {"1.1.1.1", "9.9.9.9"}},
		},
	}
	for _, f := range Analyze(rep2) {
		if f.Type == "origin_candidate" {
			t.Errorf("无 CDN 时不应推断源站候选：%+v", f)
		}
	}
}
