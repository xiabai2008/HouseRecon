package recon

import (
	"strings"
	"testing"
	"time"
)

// ⭐ 本地时间线聚合：首见/末见/是否仍存在/出现次数
func TestBuildLocalTimeline(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	s1 := mkSnap("example.com", func(s *Snapshot) {
		s.TakenAt = t0
		s.IPs = []string{"1.1.1.1"}
		s.Subdomains = []string{"a.example.com"}
		s.OpenPorts = []SnapshotPort{{IP: "1.1.1.1", Port: 443, Service: "https"}}
	})
	s2 := mkSnap("example.com", func(s *Snapshot) {
		s.TakenAt = t0.Add(24 * time.Hour)
		s.IPs = []string{"1.1.1.1", "2.2.2.2"}
		s.Subdomains = []string{"a.example.com", "b.example.com"}
		s.OpenPorts = []SnapshotPort{{IP: "1.1.1.1", Port: 443, Service: "https"}}
	})
	s3 := mkSnap("example.com", func(s *Snapshot) {
		s.TakenAt = t0.Add(48 * time.Hour)
		s.IPs = []string{"2.2.2.2"}
		s.Subdomains = []string{"a.example.com"}
		s.OpenPorts = []SnapshotPort{{IP: "2.2.2.2", Port: 443, Service: "https"}}
	})

	tl := BuildLocalTimeline([]*Snapshot{s1, s2, s3})
	if tl == nil {
		t.Fatal("应返回时间线")
	}
	if tl.Snapshots != 3 || tl.Target != "example.com" {
		t.Errorf("基础信息错误：%+v", tl)
	}
	if !tl.From.Equal(t0) || !tl.To.Equal(t0.Add(48*time.Hour)) {
		t.Errorf("时间范围错误：%v → %v", tl.From, tl.To)
	}

	// IP 迁移轨迹：1.1.1.1 先出现后消失；2.2.2.2 后出现且仍在
	if len(tl.IPs) != 2 {
		t.Fatalf("应有 2 个 IP span，实际 %+v", tl.IPs)
	}
	ip1, ip2 := tl.IPs[0], tl.IPs[1]
	if ip1.Key != "1.1.1.1" || ip1.Present {
		t.Errorf("1.1.1.1 应已消失：%+v", ip1)
	}
	if !ip1.FirstSeen.Equal(t0) || !ip1.LastSeen.Equal(t0.Add(24*time.Hour)) || ip1.Snapshots != 2 {
		t.Errorf("1.1.1.1 区间错误：%+v", ip1)
	}
	if ip2.Key != "2.2.2.2" || !ip2.Present || !ip2.FirstSeen.Equal(t0.Add(24*time.Hour)) {
		t.Errorf("2.2.2.2 区间错误：%+v", ip2)
	}

	// 子域：a 仍在；b 只在 s2 出现一次 → 已消失
	if len(tl.Subdomains) != 2 {
		t.Fatalf("应有 2 个子域 span，实际 %+v", tl.Subdomains)
	}
	if tl.Subdomains[0].Key != "a.example.com" || !tl.Subdomains[0].Present {
		t.Errorf("a 应仍存在：%+v", tl.Subdomains[0])
	}
	if tl.Subdomains[1].Key != "b.example.com" || tl.Subdomains[1].Present || tl.Subdomains[1].Snapshots != 1 {
		t.Errorf("b 应已消失且只出现 1 次：%+v", tl.Subdomains[1])
	}

	// 端口：1.1.1.1:443 消失；2.2.2.2:443 仍在
	if len(tl.Ports) != 2 {
		t.Fatalf("应有 2 个端口 span，实际 %+v", tl.Ports)
	}
	if tl.Ports[0].Key != "1.1.1.1:443" || tl.Ports[0].Present {
		t.Errorf("1.1.1.1:443 应已消失：%+v", tl.Ports[0])
	}
	if tl.Ports[1].Key != "2.2.2.2:443" || !tl.Ports[1].Present {
		t.Errorf("2.2.2.2:443 应仍存在：%+v", tl.Ports[1])
	}

	// nil / 空防御
	if BuildLocalTimeline(nil) != nil {
		t.Error("nil 应返回 nil")
	}
	if BuildLocalTimeline([]*Snapshot{nil, nil}) != nil {
		t.Error("全 nil 应返回 nil")
	}
}

// ⭐⭐ H3：最新快照覆盖不完整时，不得把"本次没采"误报成"已消失"
func TestBuildLocalTimeline_CoverageBasis(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	s1 := mkSnap("example.com", func(s *Snapshot) {
		s.TakenAt = t0
		s.Subdomains = []string{"a.example.com"}
		s.OpenPorts = []SnapshotPort{{IP: "1.1.1.1", Port: 443, Service: "https"}}
	})
	// 最新快照：CT/被动/端口全部没采（数据源失败或忘了参数）
	s2 := mkSnap("example.com", func(s *Snapshot) {
		s.TakenAt = t0.Add(24 * time.Hour)
		s.Coverage.CT = false
		s.Coverage.Passive = false
		s.Coverage.Ports = false
		s.OpenPorts = nil
	})
	tl := BuildLocalTimeline([]*Snapshot{s1, s2})
	if !tl.Subdomains[0].Present {
		t.Error("⭐ 覆盖不完整的最新快照不得把子域判成已消失")
	}
	if !tl.Ports[0].Present {
		t.Error("⭐ 覆盖不完整的最新快照不得把端口判成已消失")
	}
	if tl.Note == "" {
		t.Error("应提示最新快照覆盖不完整")
	}

	// 对照：覆盖完整的快照里真的消失 → 判为已消失
	s3 := mkSnap("example.com", func(s *Snapshot) {
		s.TakenAt = t0.Add(48 * time.Hour)
		// 覆盖完整（mkSnap 默认），但子域/端口为空 → 真消失
	})
	tl2 := BuildLocalTimeline([]*Snapshot{s1, s3})
	if tl2.Subdomains[0].Present {
		t.Error("覆盖完整快照中消失应判为已消失")
	}
	if tl2.Ports[0].Present {
		t.Error("覆盖完整快照中消失的端口应判为已消失")
	}
}

// 渲染：包含关键标记
func TestWriteLocalTimeline(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	s1 := mkSnap("example.com", func(s *Snapshot) {
		s.TakenAt = t0
		s.IPs = []string{"1.1.1.1"}
	})
	s2 := mkSnap("example.com", func(s *Snapshot) {
		s.TakenAt = t0.Add(24 * time.Hour)
		s.IPs = []string{"2.2.2.2"}
	})
	tl := BuildLocalTimeline([]*Snapshot{s1, s2})

	var b strings.Builder
	WriteLocalTimeline(&b, tl)
	out := b.String()
	for _, want := range []string{
		"资产时间线", "example.com", "迁移轨迹",
		"1.1.1.1", "已消失", "2.2.2.2", "现在",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("渲染缺少 %q：\n%s", want, out)
		}
	}
	// nil 安全（不 panic）
	var b2 strings.Builder
	WriteLocalTimeline(&b2, nil)
	if b2.Len() != 0 {
		t.Error("nil 不应输出内容")
	}
}
