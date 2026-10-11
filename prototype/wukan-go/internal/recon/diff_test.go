package recon

import (
	"testing"
	"time"
)

// mkSnap 构造测试快照（默认覆盖完整 —— 覆盖率门控的测试另行覆盖）
func mkSnap(target string, mod func(*Snapshot)) *Snapshot {
	s := &Snapshot{
		Target:  target,
		TakenAt: time.Now().UTC(),
		Coverage: SnapshotCoverage{
			DNS: true, CT: true, Passive: true,
			Ports: true, PortsSpec: "top100", Tech: true,
		},
	}
	if mod != nil {
		mod(s)
	}
	return s
}

// findChanges 按 kind 过滤变化
func findChanges(d *SnapshotDiff, kind string) []Change {
	var out []Change
	for _, c := range d.Changes {
		if c.Kind == kind {
			out = append(out, c)
		}
	}
	return out
}

// ⭐ 子域增删：a 消失、c 新增、b 不变
func TestDiffSnapshots_SubdomainChanges(t *testing.T) {
	prev := mkSnap("example.com", func(s *Snapshot) {
		s.Subdomains = []string{"a.example.com", "b.example.com"}
	})
	curr := mkSnap("example.com", func(s *Snapshot) {
		s.Subdomains = []string{"b.example.com", "c.example.com"}
	})
	d := DiffSnapshots(prev, curr)
	if d == nil {
		t.Fatal("应返回差异")
	}

	added := findChanges(d, ChangeSubdomainAdded)
	removed := findChanges(d, ChangeSubdomainRemoved)
	if len(added) != 1 || added[0].Target != "c.example.com" {
		t.Errorf("应报 1 个新增子域 c.example.com，实际 %+v", added)
	}
	if len(removed) != 1 || removed[0].Target != "a.example.com" {
		t.Errorf("应报 1 个消失子域 a.example.com，实际 %+v", removed)
	}
	if len(d.Changes) != 2 {
		t.Errorf("b.example.com 未变化不应产生记录，实际 %d 条", len(d.Changes))
	}
}

// ⭐ 大小写归一：域名不区分大小写，不能因为大小写差异报"变化"（零假阳性）
func TestDiffSnapshots_CaseNormalization(t *testing.T) {
	prev := mkSnap("example.com", func(s *Snapshot) {
		s.Subdomains = []string{"WWW.Example.COM", "API.example.com"}
		s.IPs = []string{"1.2.3.4"}
	})
	curr := mkSnap("example.com", func(s *Snapshot) {
		s.Subdomains = []string{"www.example.com", "api.EXAMPLE.com"}
		s.IPs = []string{"1.2.3.4"}
	})
	d := DiffSnapshots(prev, curr)
	if !d.IsEmpty() {
		t.Errorf("仅大小写不同不应报变化：%+v", d.Changes)
	}
}

// 解析 IP 增删
func TestDiffSnapshots_IPChanges(t *testing.T) {
	prev := mkSnap("example.com", func(s *Snapshot) {
		s.IPs = []string{"1.2.3.4", "5.6.7.8"}
	})
	curr := mkSnap("example.com", func(s *Snapshot) {
		s.IPs = []string{"1.2.3.4", "9.9.9.9"}
	})
	d := DiffSnapshots(prev, curr)

	added := findChanges(d, ChangeIPAdded)
	removed := findChanges(d, ChangeIPRemoved)
	if len(added) != 1 || added[0].Target != "9.9.9.9" {
		t.Errorf("应报新增 IP 9.9.9.9，实际 %+v", added)
	}
	if len(removed) != 1 || removed[0].Target != "5.6.7.8" {
		t.Errorf("应报消失 IP 5.6.7.8，实际 %+v", removed)
	}
}

// ⭐ 端口变化：新增开放 / 不再开放 / 服务变化
func TestDiffSnapshots_PortChanges(t *testing.T) {
	prev := mkSnap("example.com", func(s *Snapshot) {
		s.OpenPorts = []SnapshotPort{
			{Host: "example.com", IP: "1.2.3.4", Port: 80, Service: "http"},
			{Host: "example.com", IP: "1.2.3.4", Port: 443, Service: "https"},
			{Host: "example.com", IP: "1.2.3.4", Port: 22, Service: "ssh"},
		}
	})
	curr := mkSnap("example.com", func(s *Snapshot) {
		s.OpenPorts = []SnapshotPort{
			{Host: "example.com", IP: "1.2.3.4", Port: 80, Service: "http"},
			{Host: "example.com", IP: "1.2.3.4", Port: 8443, Service: "https-alt"},
			{Host: "example.com", IP: "1.2.3.4", Port: 22, Service: "telnet"},
		}
	})
	d := DiffSnapshots(prev, curr)

	added := findChanges(d, ChangePortAdded)
	removed := findChanges(d, ChangePortRemoved)
	changed := findChanges(d, ChangePortServiceChanged)
	if len(added) != 1 || added[0].Target != "1.2.3.4:8443" {
		t.Errorf("应报新增端口 1.2.3.4:8443，实际 %+v", added)
	}
	if len(removed) != 1 || removed[0].Target != "1.2.3.4:443" {
		t.Errorf("应报消失端口 1.2.3.4:443，实际 %+v", removed)
	}
	if len(changed) != 1 || changed[0].Target != "1.2.3.4:22" {
		t.Errorf("应报服务变化 1.2.3.4:22（ssh→telnet），实际 %+v", changed)
	}
	// 服务变化必须带 Before/After
	if changed[0].Before != "ssh" || changed[0].After != "telnet" {
		t.Errorf("服务变化应带 Before/After，实际 %q → %q", changed[0].Before, changed[0].After)
	}
	// 80 端口无变化
	if len(d.Changes) != 3 {
		t.Errorf("应共 3 条变化，实际 %d 条：%+v", len(d.Changes), d.Changes)
	}
}

// ⭐ 零假阳性：服务识别从有到无（可能是 banner 抓取失败）不报"变化"
func TestDiffSnapshots_PortServiceEmptyNoNoise(t *testing.T) {
	prev := mkSnap("example.com", func(s *Snapshot) {
		s.OpenPorts = []SnapshotPort{{IP: "1.2.3.4", Port: 3306, Service: "mysql"}}
	})
	curr := mkSnap("example.com", func(s *Snapshot) {
		s.OpenPorts = []SnapshotPort{{IP: "1.2.3.4", Port: 3306, Service: ""}}
	})
	d := DiffSnapshots(prev, curr)
	if !d.IsEmpty() {
		t.Errorf("单侧服务识别为空不应报变化（可能是抓取抖动）：%+v", d.Changes)
	}
}

// ⭐ tech 指纹变化：状态码 / Server / favicon / 标题
func TestDiffSnapshots_TechChanges(t *testing.T) {
	prev := mkSnap("example.com", func(s *Snapshot) {
		s.Tech = []SnapshotTech{
			{URL: "https://a.example.com", Status: 200, Server: "nginx/1.24", Title: "A", FaviconProduct: "Grafana"},
			{URL: "https://b.example.com", Status: 200, Server: "apache", Title: "Old"},
			{URL: "https://c.example.com", Status: 200, Server: "nginx", FaviconProduct: "Jenkins"},
			{URL: "https://d.example.com", Status: 200, Server: "nginx"},
			{URL: "https://e.example.com", Status: 0}, // 上次探测失败
		}
	})
	curr := mkSnap("example.com", func(s *Snapshot) {
		s.Tech = []SnapshotTech{
			{URL: "https://a.example.com", Status: 403, Server: "nginx/1.24", Title: "A", FaviconProduct: "Grafana"},
			{URL: "https://b.example.com", Status: 200, Server: "apache", Title: "New"},
			{URL: "https://c.example.com", Status: 200, Server: "nginx", FaviconProduct: "GitLab"},
			{URL: "https://d.example.com", Status: 200, Server: "nginx/1.25"}, // Server 变化
			{URL: "https://e.example.com", Status: 200},                       // 恢复
		}
	})
	d := DiffSnapshots(prev, curr)

	if got := findChanges(d, ChangeTechStatusChanged); len(got) != 2 {
		t.Errorf("应报 2 处状态变化（a: 200→403；e: 失败→200），实际 %+v", got)
	}
	if got := findChanges(d, ChangeTechServerChanged); len(got) != 1 || got[0].Target != "https://d.example.com" {
		t.Errorf("应报 d 的 Server 变化，实际 %+v", got)
	}
	if got := findChanges(d, ChangeTechFaviconChanged); len(got) != 1 || got[0].Target != "https://c.example.com" {
		t.Errorf("应报 c 的 favicon 变化（Jenkins→GitLab），实际 %+v", got)
	}
	if got := findChanges(d, ChangeTechTitleChanged); len(got) != 1 || got[0].Target != "https://b.example.com" {
		t.Errorf("应报 b 的标题变化，实际 %+v", got)
	}
	// 状态变化的 Before/After 必须可读
	for _, c := range findChanges(d, ChangeTechStatusChanged) {
		if c.Target == "https://e.example.com" && (c.Before != "探测失败" || c.After != "200") {
			t.Errorf("e 的状态变化应为 探测失败→200，实际 %q→%q", c.Before, c.After)
		}
	}
}

// ⭐ tech 零假阳性：单侧为空的字段不参与比较
func TestDiffSnapshots_TechEmptyFieldNoNoise(t *testing.T) {
	prev := mkSnap("example.com", func(s *Snapshot) {
		s.Tech = []SnapshotTech{{URL: "https://a.example.com", Status: 200, Server: "", Title: "", FaviconProduct: ""}}
	})
	curr := mkSnap("example.com", func(s *Snapshot) {
		s.Tech = []SnapshotTech{{URL: "https://a.example.com", Status: 200, Server: "nginx", Title: "首页", FaviconProduct: "Grafana"}}
	})
	d := DiffSnapshots(prev, curr)
	if !d.IsEmpty() {
		t.Errorf("单侧字段为空不应报变化（识别能力变化 ≠ 资产变化）：%+v", d.Changes)
	}
}

// ⭐ tech 端点增删被**刻意抑制**：
//
// 快照的 tech 列表包含失败探测（Status=0），"URL 不在列表里"只能说明
// "本次没探测它"（目标选择随 CT/被动结果与 tech-max 截断洗牌），
// 不能说明消失 —— 端点不可达会以 status_changed（→探测失败）出现。
// 产出 tech_added/removed 只会是选择噪音（审查发现的 H1 相关）。
func TestDiffSnapshots_TechAddRemove_Suppressed(t *testing.T) {
	prev := mkSnap("example.com", func(s *Snapshot) {
		s.Tech = []SnapshotTech{{URL: "https://a.example.com", Status: 200}}
	})
	curr := mkSnap("example.com", func(s *Snapshot) {
		s.Tech = []SnapshotTech{{URL: "https://b.example.com", Status: 200}}
	})
	d := DiffSnapshots(prev, curr)
	if !d.IsEmpty() {
		t.Errorf("tech 端点增删不应产出变化（选择依赖，非资产变化）：%+v", d.Changes)
	}
}

// ⭐ P1-3：JARM / H2 SETTINGS 变化检测（双方非空才比 —— 零假阳性）
func TestDiffSnapshots_TechJARMAndH2(t *testing.T) {
	prev := mkSnap("example.com", func(s *Snapshot) {
		s.Tech = []SnapshotTech{{
			URL: "https://a.example.com", Status: 200,
			JARM:       "27d40d40d00040d1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c",
			H2Settings: "1:65536;4:6291456|15663105",
		}}
	})
	curr := mkSnap("example.com", func(s *Snapshot) {
		s.Tech = []SnapshotTech{{
			URL: "https://a.example.com", Status: 200,
			JARM:       "29d1fb00029d29d1fc29d1fb1fb29d46f0ca2446873e81c43869f3dca73bff",
			H2Settings: "2:0;3:100;4:2097152|0",
		}}
	})
	d := DiffSnapshots(prev, curr)
	jarm := findChanges(d, ChangeTechJARMChanged)
	h2 := findChanges(d, ChangeTechH2Changed)
	if len(jarm) != 1 || jarm[0].Level != "medium" {
		t.Errorf("应报 1 条 tech_jarm_changed(medium)，实际 %+v", jarm)
	}
	if len(h2) != 1 || h2[0].Level != "low" {
		t.Errorf("应报 1 条 tech_h2_changed(low)，实际 %+v", h2)
	}
	if jarm[0].Before == "" || jarm[0].After == "" {
		t.Error("JARM 变化应带 Before/After")
	}

	// 单侧为空（未采集）→ 不报
	prev2 := mkSnap("example.com", func(s *Snapshot) {
		s.Tech = []SnapshotTech{{URL: "https://a.example.com", Status: 200}}
	})
	curr2 := mkSnap("example.com", func(s *Snapshot) {
		s.Tech = []SnapshotTech{{
			URL: "https://a.example.com", Status: 200,
			JARM: "27d40d40d00040d1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c",
		}}
	})
	d2 := DiffSnapshots(prev2, curr2)
	if len(findChanges(d2, ChangeTechJARMChanged)) != 0 {
		t.Errorf("单侧未采集 JARM 不应报变化：%+v", d2.Changes)
	}
}

// 完全一致 → 空 diff（顺序不同也算一致）
func TestDiffSnapshots_NoChanges(t *testing.T) {
	mk := func() *Snapshot {
		return mkSnap("example.com", func(s *Snapshot) {
			s.IPs = []string{"1.2.3.4"}
			s.Subdomains = []string{"a.example.com", "b.example.com"}
			s.OpenPorts = []SnapshotPort{{IP: "1.2.3.4", Port: 443, Service: "https"}}
			s.Tech = []SnapshotTech{{URL: "https://a.example.com", Status: 200, Server: "nginx"}}
		})
	}
	prev, curr := mk(), mk()
	// 打乱顺序（内容相同）
	curr.Subdomains = []string{"b.example.com", "a.example.com"}
	d := DiffSnapshots(prev, curr)
	if !d.IsEmpty() {
		t.Errorf("内容一致不应报变化：%+v", d.Changes)
	}
	if len(d.Changes) != 0 {
		t.Errorf("Changes 应为空，实际 %d", len(d.Changes))
	}
}

// ⭐⭐ 每条变化必须带判读（Detail）且级别合法 —— 对齐 TestConflicts_HaveImplication
func TestDiffSnapshots_EveryChangeHasDetail(t *testing.T) {
	prev := mkSnap("example.com", func(s *Snapshot) {
		s.IPs = []string{"1.2.3.4"}
		s.Subdomains = []string{"old.example.com"}
		s.OpenPorts = []SnapshotPort{{IP: "1.2.3.4", Port: 80, Service: "http"}, {IP: "1.2.3.4", Port: 22, Service: "ssh"}}
		s.Tech = []SnapshotTech{{URL: "https://a.example.com", Status: 200, Server: "nginx/1.24", Title: "A", FaviconProduct: "Grafana"}}
	})
	curr := mkSnap("example.com", func(s *Snapshot) {
		s.IPs = []string{"9.9.9.9"}
		s.Subdomains = []string{"new.example.com"}
		s.OpenPorts = []SnapshotPort{{IP: "1.2.3.4", Port: 80, Service: "http"}, {IP: "1.2.3.4", Port: 22, Service: "telnet"}}
		s.Tech = []SnapshotTech{{URL: "https://a.example.com", Status: 403, Server: "nginx/1.25", Title: "B", FaviconProduct: "GitLab"}}
	})
	d := DiffSnapshots(prev, curr)
	if len(d.Changes) < 8 {
		t.Fatalf("应产生足够多的变化用于验证，实际 %d 条", len(d.Changes))
	}
	validLevel := map[string]bool{"high": true, "medium": true, "low": true, "info": true}
	for _, c := range d.Changes {
		if c.Detail == "" {
			t.Errorf("⭐ [%s] %s 缺少判读（Detail）—— 只报变化不给含义等于没报", c.Kind, c.Target)
		}
		if !validLevel[c.Level] {
			t.Errorf("[%s] 级别非法: %q", c.Kind, c.Level)
		}
		if c.Target == "" {
			t.Errorf("[%s] 缺少 Target", c.Kind)
		}
	}
}

// 关键类型的级别必须正确（端口新增=high，子域新增=medium，IP 新增=low）
func TestDiffSnapshots_Levels(t *testing.T) {
	prev := mkSnap("example.com", func(s *Snapshot) {
		s.Subdomains = []string{"a.example.com"}
		s.IPs = []string{"1.2.3.4"}
	})
	curr := mkSnap("example.com", func(s *Snapshot) {
		s.Subdomains = []string{"b.example.com"}
		s.IPs = []string{"5.6.7.8"}
		s.OpenPorts = []SnapshotPort{{IP: "1.2.3.4", Port: 3389, Service: "rdp"}}
	})
	d := DiffSnapshots(prev, curr)
	want := map[string]string{
		ChangeSubdomainAdded:   "medium",
		ChangeIPAdded:          "low",
		ChangePortAdded:        "high",
		ChangeSubdomainRemoved: "info",
		ChangeIPRemoved:        "info",
	}
	for kind, level := range want {
		got := findChanges(d, kind)
		if len(got) == 0 {
			t.Errorf("缺少 %s 变化", kind)
			continue
		}
		if got[0].Level != level {
			t.Errorf("%s 级别应为 %s，实际 %s", kind, level, got[0].Level)
		}
	}
}

// 不同 target 的快照不能互相 diff（防串味）
func TestDiffSnapshots_TargetMismatch(t *testing.T) {
	prev := mkSnap("a.com", nil)
	curr := mkSnap("b.com", nil)
	if d := DiffSnapshots(prev, curr); d != nil {
		t.Errorf("不同目标的快照不应产生 diff，实际 %+v", d)
	}
}

// nil 安全
func TestDiffSnapshots_NilSafety(t *testing.T) {
	curr := mkSnap("example.com", nil)
	if d := DiffSnapshots(nil, curr); d != nil {
		t.Error("prev 为 nil 应返回 nil")
	}
	if d := DiffSnapshots(curr, nil); d != nil {
		t.Error("curr 为 nil 应返回 nil")
	}
}

// 排序：高级别在前（监控场景先看危险项）
func TestDiffSnapshots_Ordering(t *testing.T) {
	prev := mkSnap("example.com", func(s *Snapshot) {
		s.Subdomains = []string{"old.example.com"}
		s.Tech = []SnapshotTech{{URL: "https://a.example.com", Status: 200, Title: "A"}}
	})
	curr := mkSnap("example.com", func(s *Snapshot) {
		s.Subdomains = []string{"new.example.com"}
		s.OpenPorts = []SnapshotPort{{IP: "1.2.3.4", Port: 6379, Service: "redis"}}
		s.Tech = []SnapshotTech{{URL: "https://a.example.com", Status: 200, Title: "B"}}
	})
	d := DiffSnapshots(prev, curr)
	if len(d.Changes) < 4 {
		t.Fatalf("应有至少 4 条变化，实际 %d", len(d.Changes))
	}
	// 第一条必须是 high（port_added）
	if d.Changes[0].Level != "high" {
		t.Errorf("排序应高级别在前，第一条实际为 %s [%s]", d.Changes[0].Level, d.Changes[0].Kind)
	}
	// 级别顺序单调不降（high→medium→low→info）
	rank := map[string]int{"high": 0, "medium": 1, "low": 2, "info": 3}
	for i := 1; i < len(d.Changes); i++ {
		if rank[d.Changes[i].Level] < rank[d.Changes[i-1].Level] {
			t.Errorf("排序错误：第 %d 条 %s 排在第 %d 条 %s 之后",
				i+1, d.Changes[i].Level, i, d.Changes[i-1].Level)
		}
	}
}

// ⭐⭐ CDN 节点轮换：同一端口随解析 IP 移动 → 归并为 port_ip_changed（low），
// 而不是 port_added(high) + port_removed 误导用户（审查发现的 M3）
func TestDiffSnapshots_PortIPRotation(t *testing.T) {
	prev := mkSnap("example.com", func(s *Snapshot) {
		s.OpenPorts = []SnapshotPort{{IP: "1.1.1.1", Port: 443, Service: "https"}}
	})
	curr := mkSnap("example.com", func(s *Snapshot) {
		s.OpenPorts = []SnapshotPort{{IP: "2.2.2.2", Port: 443, Service: "https"}}
	})
	d := DiffSnapshots(prev, curr)
	if len(d.Changes) != 1 {
		t.Fatalf("轮换应归并为 1 条变化，实际 %d 条：%+v", len(d.Changes), d.Changes)
	}
	ch := d.Changes[0]
	if ch.Kind != ChangePortIPChanged {
		t.Errorf("应为 %s，实际 %s", ChangePortIPChanged, ch.Kind)
	}
	if ch.Level != "low" {
		t.Errorf("IP 轮换应为 low 级别（不是高危的 port_added），实际 %s", ch.Level)
	}
	if ch.Before != "1.1.1.1:443" || ch.After != "2.2.2.2:443" {
		t.Errorf("Before/After 应记录新旧地址，实际 %q → %q", ch.Before, ch.After)
	}
	// 服务不同（443 上 https vs smtp）不是轮换 → 保持高/低分开
	prev2 := mkSnap("example.com", func(s *Snapshot) {
		s.OpenPorts = []SnapshotPort{{IP: "1.1.1.1", Port: 443, Service: "https"}}
	})
	curr2 := mkSnap("example.com", func(s *Snapshot) {
		s.OpenPorts = []SnapshotPort{{IP: "2.2.2.2", Port: 443, Service: "smtp"}}
	})
	d2 := DiffSnapshots(prev2, curr2)
	if len(findChanges(d2, ChangePortAdded)) != 1 || len(findChanges(d2, ChangePortRemoved)) != 1 {
		t.Errorf("服务不同不应归并为轮换：%+v", d2.Changes)
	}
}

// ⭐⭐ 覆盖率门控（H1）：基准覆盖完整、本次 CT/被动失败 → 不产出假"消失"
func TestDiffSnapshots_CoverageGate_Subdomains(t *testing.T) {
	prev := mkSnap("example.com", func(s *Snapshot) {
		s.Subdomains = []string{"a.example.com", "b.example.com"}
	})
	curr := mkSnap("example.com", func(s *Snapshot) {
		// 本次 CT 失败：子域列表为空（但这不是资产消失！）
		s.Coverage.CT = false
	})
	d := DiffSnapshots(prev, curr)
	if got := findChanges(d, ChangeSubdomainRemoved); len(got) != 0 {
		t.Errorf("⭐ 覆盖不完整时不得报子域消失（假阳性），实际 %+v", got)
	}
	cov := findChanges(d, ChangeCoverageChanged)
	if len(cov) != 1 || cov[0].Target != CoverageCategorySubdomains {
		t.Errorf("应产出 1 条 subdomains 覆盖率说明，实际 %+v", cov)
	}
	if cov[0].Before != "完整" || cov[0].After != "不完整" {
		t.Errorf("覆盖率 Before/After 应可读，实际 %q → %q", cov[0].Before, cov[0].After)
	}
	if cov[0].Detail == "" {
		t.Error("覆盖率说明也必须带判读")
	}

	// 两侧都失败 → 静默（本来就没采，无可比性）
	curr2 := mkSnap("example.com", func(s *Snapshot) { s.Coverage.CT = false })
	prev2 := mkSnap("example.com", func(s *Snapshot) { s.Coverage.CT = false })
	if d2 := DiffSnapshots(prev2, curr2); !d2.IsEmpty() {
		t.Errorf("两侧都不完整时应静默，实际 %+v", d2.Changes)
	}
}

// ⭐⭐ 端口扫描参数不同 → 集合不可比，产出覆盖率说明而非增删
func TestDiffSnapshots_CoverageGate_PortsSpec(t *testing.T) {
	prev := mkSnap("example.com", func(s *Snapshot) {
		s.Coverage.PortsSpec = "top100"
		s.OpenPorts = []SnapshotPort{{IP: "1.2.3.4", Port: 80, Service: "http"}}
	})
	curr := mkSnap("example.com", func(s *Snapshot) {
		s.Coverage.PortsSpec = "80,443"
		s.OpenPorts = []SnapshotPort{{IP: "1.2.3.4", Port: 443, Service: "https"}}
	})
	d := DiffSnapshots(prev, curr)
	if len(findChanges(d, ChangePortAdded)) != 0 || len(findChanges(d, ChangePortRemoved)) != 0 {
		t.Errorf("参数不同时不得报端口增删，实际 %+v", d.Changes)
	}
	cov := findChanges(d, ChangeCoverageChanged)
	if len(cov) != 1 || cov[0].Target != CoverageCategoryPorts {
		t.Errorf("应产出 ports 覆盖率说明，实际 %+v", cov)
	}
	if cov[0].Before != "top100" || cov[0].After != "80,443" {
		t.Errorf("应显示参数变化，实际 %q → %q", cov[0].Before, cov[0].After)
	}

	// 上次没扫、本次扫了 → 覆盖率说明（不能把首次扫描结果报成"新增端口"）
	prev3 := mkSnap("example.com", func(s *Snapshot) { s.Coverage.Ports = false })
	curr3 := mkSnap("example.com", func(s *Snapshot) {
		s.OpenPorts = []SnapshotPort{{IP: "1.2.3.4", Port: 22, Service: "ssh"}}
	})
	d3 := DiffSnapshots(prev3, curr3)
	if len(findChanges(d3, ChangePortAdded)) != 0 {
		t.Errorf("上次未扫描时不得报端口新增，实际 %+v", d3.Changes)
	}
}

// 覆盖率说明本身也要带判读（补充 EveryChangeHasDetail 的场景）
func TestDiffSnapshots_CoverageChangeHasDetail(t *testing.T) {
	prev := mkSnap("example.com", nil)
	curr := mkSnap("example.com", func(s *Snapshot) { s.Coverage.Tech = false })
	d := DiffSnapshots(prev, curr)
	if len(d.Changes) != 1 {
		t.Fatalf("应有 1 条覆盖率说明，实际 %+v", d.Changes)
	}
	ch := d.Changes[0]
	if ch.Kind != ChangeCoverageChanged || ch.Detail == "" || ch.Level != "info" {
		t.Errorf("覆盖率说明不完整：%+v", ch)
	}
}

// --since 时长解析：支持 Nd 天 + Go 标准时长
func TestParseSinceDuration(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"7d", 7 * 24 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"90m", 90 * time.Minute, false},
		{"106751d", 106751 * 24 * time.Hour, false}, // 上限内
		{"106752d", 0, true},                        // 溢出 → 必须报错（审查 L2）
		{"2000000000d", 0, true},
		{"0d", 0, true},
		{"-1d", 0, true},
		{"abc", 0, true},
		{"3", 0, true},
		{"1.5d", 0, true},
		{"", 0, true},
	}
	for _, c := range cases {
		got, err := ParseSinceDuration(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseSinceDuration(%q) 应报错", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSinceDuration(%q) 出错: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseSinceDuration(%q) = %v，期望 %v", c.in, got, c.want)
		}
	}
}
