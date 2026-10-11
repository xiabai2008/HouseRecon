package recon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wukan/wukan/internal/httpprobe"
	"github.com/wukan/wukan/internal/portscan"
)

// ⭐ 从 Report 提取快照：去重、排序、归一化、跳过无效项
func TestBuildSnapshot_Extraction(t *testing.T) {
	rep := &Report{
		Target: "https://EXAMPLE.com/path",
		DNS:    &DNSResult{IPs: []string{"1.2.3.4", "5.6.7.8", "1.2.3.4"}},
		CT: &SubdomainResult{
			Subdomains: []*SubdomainInfo{
				{Name: "www.example.com"},
				{Name: "WWW.example.com"},                 // 大小写重复
				{Name: "*.example.com", IsWildcard: true}, // 泛域名不是资产名，跳过
				{Name: "example.com"},                     // ⭐ 根域本身不算"子域"，跳过
			},
			SourcesUsed: []string{"certspotter"},
		},
		Passive: &PassiveDNSResult{
			Records: map[string][]string{
				"api.example.com": {"1.2.3.4"},
				"www.example.com": nil, // 与 CT 重复
			},
			SourcesUsed: []string{"hackertarget/hostsearch"},
		},
		Ports: []portscan.PortResult{
			{Host: "example.com", IP: "1.2.3.4", Port: 443, State: portscan.StateOpen, Service: "https"},
			{Host: "example.com", IP: "1.2.3.4", Port: 22, State: portscan.StateClosed}, // 未开放，跳过
		},
		PortsSpec: "top100",
		Tech: []*httpprobe.ProbeResult{
			{URL: "https://example.com", StatusCode: 200, Server: "nginx",
				JARM:       "27d40d40d00040d1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c",
				H2Settings: "1:65536|15663105"},
			{URL: "https://dead.example.com", Err: "timeout"}, // 失败也要记录（Status=0）
			nil, // 防御
		},
	}
	snap := BuildSnapshot(rep)
	if snap == nil {
		t.Fatal("应返回快照")
	}
	// 目标归一化：去协议、去路径、小写（与 recon/diff 同一口径）
	if snap.Target != "example.com" {
		t.Errorf("Target 应归一化为 example.com，实际 %q", snap.Target)
	}
	if snap.TakenAt.IsZero() {
		t.Error("TakenAt 不应为零值")
	}
	// 覆盖率
	if !snap.Coverage.DNS || !snap.Coverage.CT || !snap.Coverage.Passive ||
		!snap.Coverage.Ports || !snap.Coverage.Tech {
		t.Errorf("全部数据源成功时覆盖率应完整：%+v", snap.Coverage)
	}
	if snap.Coverage.PortsSpec != "top100" {
		t.Errorf("应记录端口扫描参数，实际 %q", snap.Coverage.PortsSpec)
	}
	// IP 去重 + 排序
	if len(snap.IPs) != 2 || snap.IPs[0] != "1.2.3.4" || snap.IPs[1] != "5.6.7.8" {
		t.Errorf("IPs 应去重排序，实际 %v", snap.IPs)
	}
	// 子域：CT + 被动 DNS 合并去重（大小写归一、跳过泛域名与根域）
	if len(snap.Subdomains) != 2 ||
		snap.Subdomains[0] != "api.example.com" || snap.Subdomains[1] != "www.example.com" {
		t.Errorf("Subdomains 应合并去重排序（含根域剔除），实际 %v", snap.Subdomains)
	}
	// 端口：只保留开放
	if len(snap.OpenPorts) != 1 || snap.OpenPorts[0].Port != 443 {
		t.Errorf("OpenPorts 应只保留开放端口，实际 %+v", snap.OpenPorts)
	}
	// tech：失败项记录为 Status=0，按 URL 排序
	if len(snap.Tech) != 2 {
		t.Fatalf("Tech 应有 2 条（含失败项），实际 %d", len(snap.Tech))
	}
	if snap.Tech[0].URL != "https://dead.example.com" || snap.Tech[0].Status != 0 {
		t.Errorf("失败探测应记录为 Status=0，实际 %+v", snap.Tech[0])
	}
	if snap.Tech[1].URL != "https://example.com" || snap.Tech[1].Server != "nginx" {
		t.Errorf("tech 解析错误：%+v", snap.Tech[1])
	}
	// P1-3：JARM / H2 指纹也要进快照
	if snap.Tech[1].JARM == "" || snap.Tech[1].H2Settings == "" {
		t.Errorf("快照应包含 JARM/H2 指纹：%+v", snap.Tech[1])
	}
}

// ⭐ 覆盖率判定：数据源失败时必须为 false（否则差异引擎会误报"消失"）
func TestBuildSnapshot_Coverage(t *testing.T) {
	// CT 全失败：SourcesUsed 为空
	rep := &Report{
		Target: "example.com",
		DNS:    &DNSResult{Err: "解析失败"},
		CT:     &SubdomainResult{SourcesFailed: map[string]string{"certspotter": "限流"}},
		Passive: &PassiveDNSResult{
			SourcesFailed: map[string]string{"hackertarget/hostsearch": "限流"},
		},
	}
	snap := BuildSnapshot(rep)
	if snap.Coverage.DNS {
		t.Error("DNS 出错时覆盖率应为 false")
	}
	if snap.Coverage.CT {
		t.Error("CT 无成功来源时覆盖率应为 false")
	}
	if snap.Coverage.Passive {
		t.Error("被动 DNS 无成功来源时覆盖率应为 false")
	}
	if snap.Coverage.Ports || snap.Coverage.Tech {
		t.Error("未跑端口/指纹时覆盖率应为 false")
	}

	// 被动 DNS "有来源但没记录"（hostsearch 失败、dnslookup 成功）→ 不可信
	rep2 := &Report{
		Target: "example.com",
		Passive: &PassiveDNSResult{
			SourcesUsed:   []string{"hackertarget/dnslookup"},
			SourcesFailed: map[string]string{"hackertarget/hostsearch": "限流"},
		},
	}
	if BuildSnapshot(rep2).Coverage.Passive {
		t.Error("被动 DNS 无实际记录时覆盖率应为 false")
	}
}

// nil / 空报告防御
func TestBuildSnapshot_NilSafety(t *testing.T) {
	if snap := BuildSnapshot(nil); snap != nil {
		t.Error("nil report 应返回 nil")
	}
	snap := BuildSnapshot(&Report{Target: "example.com"})
	if snap == nil || snap.Target != "example.com" {
		t.Errorf("空报告应返回最小快照，实际 %+v", snap)
	}
	if len(snap.IPs)+len(snap.Subdomains)+len(snap.OpenPorts)+len(snap.Tech) != 0 {
		t.Errorf("空报告不应有资产项：%+v", snap)
	}
}

// 子域尾部点号归一化
func TestBuildSnapshot_TrailingDot(t *testing.T) {
	rep := &Report{
		Target: "example.com",
		CT: &SubdomainResult{Subdomains: []*SubdomainInfo{
			{Name: "www.example.com."},
		}},
	}
	snap := BuildSnapshot(rep)
	if len(snap.Subdomains) != 1 || snap.Subdomains[0] != "www.example.com" {
		t.Errorf("尾部点号应被去掉，实际 %v", snap.Subdomains)
	}
}

// ⭐ 存储：保存并返回上一次快照；首次返回 nil
func TestSnapshotStore_SaveAndPrevious(t *testing.T) {
	store := NewSnapshotStore(t.TempDir(), 30)

	s1 := mkSnap("example.com", func(s *Snapshot) { s.IPs = []string{"1.1.1.1"} })
	prev, appended, err := store.SaveAndPrevious(s1)
	if err != nil {
		t.Fatal(err)
	}
	if prev != nil {
		t.Error("首次保存应返回 nil（无对比基准）")
	}
	if !appended {
		t.Error("首次保存应追加")
	}

	s2 := mkSnap("example.com", func(s *Snapshot) { s.IPs = []string{"2.2.2.2"} })
	prev, _, err = store.SaveAndPrevious(s2)
	if err != nil {
		t.Fatal(err)
	}
	if prev == nil || prev.IPs[0] != "1.1.1.1" {
		t.Errorf("第二次保存应返回第一次的快照，实际 %+v", prev)
	}

	s3 := mkSnap("example.com", func(s *Snapshot) { s.IPs = []string{"3.3.3.3"} })
	if _, _, err := store.SaveAndPrevious(s3); err != nil {
		t.Fatal(err)
	}
	snaps, err := store.Load("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 3 {
		t.Fatalf("应有 3 个快照，实际 %d", len(snaps))
	}
	// 按时间从旧到新
	if snaps[0].IPs[0] != "1.1.1.1" || snaps[1].IPs[0] != "2.2.2.2" {
		t.Errorf("快照顺序应为从旧到新，实际 %v / %v", snaps[0].IPs, snaps[1].IPs)
	}
}

// ⭐ 内容去重：相同内容在心跳窗口内不重复追加（防高频运行刷爆历史）
func TestSnapshotStore_Dedup(t *testing.T) {
	store := NewSnapshotStore(t.TempDir(), 30)

	s1 := mkSnap("example.com", func(s *Snapshot) { s.IPs = []string{"1.1.1.1"} })
	if _, _, err := store.SaveAndPrevious(s1); err != nil {
		t.Fatal(err)
	}

	// 相同内容、间隔 1 分钟 → 跳过追加，prev 仍返回
	s2 := mkSnap("example.com", func(s *Snapshot) { s.IPs = []string{"1.1.1.1"} })
	prev, appended, err := store.SaveAndPrevious(s2)
	if err != nil {
		t.Fatal(err)
	}
	if appended {
		t.Error("相同内容在心跳窗口内不应追加")
	}
	if prev == nil {
		t.Error("跳过追加时仍应返回最近快照作为对比基准")
	}
	if snaps, _ := store.Load("example.com"); len(snaps) != 1 {
		t.Errorf("应只有 1 条存储，实际 %d", len(snaps))
	}

	// 相同内容、间隔超过心跳（25h）→ 追加（心跳记录）
	s3 := mkSnap("example.com", func(s *Snapshot) {
		s.IPs = []string{"1.1.1.1"}
		s.TakenAt = s1.TakenAt.Add(25 * time.Hour)
	})
	if _, appended, err := store.SaveAndPrevious(s3); err != nil {
		t.Fatal(err)
	} else if !appended {
		t.Error("超过心跳间隔后相同内容也应追加（证明基线仍然成立）")
	}

	// 内容不同 → 总是追加
	s4 := mkSnap("example.com", func(s *Snapshot) { s.IPs = []string{"9.9.9.9"} })
	if _, appended, err := store.SaveAndPrevious(s4); err != nil {
		t.Fatal(err)
	} else if !appended {
		t.Error("内容变化必须追加")
	}
	if snaps, _ := store.Load("example.com"); len(snaps) != 3 {
		t.Errorf("应有 3 条存储，实际 %d", len(snaps))
	}
}

// 保留上限：超出后裁剪最旧的
func TestSnapshotStore_Prune(t *testing.T) {
	store := NewSnapshotStore(t.TempDir(), 2)
	for i := 0; i < 4; i++ {
		s := mkSnap("example.com", func(s *Snapshot) {
			s.IPs = []string{"10.0.0." + string(rune('1'+i))}
		})
		if _, _, err := store.SaveAndPrevious(s); err != nil {
			t.Fatal(err)
		}
	}
	snaps, _ := store.Load("example.com")
	if len(snaps) != 2 {
		t.Fatalf("keep=2 时最多保留 2 个，实际 %d", len(snaps))
	}
	// 保留的是最新的两个
	if snaps[0].IPs[0] != "10.0.0.3" || snaps[1].IPs[0] != "10.0.0.4" {
		t.Errorf("应保留最新两个，实际 %v / %v", snaps[0].IPs, snaps[1].IPs)
	}
}

// 无快照文件 → 空结果，不报错
func TestSnapshotStore_LoadMissing(t *testing.T) {
	store := NewSnapshotStore(t.TempDir(), 30)
	snaps, err := store.Load("not-exist.com")
	if err != nil {
		t.Errorf("无文件不应报错: %v", err)
	}
	if len(snaps) != 0 {
		t.Errorf("无文件应返回空列表，实际 %d", len(snaps))
	}
}

// ⭐⭐ 损坏的快照文件不能被静默覆盖（否则一次解析失败就清空全部历史）
func TestSnapshotStore_CorruptFileKeepsData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.com.json")
	corrupt := "{ 这不是合法 JSON"
	if err := os.WriteFile(path, []byte(corrupt), 0o644); err != nil {
		t.Fatal(err)
	}

	store := NewSnapshotStore(dir, 30)
	_, _, err := store.SaveAndPrevious(mkSnap("example.com", nil))
	if err == nil {
		t.Fatal("损坏文件应报错，不能静默覆盖")
	}
	// 原文件必须原样保留
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != corrupt {
		t.Errorf("损坏文件被改写了：%q", string(got))
	}
}

// ⭐ 容忍 UTF-8 BOM（记事本另存的常见形态）
func TestSnapshotStore_ToleratesBOM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.com.json")
	body := "\xef\xbb\xbf" + `{"target":"example.com","snapshots":[{"target":"example.com","taken_at":"2026-10-01T00:00:00Z","coverage":{"dns":true}}]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	store := NewSnapshotStore(dir, 30)
	snaps, err := store.Load("example.com")
	if err != nil {
		t.Fatalf("带 BOM 的文件应能加载: %v", err)
	}
	if len(snaps) != 1 {
		t.Errorf("应加载 1 条，实际 %d", len(snaps))
	}
}

// ⭐⭐ 目标校验：净化撞名时不能把别的目标的快照当成自己的（静默串目标）
func TestSnapshotStore_TargetMismatch(t *testing.T) {
	dir := t.TempDir()
	// "a_b.com" 的正常文件
	store := NewSnapshotStore(dir, 30)
	if _, _, err := store.SaveAndPrevious(mkSnap("a_b.com", func(s *Snapshot) {
		s.IPs = []string{"4.4.4.4"}
	})); err != nil {
		t.Fatal(err)
	}
	// "a b.com" 归一化后净化成 a_b.com-<hash>.json（有损名带哈希后缀）→ 不同文件
	if _, _, err := store.SaveAndPrevious(mkSnap("a b.com", nil)); err != nil {
		t.Fatal(err)
	}
	// 两者必须互不干扰
	snaps1, err := store.Load("a_b.com")
	if err != nil || len(snaps1) != 1 || snaps1[0].IPs[0] != "4.4.4.4" {
		t.Errorf("a_b.com 的快照应完好：err=%v %+v", err, snaps1)
	}
	snaps2, err := store.Load("a b.com")
	if err != nil || len(snaps2) != 1 {
		t.Errorf("a b.com 的快照应独立存在：err=%v %+v", err, snaps2)
	}

	// 手工构造目标不匹配的文件 → 必须报错而不是静默读成自己的
	mismatch := `{"target":"other.com","snapshots":[]}`
	if err := os.WriteFile(filepath.Join(dir, "example.com.json"), []byte(mismatch), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("example.com"); err == nil {
		t.Error("文件目标不匹配时应报错")
	}
	if _, _, err := store.SaveAndPrevious(mkSnap("example.com", nil)); err == nil {
		t.Error("文件目标不匹配时不得追加（防污染）")
	}
}

// 目标名净化：路径分隔符不可进入文件名 + Windows 保留名规避
func TestSnapshotStore_TargetSanitization(t *testing.T) {
	dir := t.TempDir()
	store := NewSnapshotStore(dir, 30)

	// 大小写/协议/路径统一归一 → 同一文件
	if _, _, err := store.SaveAndPrevious(mkSnap("https://EXAMPLE.com/path", nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "example.com.json")); err != nil {
		t.Errorf("归一化后应写入 example.com.json: %v", err)
	}

	// 前向斜杠穿越：归一化在第一个 / 处截断 → 退化为空目标 → 明确拒绝
	if _, _, err := store.SaveAndPrevious(mkSnap("../evil/../x", nil)); err == nil {
		t.Error("退化目标（归一化后为空）应被拒绝")
	}

	// 反斜杠（Windows 分隔符，归一化不处理）→ 由净化层兜底：
	// 必须落在目录内，且文件名无分隔符（具体文件名断言，不能空转）
	if _, _, err := store.SaveAndPrevious(mkSnap(`evil\..\x`, nil)); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		if strings.ContainsAny(e.Name(), "/\\") {
			t.Errorf("文件名不应含路径分隔符: %q", e.Name())
		}
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "evil_.._x") {
		t.Errorf("净化后的文件应在目录内（期望含 evil_.._x），实际 %v", names)
	}

	// Windows 保留设备名不能直接当文件名
	if _, _, err := store.SaveAndPrevious(mkSnap("con", nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "_con.json")); err != nil {
		t.Errorf("保留名应加前缀规避: %v", err)
	}
}

// 空目标名拒绝保存
func TestSnapshotStore_RejectEmptyTarget(t *testing.T) {
	store := NewSnapshotStore(t.TempDir(), 30)
	if _, _, err := store.SaveAndPrevious(mkSnap("", nil)); err == nil {
		t.Error("空目标名应报错")
	}
}

// ⭐ --since 的基准选择：不晚于 cutoff 的最新快照
func TestSnapshotStore_LatestBefore(t *testing.T) {
	store := NewSnapshotStore(t.TempDir(), 30)
	now := time.Now().UTC()

	old := mkSnap("example.com", func(s *Snapshot) { s.IPs = []string{"1.1.1.1"} })
	old.TakenAt = now.Add(-72 * time.Hour)
	mid := mkSnap("example.com", func(s *Snapshot) { s.IPs = []string{"2.2.2.2"} })
	mid.TakenAt = now.Add(-24 * time.Hour)
	newest := mkSnap("example.com", func(s *Snapshot) { s.IPs = []string{"3.3.3.3"} })
	newest.TakenAt = now

	for _, s := range []*Snapshot{old, mid, newest} {
		if _, _, err := store.SaveAndPrevious(s); err != nil {
			t.Fatal(err)
		}
	}

	// cutoff = 48h 前 → 应选 72h 前的 old（mid 比 cutoff 新，排除）
	got, err := store.LatestBefore("example.com", now.Add(-48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.IPs[0] != "1.1.1.1" {
		t.Errorf("应选 72h 前的快照，实际 %+v", got)
	}

	// cutoff = 100h 前 → 没有更早的
	got, err = store.LatestBefore("example.com", now.Add(-100*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("没有更早快照应返回 nil，实际 %+v", got)
	}

	// cutoff = now → 最新一个
	got, _ = store.LatestBefore("example.com", now)
	if got == nil || got.IPs[0] != "3.3.3.3" {
		t.Errorf("cutoff=now 应返回最新快照，实际 %+v", got)
	}
}

// keep <= 0 时使用默认保留数
func TestSnapshotStore_DefaultKeep(t *testing.T) {
	store := NewSnapshotStore(t.TempDir(), 0)
	if store.keep != DefaultSnapshotKeep {
		t.Errorf("keep=0 应使用默认值 %d，实际 %d", DefaultSnapshotKeep, store.keep)
	}
}

// 默认目录必须在 ~/.wukan/ 下（与其它缓存一致）
func TestDefaultSnapshotDir(t *testing.T) {
	dir := DefaultSnapshotDir()
	if !strings.Contains(dir, ".wukan") || !strings.Contains(dir, "snapshots") {
		t.Errorf("默认目录应在 ~/.wukan/snapshots 下，实际 %q", dir)
	}
}
