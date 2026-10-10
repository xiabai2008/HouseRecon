package portscan

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ⭐ 缓存键必须区分所有会改变结果的输入 —— 尤其是 Host 头
//
// 同一个 IP:80 上不同 Host 返回不同站点（CDN/虚拟主机），
// 键不区分会让 a.example.com 的结果被误用到 b.example.com 上。
func TestMakeCacheKey_Distinguishes(t *testing.T) {
	base := MakeCacheKey("1.2.3.4", 80, "a.example.com", true, false)

	// 同参数必须相同
	if again := MakeCacheKey("1.2.3.4", 80, "a.example.com", true, false); again != base {
		t.Errorf("同参数应生成相同键：%q vs %q", base, again)
	}
	// 不同 IP
	if k := MakeCacheKey("1.2.3.5", 80, "a.example.com", true, false); k == base {
		t.Error("IP 不同应生成不同缓存键")
	}
	// 不同端口
	if k := MakeCacheKey("1.2.3.4", 443, "a.example.com", true, false); k == base {
		t.Error("端口不同应生成不同缓存键")
	}
	// ⭐ 不同 Host 头（核心防护）
	if k := MakeCacheKey("1.2.3.4", 80, "b.example.com", true, false); k == base {
		t.Error("⭐ 不同 Host 头必须生成不同缓存键")
	}
	// Host 头大小写不敏感（RFC 要求）
	if k := MakeCacheKey("1.2.3.4", 80, "A.EXAMPLE.COM", true, false); k != base {
		t.Errorf("Host 头应大小写不敏感：%q vs %q", base, k)
	}
	// 抓 banner 开关不同 → 键不同（结果语义不同，不可复用）
	if k := MakeCacheKey("1.2.3.4", 80, "a.example.com", false, false); k == base {
		t.Error("grabBanner 不同应生成不同缓存键")
	}
	// TLS 握手开关不同 → 键不同
	if k := MakeCacheKey("1.2.3.4", 80, "a.example.com", true, true); k == base {
		t.Error("tlsProbe 不同应生成不同缓存键")
	}
	// 空 Host 头与有 Host 头不能混淆
	if k := MakeCacheKey("1.2.3.4", 80, "", true, false); k == base {
		t.Error("有无 Host 头应生成不同缓存键")
	}
}

// ⭐ 负缓存判定必须依据状态而不是 Err 字段：
// open + Err（TLS 握手失败）的"开放"是确定的，属正缓存。
func TestPortCache_IsInconclusive(t *testing.T) {
	cases := []struct {
		name string
		r    PortResult
		want bool
	}{
		{"open", PortResult{State: StateOpen}, false},
		{"closed", PortResult{State: StateClosed}, false},
		{"open 但 TLS 握手失败（端口开放是确定的）",
			PortResult{State: StateOpen, Err: "TLS 握手失败"}, false},
		{"filtered（超时，不确定）", PortResult{State: StateFiltered}, true},
		{"error", PortResult{State: StateError}, true},
	}
	for _, c := range cases {
		if got := isInconclusive(&c.r); got != c.want {
			t.Errorf("%s: isInconclusive = %v, 期望 %v", c.name, got, c.want)
		}
	}
}

// ⭐ 正/负缓存 TTL 分层：确定结果 6 小时，不确定结果 10 分钟
func TestPortCache_PositiveAndNegativeTTL(t *testing.T) {
	if NegativeCacheTTL >= CacheTTL {
		t.Errorf("负缓存 TTL(%v) 必须短于正缓存 TTL(%v)", NegativeCacheTTL, CacheTTL)
	}
	if CacheTTL != 6*time.Hour {
		t.Errorf("正缓存 TTL 应为 6 小时（端口状态比指纹变化快），实际 %v", CacheTTL)
	}
	if NegativeCacheTTL > 30*time.Minute {
		t.Errorf("负缓存 TTL(%v) 过长 —— 一次抖动会被固化成'端口 filtered'", NegativeCacheTTL)
	}

	c, err := NewFilePortCache("", time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}

	// 确定结果（open）→ 正缓存
	c.Put("open", &PortResult{State: StateOpen, Port: 443})
	// 不确定结果（filtered）→ 负缓存
	c.Put("filt", &PortResult{State: StateFiltered, Port: 12345})

	got, ok := c.Get("open")
	if !ok || got.State != StateOpen {
		t.Fatal("open 结果应进入正缓存")
	}
	if c.items["open"].Neg {
		t.Error("open 不应被标记为负缓存")
	}
	if _, ok := c.Get("filt"); !ok {
		t.Fatal("filtered 结果应进入负缓存（否则重复扫描每次都要等满超时）")
	}
	if !c.items["filt"].Neg {
		t.Error("filtered 应被标记为负缓存")
	}

	// 把 open 结果的时间拨到 7 小时前（超过正缓存 6h）→ 必须失效
	c.items["open"].CachedAt = time.Now().Add(-7 * time.Hour).UnixNano()
	if _, ok := c.Get("open"); ok {
		t.Error("超过正缓存 TTL 的条目不应被返回")
	}
	// filtered 拨到 11 分钟前（超过负缓存 10min）→ 必须失效
	c.items["filt"].CachedAt = time.Now().Add(-11 * time.Minute).UnixNano()
	if _, ok := c.Get("filt"); ok {
		t.Error("超过负缓存 TTL 的不确定结果不应被返回")
	}
}

// ⭐ Get 必须返回深拷贝且标记 Cached —— 调用方不应污染缓存，
// 用户也必须知道这不是实时结果
func TestPortCache_DeepCopyAndMarked(t *testing.T) {
	c, _ := NewFilePortCache("", time.Hour, false)
	c.Put("k", &PortResult{State: StateOpen, Port: 443, Banner: "Server: nginx"})

	got, ok := c.Get("k")
	if !ok {
		t.Fatal("应命中")
	}
	if !got.Cached {
		t.Error("⭐ 缓存命中必须标记 Cached=true")
	}
	if got.CacheAge == "" {
		t.Error("缓存命中应填写 CacheAge")
	}
	if c.items["k"].Result.Cached {
		t.Error("存入缓存时应为 Cached=false（标记由 Get 设置）")
	}

	got.Banner = "被调用方修改了"
	got.Port = 9999
	again, _ := c.Get("k")
	if again.Banner != "Server: nginx" || again.Port != 443 {
		t.Errorf("⭐ Get 返回的必须是深拷贝，缓存被污染：banner=%q port=%d",
			again.Banner, again.Port)
	}
}

// ⭐ Save 时剔除过期条目（避免文件无限膨胀），load 后可命中未过期条目
func TestPortCache_SaveLoadAndPrune(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "ports-cache.json")

	c, err := NewFilePortCache(path, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	c.Put("valid", &PortResult{State: StateOpen, Port: 443, IP: "1.2.3.4"})
	c.Put("expired", &PortResult{State: StateClosed, Port: 80, IP: "1.2.3.4"})
	c.items["expired"].CachedAt = time.Now().Add(-2 * time.Hour).UnixNano()

	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("保存后文件应存在: %v", err)
	}

	// 重新加载
	c2, err := NewFilePortCache(path, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Len() != 1 {
		t.Errorf("Save 应剔除过期条目，load 后应剩 1 条，实际 %d", c2.Len())
	}
	if _, ok := c2.Get("valid"); !ok {
		t.Error("未过期条目应能加载并命中")
	}

	// 不存在缓存文件时不应报错（首次运行场景）
	c3, err := NewFilePortCache(filepath.Join(dir, "not-exist.json"), time.Hour, true)
	if err != nil {
		t.Errorf("首次运行（无缓存文件）不应报错: %v", err)
	}
	if c3.Len() != 0 {
		t.Error("无缓存文件时条目数应为 0")
	}
}

// 统计：命中与未命中都要计数
func TestPortCache_Stats(t *testing.T) {
	c, _ := NewFilePortCache("", time.Hour, false)
	c.Put("k", &PortResult{State: StateOpen})

	c.Get("k")     // 命中
	c.Get("miss1") // 未命中
	c.Get("miss2") // 未命中

	h, m, total := c.Stats()
	if h != 1 || m != 2 || total != 3 {
		t.Errorf("统计错误: hits=%d misses=%d total=%d, 期望 1/2/3", h, m, total)
	}
}

// ⭐⭐ Scanner 集成：第二次扫描必须命中缓存（不发连接），
// 且缓存结果在目标下线后仍可用（覆盖"扫→复核→写报告"循环）
func TestScanner_CacheRoundTrip(t *testing.T) {
	// 起一个本地监听，拿到一个确定开放的端口
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	cache, _ := NewFilePortCache("", time.Hour, false)

	cfg := DefaultConfig()
	cfg.Ports = []int{port}
	cfg.Cache = cache
	cfg.RateLimit = 0      // 测试不限速
	cfg.GrabBanner = false // 静默监听会让 banner 读取等满超时，测试无需抓 banner

	sc := New(cfg)

	first := sc.ScanHost("127.0.0.1")
	if len(first) != 1 || !first[0].Open() {
		t.Fatalf("第一次扫描应为 open，实际 %+v", first)
	}
	if first[0].Cached {
		t.Error("第一次扫描不应标记 Cached")
	}

	// 第二次扫描 → 应命中缓存
	second := sc.ScanHost("127.0.0.1")
	if !second[0].Cached {
		t.Error("⭐ 第二次扫描应命中缓存（Cached=true）")
	}
	h, _, tot := cache.Stats()
	if h != 1 || tot != 2 {
		t.Errorf("缓存统计应为 1 命中 / 2 查询，实际 %d/%d", h, tot)
	}

	// 目标下线后第三次扫描 → 缓存仍返回 open（这正是缓存的价值：
	// 复核阶段不用重新连接目标）
	_ = ln.Close()
	time.Sleep(30 * time.Millisecond)
	third := sc.ScanHost("127.0.0.1")
	if !third[0].Open() || !third[0].Cached {
		t.Errorf("⭐ 目标下线后应返回缓存的 open 结果，实际 %+v", third[0])
	}

	// 对照：不带缓存的扫描器现在应报 closed（证明监听确实关了）
	cfg2 := DefaultConfig()
	cfg2.Ports = []int{port}
	cfg2.RateLimit = 0
	cfg2.GrabBanner = false
	sc2 := New(cfg2)
	fresh := sc2.ScanHost("127.0.0.1")
	if fresh[0].Open() {
		t.Error("对照扫描：监听已关闭，不应再报 open")
	}
}

// ⭐ 缓存命中时不发起任何连接 —— 用"预填充 filtered"证明：
//
// 127.0.0.1 上不存在的端口真实探测会得到 closed（RST），
// 若返回 filtered 且 Cached=true，说明结果完全来自缓存、没有发过连接。
func TestScanner_CacheHitSkipsDial(t *testing.T) {
	// 拿一个确定没人监听的端口（监听后立刻关掉）
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cache, _ := NewFilePortCache("", time.Hour, false)
	cfg := DefaultConfig()
	cfg.Ports = []int{port}
	cfg.Cache = cache
	cfg.RateLimit = 0

	// 预填充：用与 Scanner 完全相同的键生成方式
	key := MakeCacheKey("127.0.0.1", port, "127.0.0.1", cfg.GrabBanner, cfg.TLSProbe)
	cache.Put(key, &PortResult{
		Host: "127.0.0.1", IP: "127.0.0.1", Port: port,
		State: StateFiltered, Err: "timeout",
	})

	sc := New(cfg)
	got := sc.ScanHost("127.0.0.1")
	if len(got) != 1 {
		t.Fatalf("应返回 1 个结果，实际 %d", len(got))
	}
	if got[0].State != StateFiltered || !got[0].Cached {
		t.Errorf("⭐ 结果应完全来自缓存（filtered + Cached=true），实际 state=%s cached=%v",
			got[0].State, got[0].Cached)
	}
}

// ⭐ 缓存键里的 Host 头取"实际会发送"的值：
// 配置了 HostHeader 时用它，否则用主机名本身
func TestScanner_CacheKeyUsesEffectiveHost(t *testing.T) {
	cache, _ := NewFilePortCache("", time.Hour, false)
	cfg := DefaultConfig()
	cfg.Ports = []int{80}
	cfg.HostHeader = "a.example.com"
	cfg.RateLimit = 0
	cfg.Cache = cache

	// 预填充：HostHeader 生效 → 键用 a.example.com
	key := MakeCacheKey("1.2.3.4", 80, "a.example.com", cfg.GrabBanner, cfg.TLSProbe)
	cache.Put(key, &PortResult{
		Host: "1.2.3.4", IP: "1.2.3.4", Port: 80,
		State: StateOpen, Service: "http",
	})

	sc := New(cfg)
	got := sc.probe("1.2.3.4", "1.2.3.4", 80)
	if !got.Cached || got.State != StateOpen {
		t.Errorf("配置了 HostHeader 时应按实际发送的 Host 命中缓存，实际 %+v", got)
	}
	// Host 应被本次调用方覆盖
	if got.Host != "1.2.3.4" {
		t.Errorf("命中的结果 Host 应为本次调用方的主机名，实际 %q", got.Host)
	}
}

// 清空缓存
func TestPortCache_Clear(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	c, _ := NewFilePortCache(path, time.Hour, false)
	c.Put("k", &PortResult{State: StateOpen})
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if err := c.Clear(); err != nil {
		t.Fatal(err)
	}
	if c.Len() != 0 {
		t.Error("Clear 后条目数应为 0")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("Clear 后缓存文件应被删除")
	}
}

// ListEntries 输出应包含目标与状态（供 --cache-stats 展示）
func TestPortCache_ListEntries(t *testing.T) {
	c, _ := NewFilePortCache("", time.Hour, false)
	c.Put("a", &PortResult{State: StateOpen, IP: "1.2.3.4", Port: 443})
	c.Put("b", &PortResult{State: StateFiltered, IP: "1.2.3.4", Port: 12345})

	rows := c.ListEntries()
	if len(rows) != 2 {
		t.Fatalf("应有 2 行，实际 %d", len(rows))
	}
	joined := strings.Join(rows, "|")
	for _, want := range []string{"1.2.3.4:443", "1.2.3.4:12345", "open", "filtered", "[负缓存]"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ListEntries 输出缺少 %q：%s", want, joined)
		}
	}
	// 排序：443 在 12345 之前（按字符串排序）
	if rows[0] >= rows[1] {
		t.Errorf("条目应按目标排序：%q vs %q", rows[0], rows[1])
	}
}
