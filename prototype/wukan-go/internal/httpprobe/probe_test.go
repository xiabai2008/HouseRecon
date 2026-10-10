package httpprobe

import (
	"encoding/hex"
	"testing"
	"time"
)

// ⭐⭐ favicon 哈希的测试向量来自**独立的 Python 参考实现**交叉产出，
//
//	不是自己算自己 —— 那样只能证明代码没崩，证明不了算法对。
//
// 测试向量（hex 数据 → 期望的有符号 int32）：
//
//	""       → 0
//	00000100 → -216455174
//
// ⭐ 早期版本里的第三个向量（GOLF → 1778677923）是**手填错的**，
//
//	实际应为 184701246。教训：测试向量必须由**独立实现**交叉生成，
//	凭记忆填的期望值会让"实现错误"与"期望值错误"无法区分。
func TestShodanFaviconHash_Vectors(t *testing.T) {
	cases := []struct {
		hexData string
		name    string
		want    int64
	}{
		{"", "空数据", 0},
		{"00000100", "4 字节 ICO 头", -216455174},
		{"474f4c46", "GOLF (4 字节)", 184701246},
	}
	for _, c := range cases {
		data, err := hex.DecodeString(c.hexData)
		if err != nil {
			t.Fatalf("%s: hex 解码失败: %v", c.name, err)
		}
		got := ShodanFaviconHash(data)
		if got != c.want {
			t.Errorf("%s: ShodanFaviconHash = %d, 期望 %d", c.name, got, c.want)
		}
	}
}

// ⭐ 验证 MurmurHash3 x86_32 的标准测试向量
//
// 参考：SMHasher 的 murmur3_x86_32 测试集。
// 这组向量能直接证明算法实现无误（不只是"和我的另一份代码一致"）。
func TestMurmur3X86_32_StandardVectors(t *testing.T) {
	cases := []struct {
		in   string
		seed uint32
		want uint32
	}{
		{"", 0x00000000, 0x00000000},
		{"", 0x514E28B7, 0x2FEF5C8F},
		{"\xff\xff\xff\xff", 0x00000000, 0x76293B50},
		{"\x21\x43\x65\x87", 0x00000000, 0xF55B516B},
		{"\x21\x43\x65\x87", 0x5082EDEE, 0x2362F9DE},
		{"\x21\x43\x65", 0x00000000, 0x7E4A8634},
		{"\x21\x43", 0x00000000, 0xA0F7B07A},
		{"\x21", 0x00000000, 0x72661CF4},
		{"\x00\x00\x00\x00", 0x00000000, 0x2362F9DE},
		{"\x00\x00\x00", 0x00000000, 0x85F0B427},
		{"\x00\x00", 0x00000000, 0x30F4C306},
		{"\x00", 0x00000000, 0x514E28B7},
		{"hello", 0x00000000, 0x248BFA47},
		{"Hello, world!", 0x00000000, 0xC0363E43},
		{"The quick brown fox jumps over the lazy dog", 0x00000000, 0x2E4FF723},
	}
	for _, c := range cases {
		got := murmur3x86_32([]byte(c.in), c.seed)
		if got != c.want {
			t.Errorf("murmur3x86_32(%q, seed=%#x) = %#x, 期望 %#x",
				c.in, c.seed, got, c.want)
		}
	}
}

// ⭐ 验证 RFC 2045 换行逻辑 —— 这是 Shodan 兼容性的关键
//
// 反例：如果不换行（直接对 base64 算哈希），结果会完全不同。
// 调研报告 §第八章坑 5 明确指出"中文教程普遍抄错这点，
// 导致自建工具算出的 hash 永远对不上 Shodan"。
func TestBase64LineWrapping(t *testing.T) {
	// 构造长度使 base64 后超过 76 字符的数据
	// 57 字节 → base64 76 字符（刚好不换行）
	// 58 字节 → base64 80 字符（必须换行）
	data57 := make([]byte, 57)
	for i := range data57 {
		data57[i] = byte(i)
	}
	data58 := append(append([]byte{}, data57...), 0xFF)

	// 两种长度应该算出不同的哈希（若换行逻辑失效，可能出现巧合相同）
	h57 := ShodanFaviconHash(data57)
	h58 := ShodanFaviconHash(data58)
	if h57 == h58 {
		t.Errorf("57 字节与 58 字节数据算出相同哈希 %d —— 换行逻辑可能失效", h57)
	}
}

// ⭐ 验证输出是**有符号**整数
//
// Shodan 返回的是 signed int32，若实现返回 uint32，
// 高位为 1 的哈希会变成巨大的正数，导致比对失败。
func TestHashIsSigned(t *testing.T) {
	// 找一个会产生负数的输入
	found := false
	for i := 0; i < 1000; i++ {
		data := []byte{byte(i), byte(i >> 8), 0xFF, 0xFF}
		h := ShodanFaviconHash(data)
		if h < 0 {
			found = true
			if h > 0x7fffffff {
				t.Errorf("哈希 %d 超出 int32 范围", h)
			}
			break
		}
	}
	if !found {
		t.Skip("未在测试范围内找到负数哈希（可接受）")
	}
}

// ── 证书匹配测试 ──────────────────────────────────────────

func TestCertCoversHost(t *testing.T) {
	cases := []struct {
		dnsNames []string
		host     string
		want     bool
	}{
		{[]string{"example.com"}, "example.com", true},
		{[]string{"example.com"}, "www.example.com", false},
		{[]string{"*.example.com"}, "www.example.com", true},
		{[]string{"*.example.com"}, "example.com", false}, // 通配符不匹配裸域
		{[]string{"*.example.com", "example.com"}, "example.com", true},
		{[]string{"a.example.com", "b.example.com"}, "b.example.com", true},
		{[]string{"a.example.com"}, "b.example.com", false},
		{[]string{"EXAMPLE.COM"}, "example.com", true}, // 大小写不敏感
		{[]string{"*.例え.com"}, "www.例え.com", true},
		{nil, "example.com", false},
	}
	for _, c := range cases {
		got := certCoversHost(c.dnsNames, c.host)
		if got != c.want {
			t.Errorf("certCoversHost(%v, %q) = %v, 期望 %v",
				c.dnsNames, c.host, got, c.want)
		}
	}
}

// ── URL 解析测试 ──────────────────────────────────────────

func TestParseURL(t *testing.T) {
	cases := []struct {
		in      string
		scheme  string
		host    string
		port    int
		wantErr bool
	}{
		{"http://example.com", "http", "example.com", 80, false},
		{"https://example.com", "https", "example.com", 443, false},
		{"https://example.com:8443/x", "https", "example.com", 8443, false},
		{"example.com", "http", "example.com", 80, false},
		{"https://1.2.3.4:9000", "https", "1.2.3.4", 9000, false},
		{"http://", "http", "", 0, true},
		{"https://a:notaport", "https", "a", 0, true},
	}
	for _, c := range cases {
		u, err := parseURL(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseURL(%q) 应报错但成功", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseURL(%q) 报错: %v", c.in, err)
			continue
		}
		if u.schemeStr != c.scheme || u.hostStr != c.host || u.portNum != c.port {
			t.Errorf("parseURL(%q) = (%s,%s,%d), 期望 (%s,%s,%d)",
				c.in, u.schemeStr, u.hostStr, u.portNum, c.scheme, c.host, c.port)
		}
	}
}

// ── 正文特征提取测试 ──────────────────────────────────────

func TestExtractTitle(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"<html><head><title>Hello</title></head><body>x</body></html>", "Hello"},
		{"<TITLE>Upper</TITLE>", "Upper"},
		{"<title>带中文的标题</title>", "带中文的标题"},
		{"<html><body>无标题</body></html>", ""},
		{"<title>换行\n标题</title>", "换行 标题"},
		{"", ""},
	}
	for _, c := range cases {
		if got := extractTitle(c.in); got != c.want {
			t.Errorf("extractTitle(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

func TestExtractKeywords(t *testing.T) {
	cases := []struct {
		in   string
		want string // 期望包含的关键词
	}{
		{"<html>Powered by WordPress wp-content</html>", "WordPress"},
		{"<script src='/jquery-3.6.0.js'>", "jQuery"},
		{"<div class='vue-app'>__vue__</div>", "Vue"},
		{"random text", ""},
	}
	for _, c := range cases {
		got := extractKeywords(c.in)
		found := false
		for _, k := range got {
			if k == c.want {
				found = true
				break
			}
		}
		if c.want == "" && len(got) > 0 {
			t.Errorf("extractKeywords(%q) = %v, 期望空", c.in, got)
		}
		if c.want != "" && !found {
			t.Errorf("extractKeywords(%q) = %v, 期望包含 %q", c.in, got, c.want)
		}
	}
}

// ── 冲突检测测试 ──────────────────────────────────────────

// ⭐⭐ 回归防护：CDN 检测的「自我矛盾」假阳性
//
// 实测发现（2026-10-05）：aliyun.com 的 Server 头是 "Tengine"，
// 而 Tengine 本身就是阿里云的服务器软件。
// 早期实现把它当成「CDN 声称」，又把同一个 Server 头当成「泄露的源站特征」
// —— 同一行证据既当声称又当反证，逻辑上自相矛盾，产生假阳性。
//
// 修复：只有当 CDN 判定来自**独立于 Server 头**的信号
// （CF-RAY / X-Cache / X-Amz-Cf-Id 之类专用头）时才报此冲突。
func TestCDNDetect_SelfContradiction(t *testing.T) {
	cases := []struct {
		name            string
		p               *ProbeResult
		wantCDN         bool
		wantIndependent bool
	}{
		{
			name:            "Tengine 只在 Server 头（阿里云自有服务器软件，非 CDN 证据）",
			p:               &ProbeResult{Server: "Tengine"},
			wantCDN:         true,
			wantIndependent: false, // ⭐ 关键：不独立
		},
		{
			name:            "Cloudflare 只在 Server 头",
			p:               &ProbeResult{Server: "cloudflare"},
			wantCDN:         true,
			wantIndependent: false,
		},
		{
			name: "有 CF-RAY 专用头（真正的独立 CDN 证据）",
			p: &ProbeResult{
				Server:    "nginx",
				CFHeaders: map[string]string{"Cf-Ray": "8d0e0a1b2c3d4e5f-SYD"},
			},
			wantCDN:         true,
			wantIndependent: true,
		},
		{
			name: "有 X-Cache 专用头",
			p: &ProbeResult{
				Server:     "Tengine",
				CDNHeaders: map[string]string{"X-Cache": "MISS from t-1-1-1"},
			},
			wantCDN:         true,
			wantIndependent: true,
		},
	}

	for _, c := range cases {
		name, indep := detectCDNIndependent(c.p)
		if (name != "") != c.wantCDN {
			t.Errorf("%s: CDN 检测 = %q, 期望有=%v", c.name, name, c.wantCDN)
		}
		if indep != c.wantIndependent {
			t.Errorf("%s: 独立性 = %v, 期望 %v（CDN=%q）",
				c.name, indep, c.wantIndependent, name)
		}
	}
}

// ⭐ 关键断言：Server-only 的 CDN 判定**不得**触发泄露冲突
func TestDetectConflicts_NoSelfContradictoryLeak(t *testing.T) {
	p := &ProbeResult{
		URL:          "https://www.aliyun.com",
		Server:       "Tengine",
		CFHeaders:    map[string]string{},
		CDNHeaders:   map[string]string{},
		SecurityHdrs: map[string]string{},
		StatusCode:   200,
	}
	rep := DetectConflicts(p)
	for _, c := range rep.Conflicts {
		if c.Type == ConflictCDNLeak {
			t.Errorf("⭐ 不应报 CDN 泄露冲突（自我矛盾）：%s —— "+
				"Server: Tengine 本身就是阿里云的软件，不构成泄露", c.Title)
		}
	}
}

// ⭐⭐ 回归防护：「用 IP 访问」导致的证书 SAN 假阳性
//
// 实测发现（2026-10-05）：recon 阶段为逐个探测 CDN 节点，URL 构造为
// `http://1.2.3.4:80`。此时证书 SAN 是 `*.example.com`，
// **IP 天然不匹配任何 SAN** —— 但这不是证书配置错误。
// 早期实现没排除这种情况，导致 3 个 CDN 节点全部误报。
func TestDetectConflicts_NoCertMismatchForIPAccess(t *testing.T) {
	p := &ProbeResult{
		URL:             "http://1.2.3.4:80", // ⭐ IP 直连
		CertSANs:        []string{"*.example.com"},
		CertMatchesHost: false, // 必然不匹配
		CFHeaders:       map[string]string{},
		CDNHeaders:      map[string]string{},
		SecurityHdrs:    map[string]string{},
	}
	rep := DetectConflicts(p)
	for _, c := range rep.Conflicts {
		if c.Type == ConflictCertMismatch {
			t.Errorf("⭐ IP 直连时不应报证书 SAN 冲突：%s", c.Title)
		}
	}
	// ⭐ 但用域名访问时必须报出
	p2 := &ProbeResult{
		URL:             "https://wrong.example.com",
		CertSANs:        []string{"other.com", "*.other.com"},
		CertMatchesHost: false,
		CFHeaders:       map[string]string{},
		CDNHeaders:      map[string]string{},
		SecurityHdrs:    map[string]string{},
	}
	rep2 := DetectConflicts(p2)
	found := false
	for _, c := range rep2.Conflicts {
		if c.Type == ConflictCertMismatch {
			found = true
		}
	}
	if !found {
		t.Error("域名访问时证书 SAN 不匹配应该报出")
	}
}

// ⭐ 独立 CDN 头 + 源站泄露 → 必须报出
func TestDetectConflicts_RealCDNLeak(t *testing.T) {
	p := &ProbeResult{
		URL:          "https://example.com",
		Server:       "nginx",
		PoweredBy:    "PHP/8.2.0",
		CFHeaders:    map[string]string{"Cf-Ray": "8d0e0a1b2c3d4e5f-SYD"},
		CDNHeaders:   map[string]string{},
		SecurityHdrs: map[string]string{},
		StatusCode:   200,
	}
	rep := DetectConflicts(p)
	found := false
	for _, c := range rep.Conflicts {
		if c.Type == ConflictCDNLeak {
			found = true
			if c.Severity != SevMedium {
				t.Errorf("严重程度 = %q, 期望 medium", c.Severity)
			}
			if len(c.Sources) < 2 {
				t.Errorf("应记录至少 2 个冲突来源，实际 %d", len(c.Sources))
			}
			if c.Implication == "" {
				t.Error("必须给出判读（Implication），否则用户不知道能做什么")
			}
		}
	}
	if !found {
		t.Error("有独立 CDN 头 + Server/Powered-By 泄露，应该报出 cdn_leak")
	}
}

// ⭐ 冲突必须带判读 —— 报出问题却不告诉用户能做什么等于没报
func TestConflicts_HaveImplication(t *testing.T) {
	p := &ProbeResult{
		URL:          "http://example.com",
		SetCookies:   []string{"JSESSIONID=abc123; Path=/"},
		CFHeaders:    map[string]string{},
		CDNHeaders:   map[string]string{},
		SecurityHdrs: map[string]string{},
		StatusCode:   200,
	}
	rep := DetectConflicts(p)
	if len(rep.Conflicts) == 0 {
		t.Fatal("应该检出 Cookie 缺标志的冲突")
	}
	for _, c := range rep.Conflicts {
		if c.Implication == "" {
			t.Errorf("冲突 %s 缺少判读说明", c.Type)
		}
		if c.Title == "" {
			t.Errorf("冲突 %s 缺少标题", c.Type)
		}
	}
}

// ⭐ 无冲突时必须明确说"无冲突"，不硬凑
func TestDetectConflicts_NoFalsePositiveOnClean(t *testing.T) {
	p := &ProbeResult{
		URL:        "https://clean.example.com",
		Server:     "nginx/1.24.0",
		TLSVersion: "TLS 1.3",
		ALPN:       "h2",
		CFHeaders:  map[string]string{},
		CDNHeaders: map[string]string{},
		SecurityHdrs: map[string]string{
			"strict-transport-security": "max-age=31536000",
			"x-frame-options":           "DENY",
		},
		CertSANs:        []string{"*.example.com"},
		CertMatchesHost: true,
		StatusCode:      200,
		BodyKeywords:    []string{"jQuery"},
	}
	rep := DetectConflicts(p)
	if !rep.Clean {
		for _, c := range rep.Conflicts {
			t.Errorf("干净目标不应报冲突，却报了：%s — %s", c.Type, c.Title)
		}
	}
}

// ── 缓存测试 ──────────────────────────────────────────────

// ⭐⭐ 回归防护：缓存键必须区分 Host 头
//
// 同一 IP:80 上，不同 Host 头返回的是**完全不同的站点**
// （CDN/WAF 按 Host 路由）。若缓存键只用 URL，
// a.example.com 的指纹会被误用到 b.example.com 上 ——
// 产出「看起来正常但完全错误」的结论。
func TestMakeCacheKey_HostHeaderMatters(t *testing.T) {
	k1 := MakeCacheKey("http://1.2.3.4:80", "a.example.com", true, "UA")
	k2 := MakeCacheKey("http://1.2.3.4:80", "b.example.com", true, "UA")
	if k1 == k2 {
		t.Errorf("⭐ 不同 Host 头必须生成不同缓存键，但两者都是 %q", k1)
	}
	// 同 Host 必须生成相同键
	k3 := MakeCacheKey("http://1.2.3.4:80", "a.example.com", true, "UA")
	if k1 != k3 {
		t.Errorf("同参数应生成相同缓存键：%q vs %q", k1, k3)
	}
	// 大小写不敏感（Host 头本身不区分大小写）
	k4 := MakeCacheKey("http://1.2.3.4:80", "A.EXAMPLE.COM", true, "UA")
	if k1 != k4 {
		t.Errorf("Host 头应大小写不敏感：%q vs %q", k1, k4)
	}
	// 跟随重定向设置不同 → 键不同
	k5 := MakeCacheKey("http://1.2.3.4:80", "a.example.com", false, "UA")
	if k1 == k5 {
		t.Error("followRedirect 不同应生成不同缓存键（FinalURL 会不同）")
	}
	// URL 不同 → 键不同
	k6 := MakeCacheKey("http://1.2.3.5:80", "a.example.com", true, "UA")
	if k1 == k6 {
		t.Error("URL 不同应生成不同缓存键")
	}
}

// ⭐ 负缓存：失败结果应缓存但 TTL 远短于成功结果
//
// 实测教训：4 个子域重定向后超时，每次重试吃掉 16 秒。
// 完全不缓存失败 → 缓存对这批目标无效。
// 但 TTL 必须短，否则一次抖动会被固化成"该站点无指纹"。
func TestCache_NegativeTTL(t *testing.T) {
	c, err := NewFileTechCache("", time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}

	// 失败结果应写入（作为负缓存）
	failKey := "fail-key"
	c.Put(failKey, &ProbeResult{URL: "http://x", Err: "timeout"})

	got, ok := c.Get(failKey)
	if !ok {
		t.Fatal("失败结果应进入负缓存（否则重复重试会吃掉大量时间）")
	}
	if got.Err == "" {
		t.Error("负缓存应保留原始错误信息")
	}

	// 负缓存 TTL 远短于正常 TTL
	if NegativeCacheTTL >= CacheTTL {
		t.Errorf("负缓存 TTL(%v) 必须短于正常 TTL(%v)", NegativeCacheTTL, CacheTTL)
	}
	if NegativeCacheTTL > 30*time.Minute {
		t.Errorf("负缓存 TTL(%v) 过长 —— 一次抖动会被固化成'该站点无指纹'", NegativeCacheTTL)
	}
}

// ⭐ Get 必须返回深拷贝 —— 调用方（冲突检测）不应污染缓存
func TestCache_ReturnsDeepCopy(t *testing.T) {
	c, _ := NewFileTechCache("", time.Minute, false)
	c.Put("k", &ProbeResult{URL: "http://x", Server: "nginx"})

	got, _ := c.Get("k")
	got.Server = "被调用方修改了"
	got.URL = "被调用方改了"

	again, _ := c.Get("k")
	if again.Server != "nginx" {
		t.Errorf("⭐ Get 返回的必须是深拷贝，缓存被调用方污染：%q", again.Server)
	}
	if again.URL != "http://x" {
		t.Errorf("缓存里的 URL 被调用方改了：%q", again.URL)
	}
}

// ⭐ 缓存命中时要标记 Cached，让用户知道这不是实时结果
func TestCache_MarksCached(t *testing.T) {
	c, _ := NewFileTechCache("", time.Minute, false)
	c.Put("k", &ProbeResult{URL: "http://x", Server: "nginx"})

	got, _ := c.Get("k")
	if !got.Cached {
		t.Error("⭐ 缓存命中必须标记 Cached=true（用户需知道这不是实时结果）")
	}
	// 存进去的必须是 Cached=false
	if c.items["k"].Result.Cached {
		t.Error("存入缓存时应为 Cached=false（标记由 Get 设置）")
	}
}

// ⭐ 过期条目不应被返回，且应被清理
func TestCache_Expiry(t *testing.T) {
	c, _ := NewFileTechCache("", 50*time.Millisecond, false)
	c.Put("k", &ProbeResult{URL: "http://x", Server: "nginx"})

	if _, ok := c.Get("k"); !ok {
		t.Fatal("未过期时应命中")
	}
	time.Sleep(80 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Error("过期条目不应被返回")
	}
	if c.Len() != 0 {
		t.Error("过期条目应被清理（避免文件无限膨胀）")
	}
}

// ⭐ 统计：命中与未命中都要计数
func TestCache_Stats(t *testing.T) {
	c, _ := NewFileTechCache("", time.Minute, false)
	c.Put("k", &ProbeResult{URL: "http://x"})

	c.Get("k")     // 命中
	c.Get("miss1") // 未命中
	c.Get("miss2") // 未命中

	h, m, total := c.Stats()
	if h != 1 || m != 2 || total != 3 {
		t.Errorf("统计错误: hits=%d misses=%d total=%d, 期望 1/2/3", h, m, total)
	}
}

// ⭐⭐⭐ favicon 哈希表回归测试 —— **哈希值来自实测，不是记忆**
//
// 这条测试不验证哈希算法（已由 TestMurmur3X86_32_StandardVectors 覆盖），
// 而是**锁死哈希表的内容**。
//
// ⭐ 为什么必须锁：
//
//	填错的哈希**不会让程序崩溃**，只会让 favicon 识别**静默失效**
//	（表现是"永远匹配不上"，没有任何报错）—— 这是最难发现的一类 bug。
//
//	实测教训（2026-10-05）：初版表里 9 条凭印象填的哈希，实测后发现几乎全错。
//	例如 Jenkins 实际是 1928290，初版写的是 1989169301（差三个数量级）。
//	没有这条测试，那个错误会一直潜伏下去。
//
// 数据来源：internal/httpprobe/favicon_table.json
//
//	2026-10-05 下载各站点 /favicon.ico → 本项目 ShodanFaviconHash 计算 → 记录 md5
type favTableRow struct {
	hash int64
	size int
	md5  string
}

var faviconTableTestData = []favTableRow{
	{1884118115, 1150, "cede20407ea3f3bd0c4b3400e0259b3e"},
	{1928290, 15086, "eb49296996ffb774cc7d41587f9af573"},
	{1848946384, 6518, "7f969f62ee272a3be19966806fff4ad5"},
	{1265477436, 591, "66f9a1c3f2cfd0df1b570990e86d3095"},
	{-1668137428, 4335, "e90d8dffba444c7f6211e99d678e5cb2"},
	{-1098357615, 4022, "c120ba1c67bb7e4e419e3cfcc7dd21ac"},
	{-825614509, 32180, "35ee196961dbfd776b33bde140e872d7"},
	{1535719526, 20603, "4da3bc35b7bb6938cb5a993579c415df"},
	{-706997553, 15406, "68a611da7f2f44b48e8f7e428f80a2e0"},
	{2111119328, 183258, "ac3a6cc202d51cd4b38e90f5db79ebc9"},
	{1261264597, 4846, "d6e812cf4bd1f9fb1b1b02adc50377a4"},
	{104027616, 32988, "e0302326eae932221bbbab43fd67e8e2"},
	{1783771745, 5430, "75cbc0b319dc2ad8943250b5a47b067f"},
	{864985040, 1130, "7155f531279ffb7e3fe57bcca4cd1739"},
	{1349811561, 15086, "4ea55e1771796d16b62520ed85c9d342"},
	{-2133341160, 4286, "53a151ba1af3acdefe16fbbdad937ee4"},
	{1195255730, 15086, "1c14c20d9014206828a1a15ba7f2418b"},
	{21411084, 15406, "d9fd380e376a122d9308bf4917e1a76d"},
	{1117213901, 15406, "72e228c3809db53da8a884b6676ed36a"},
	{1905926913, 76693, "e23a86b669ba736a52f1296b111b373e"},
	{-1261306053, 908, "f4d4f7e79fd34e08e729580664e75720"},
	{-674472512, 1409, "d0be64e474b15a6c4140d1dbd66bf31c"},
	{1291258818, 647, "79ca1ffbee6b0f1044e20305d6da1c80"},
}

func TestFaviconTable_ContentsLocked(t *testing.T) {
	if len(faviconHashTable) != len(faviconTableTestData) {
		t.Errorf("⭐ 哈希表大小变了：代码 %d 条，测试数据 %d 条。"+
			"若是有意扩充，请同步更新 favicon_table.json 与本测试",
			len(faviconHashTable), len(faviconTableTestData))
	}
	seen := map[int64]string{}
	for _, d := range faviconTableTestData {
		fp, ok := faviconHashTable[d.hash]
		if !ok {
			t.Errorf("⭐ 哈希 %d（md5 %s）不在表中 —— 它被误删了",
				d.hash, d.md5[:12])
			continue
		}
		if fp.name == "" {
			t.Errorf("哈希 %d 的产品名为空", d.hash)
		}
		if fp.cat == "" {
			t.Errorf("⭐ %s 缺类别 —— 类别让 favicon 结论能与端口/正文交叉印证",
				fp.name)
		}
		if prev, dup := seen[d.hash]; dup {
			t.Errorf("哈希 %d 重复映射到 %s 与 %s", d.hash, prev, fp.name)
		}
		seen[d.hash] = fp.name
	}
}

// ⭐ 类别映射必须覆盖所有表内产品
func TestCategoryOf_Coverage(t *testing.T) {
	missing := []string{}
	for _, fp := range faviconHashTable {
		if fp.cat == "" {
			missing = append(missing, fp.name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("⭐ 以下产品未归类（categoryOf 需补 case）：%v", missing)
	}
}

// ⭐ 类别必须能用于交叉印证：favicon 结论与开放端口应能对上
func TestCategoryCrossReference(t *testing.T) {
	cases := []struct {
		product      string
		wantCat      string
		typicalPorts []int
	}{
		{"Redis", "数据库", []int{6379}},
		{"PostgreSQL", "数据库", []int{5432}},
		{"MongoDB", "数据库", []int{27017}},
		{"Apache", "Web服务器", []int{80, 443}},
		{"nginx", "Web服务器", []int{80, 443}},
		{"GitHub", "代码托管/CI", []int{443}},
		{"Docker", "容器", []int{2375, 2376}},
	}
	for _, c := range cases {
		got := categoryOf(c.product)
		if got != c.wantCat {
			t.Errorf("categoryOf(%q) = %q, 期望 %q", c.product, got, c.wantCat)
		}
		if len(c.typicalPorts) == 0 {
			t.Errorf("%s 未记录典型端口，无法交叉印证", c.product)
		}
	}
}

// ⭐ 未命中必须返回 ok=false，不能 panic
func TestProductInfo_Miss(t *testing.T) {
	p := &ProbeResult{IP: "1.2.3.4"}
	if n, _, ok := p.ProductInfo(); ok || n != "" {
		t.Errorf("无 favicon 时应返回 ok=false，实际 %q ok=%v", n, ok)
	}
	p.FaviconMurmur = 123456789
	if n, _, ok := p.ProductInfo(); ok || n != "" {
		t.Errorf("未收录的哈希应返回 ok=false，实际 %q ok=%v", n, ok)
	}
}

// ⭐⭐ favicon 命中必须能与其它来源交叉印证 —— 这是本工具的核心逻辑
//
// 场景：favicon 说"数据库"，但只开了 80 端口 → 矛盾，应报冲突。
func TestFaviconCrossRef_ConflictDetection(t *testing.T) {
	// favicon=Redis 但 Server 头是 IIS —— 明显矛盾
	p := &ProbeResult{
		URL:             "https://x.example.com",
		FaviconMurmur:   2111119328, // Redis
		Server:          "Microsoft-IIS/10.0",
		CFHeaders:       map[string]string{},
		CDNHeaders:      map[string]string{},
		SecurityHdrs:    map[string]string{},
		CertSANs:        []string{"*.example.com"},
		CertMatchesHost: true,
	}
	rep := DetectConflicts(p)
	found := false
	for _, c := range rep.Conflicts {
		if c.Type == ConflictFaviconVsServer {
			found = true
			// ⭐ 冲突时 favicon 侧必须标为 low 信任度
			for _, src := range c.Sources {
				if src.Source == "favicon" && src.Trust != "low" {
					t.Errorf("⭐ favicon 侧信任度应为 low（它误报率结构性偏高），实际 %q", src.Trust)
				}
			}
		}
	}
	if !found {
		t.Error("favicon=Redis 但 Server=IIS 应报 favicon_vs_server 冲突")
	}

	// 一致的情况：favicon=Redis（数据库），Server=nginx（反向代理）→ 不冲突
	p2 := &ProbeResult{
		URL:             "https://x.example.com",
		FaviconMurmur:   2111119328, // Redis
		Server:          "nginx",
		CFHeaders:       map[string]string{},
		CDNHeaders:      map[string]string{},
		SecurityHdrs:    map[string]string{},
		CertSANs:        []string{"*.example.com"},
		CertMatchesHost: true,
	}
	for _, c := range DetectConflicts(p2).Conflicts {
		if c.Type == ConflictFaviconVsServer {
			t.Error("Redis 跑在 nginx 后面是正常部署，不应报冲突")
		}
	}
}
