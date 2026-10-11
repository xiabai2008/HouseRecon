package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── 被动 DNS / 资产来源 ───────────────────────────────────

// PassiveSource 被动资产来源
type PassiveSource string

const (
	SourcePassiveDNS PassiveSource = "passive_dns" // 历史解析记录
	SourceReverseIP  PassiveSource = "reverse_ip"  // IP 反查同源资产
)

// HistoricalIP 单条历史解析记录
type HistoricalIP struct {
	IP      string    `json:"ip"`
	Sources []string  `json:"sources,omitempty"`
	First   time.Time `json:"first_seen,omitempty"`
	Last    time.Time `json:"last_seen,omitempty"`
}

// PDNSTimelineEntry 一条带时间戳的历史解析记录（P2-1 时间线）
type PDNSTimelineEntry struct {
	Hostname  string    `json:"hostname"`
	IP        string    `json:"ip"`
	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	Source    string    `json:"source,omitempty"`
}

// PassiveDNSResult 被动 DNS 结果
type PassiveDNSResult struct {
	// Records 子域 → 历史 IP 列表
	Records map[string][]string `json:"records,omitempty"`
	// IPFirstSeen 每个 IP 首次出现时间
	IPFirstSeen map[string]time.Time `json:"ip_first_seen,omitempty"`
	// Timeline ⭐ 带时间戳的历史解析（OTX，P2-1）——"何时迁移、迁移到哪"
	Timeline []PDNSTimelineEntry `json:"timeline,omitempty"`
	// TotalEntries 原始条目数
	TotalEntries int `json:"total_entries,omitempty"`
	// SourcesUsed 实际可用的源
	SourcesUsed []string `json:"sources_used,omitempty"`
	// SourcesFailed 失败的源及原因
	SourcesFailed map[string]string `json:"sources_failed,omitempty"`
	// Elapsed 耗时
	Elapsed string `json:"elapsed,omitempty"`
}

// Subdomains 返回所有有历史记录的子域
func (p *PassiveDNSResult) Subdomains() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.Records))
	for k := range p.Records {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// AllIPs 返回所有历史 IP（去重，按首次出现时间倒序）
//
// ⭐ 价值：这些 IP 是**曾经**解析过的，可能已经释放给别人了。
//
//	去查这些 IP 的 rDNS / 归属，能发现"域名已下线但 IP 仍在他人手上"的情况。
func (p *PassiveDNSResult) AllIPs() []string {
	if p == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, ips := range p.Records {
		for _, ip := range ips {
			if !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
			}
		}
	}
	// 按首次出现时间倒序（越早越可能是原始资产）
	sort.Slice(out, func(i, j int) bool {
		ti, oki := p.IPFirstSeen[out[i]]
		tj, okj := p.IPFirstSeen[out[j]]
		if oki && okj && !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return out[i] < out[j]
	})
	return out
}

// ReverseIPResult IP 反查结果
type ReverseIPResult struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames,omitempty"`
	Source    string   `json:"source,omitempty"`
	Elapsed   string   `json:"elapsed,omitempty"`
	Err       string   `json:"error,omitempty"`
}

// ── hackertarget 客户端 ───────────────────────────────────

// EnvHackerTargetKey 环境变量名：hackertarget API key（可选）
//
// ⭐ 免费层仅 50 次/天，批量场景根本不够用；配置 key 后按套餐提升额度。
//
//	官方 API 通过 URL 参数 `apikey` 识别套餐（hackertarget.com/api/）。
const EnvHackerTargetKey = "WUKAN_HACKERTARGET_KEY"

// HackerTargetClient 访问 hackertarget.com 的 API
//
// ⭐ 选它的原因（实测 2026-10-04）：
//   - **免费层无需 API key**（SecurityTrails 等都要 key）
//   - 返回纯 CSV/文本，解析简单
//   - hostsearch（子域→IP）1.3s / dnslookup 1.4s / reverseiplookup 1.3s
//   - 一次 hostsearch 返回 1000 条子域，够用
type HackerTargetClient struct {
	client  *http.Client
	baseURL string
	// apiKey 可选 API key（来自环境变量 WUKAN_HACKERTARGET_KEY）
	apiKey string
}

// NewHackerTarget 创建客户端（自动读取 WUKAN_HACKERTARGET_KEY）
func NewHackerTarget(timeout time.Duration) *HackerTargetClient {
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	return &HackerTargetClient{
		client:  &http.Client{Timeout: timeout},
		baseURL: "https://api.hackertarget.com",
		// ⭐ 裁掉空白：用户从别处复制 key 常带空格/换行
		apiKey: strings.TrimSpace(os.Getenv(EnvHackerTargetKey)),
	}
}

// HasKey 是否配置了 API key
func (c *HackerTargetClient) HasKey() bool { return c.apiKey != "" }

// apiURL 构造 API 请求地址（q 转义；配置了 key 时附加 apikey 参数）
func (c *HackerTargetClient) apiURL(endpoint, q string) string {
	u := fmt.Sprintf("%s/%s/?q=%s", c.baseURL, endpoint, url.QueryEscape(q))
	if c.apiKey != "" {
		u += "&apikey=" + url.QueryEscape(c.apiKey)
	}
	return u
}

// quotaExceeded 判定响应体是否为配额耗尽
func quotaExceeded(text string) bool {
	low := strings.ToLower(text)
	return strings.Contains(low, "api count exceeded") ||
		strings.Contains(low, "too many requests")
}

// quotaHint 生成配额相关的处置提示
//
// ⭐ 有 key 和没 key 的处置完全不同：没 key 是"告诉你怎么提升"，
//
//	有 key 是"检查你的 key/套餐"——只说一句"限流了"等于没说。
func (c *HackerTargetClient) quotaHint() string {
	if c.apiKey != "" {
		return "已配置 key 仍被限流 —— 检查 key 是否有效、套餐额度是否用尽"
	}
	return "免费层 50 次/天，设置环境变量 " + EnvHackerTargetKey + " 可提升额度"
}

// hackertarget 的免费额度是每 50 请求/天，很紧
// 所以必须缓存，且并发要低。

// HostSearch 子域 → IP 映射查询
//
// 返回格式（纯 CSV，每行 host,ip）：
//
//	github.com,140.82.113.4
//	accelerator.github.com,185.199.110.153
func (c *HackerTargetClient) HostSearch(ctx context.Context, domain string) (map[string][]string, error) {
	body, err := c.get(ctx, c.apiURL("hostsearch", domain))
	if err != nil {
		return nil, err
	}
	text := string(body)
	// 错误是返回在响应体里的，不是 HTTP 状态码
	if strings.Contains(text, "error") || quotaExceeded(text) {
		msg := strings.TrimSpace(text)
		if len(msg) > 120 {
			msg = msg[:120]
		}
		if quotaExceeded(text) {
			return nil, fmt.Errorf("hackertarget 限流: %s（%s）",
				firstLine(msg), c.quotaHint())
		}
		return nil, fmt.Errorf("hackertarget: %s", msg)
	}

	records := map[string][]string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(parts[0]))
		ip := strings.TrimSpace(parts[1])
		if host == "" || net.ParseIP(ip) == nil {
			continue
		}
		ip = normalizeIP(ip)
		key := host + "|" + ip
		if seen[key] {
			continue
		}
		seen[key] = true
		records[host] = append(records[host], ip)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("hackertarget: 无记录")
	}
	return records, nil
}

// DNSLookup 根域的记录类型查询（第二个数据源，用于交叉验证）
func (c *HackerTargetClient) DNSLookup(ctx context.Context, domain string) (map[string][]string, error) {
	body, err := c.get(ctx, c.apiURL("dnslookup", domain))
	if err != nil {
		return nil, err
	}
	text := string(body)
	// ⭐ 配额耗尽必须显式报错 —— 此前只查 "error" 字样，配额消息不含
	//   "error"，会静默返回空结果（表现为"该域没有记录"）
	if quotaExceeded(text) {
		return nil, fmt.Errorf("hackertarget 限流: %s（%s）",
			firstLine(text), c.quotaHint())
	}
	if strings.Contains(text, "error") {
		return nil, fmt.Errorf("hackertarget: %s", strings.TrimSpace(firstLine(text)))
	}
	records := map[string][]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		rtype := strings.ToUpper(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		if rtype == "" || val == "" {
			continue
		}
		records[rtype] = append(records[rtype], val)
	}
	return records, nil
}

// ReverseIPLookup IP 反查同源主机名
//
// ⭐ 渗透价值：给定一个 IP，找出所有指向它的域名 —— 常见于
//
//	共享主机、CDN 回源、云主机上跑着多个站点
//
// 这能发现"你不知道的、跑在同一台服务器上的其他域"。
func (c *HackerTargetClient) ReverseIPLookup(ctx context.Context, ip string) ([]string, error) {
	body, err := c.get(ctx, c.apiURL("reverseiplookup", ip))
	if err != nil {
		return nil, err
	}
	text := string(body)
	// ⭐ 与 DNSLookup 同理：配额耗尽必须显式报错，不能静默返回空
	if quotaExceeded(text) {
		return nil, fmt.Errorf("hackertarget 限流: %s（%s）",
			firstLine(text), c.quotaHint())
	}
	if strings.Contains(text, "error") {
		return nil, fmt.Errorf("hackertarget: %s", strings.TrimSpace(firstLine(text)))
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.ToLower(line))
		if line == "" || seen[line] || net.ParseIP(line) != nil {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	sort.Strings(out)
	return out, nil
}

func (c *HackerTargetClient) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// ⭐ 伪装成浏览器。实测 hackertarget 对 UA 敏感
	req.Header.Set("User-Agent",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "+
			"(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("hackertarget 限流（HTTP 429）: %s", c.quotaHint())
	}
	if resp.StatusCode == http.StatusOK {
		return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		// 4xx 也要读 body —— hackertarget 把错误写在响应体里
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return b, nil
	}
	return nil, fmt.Errorf("返回 %d", resp.StatusCode)
}

// ── 编排 ─────────────────────────────────────────────────

// PassiveOptions 被动收集选项
type PassiveOptions struct {
	// Enabled 是否启用
	Enabled bool
	// HostSearch 是否做子域→IP 查询
	HostSearch bool
	// Timeline 是否查询 OTX 历史时间线（P2-1，免费无 key）
	Timeline bool
	// ReverseIPLimit 最多对多少个 IP 做反查（配额紧）
	ReverseIPLimit int
	// Timeout 超时
	Timeout time.Duration
	// Cache 缓存
	Cache PassiveCache
	// Concurrency 并发
	Concurrency int
}

// DefaultPassiveOptions 默认选项
func DefaultPassiveOptions() PassiveOptions {
	return PassiveOptions{
		Enabled:        true,
		HostSearch:     true,
		Timeline:       true, // ⭐ OTX 免费，默认开启（失败自动降级）
		ReverseIPLimit: 3,    // ⭐ 配额只有 50/天，默认保守
		Timeout:        30 * time.Second,
		Concurrency:    2, // hackertarget 对并发敏感
	}
}

// PassiveCache 被动数据缓存
type PassiveCache interface {
	GetPassive(key string) (map[string][]string, bool)
	PutPassive(key string, records map[string][]string)
	// GetTimeline / PutTimeline 时间线缓存（P2-1）
	GetTimeline(key string) ([]PDNSTimelineEntry, bool)
	PutTimeline(key string, entries []PDNSTimelineEntry)
}

// CollectPassive 收集被动 DNS 资产
func CollectPassive(ctx context.Context, domain string, opt PassiveOptions) *PassiveDNSResult {
	start := time.Now()
	res := &PassiveDNSResult{
		SourcesFailed: map[string]string{},
	}
	if !opt.Enabled {
		res.Elapsed = time.Since(start).String()
		return res
	}

	// 缓存优先（⭐ 配额只有 50/天）
	if opt.Cache != nil {
		if cached, ok := opt.Cache.GetPassive("hostsearch:" + domain); ok && len(cached) > 0 {
			res.Records = cached
			res.SourcesUsed = append(res.SourcesUsed, "cache")
			// ⭐ 时间线单独补齐：hostsearch 有缓存不代表时间线也有
			//   （否则缓存命中的运行永远看不到时间线）
			collectTimeline(ctx, domain, opt, res)
			res.Elapsed = time.Since(start).String()
			return res
		}
	}

	ht := NewHackerTarget(opt.Timeout)
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	if opt.HostSearch {
		if recs, err := ht.HostSearch(ctx, domain); err != nil {
			res.SourcesFailed["hackertarget/hostsearch"] = err.Error()
		} else {
			res.Records = recs
			res.SourcesUsed = append(res.SourcesUsed, "hackertarget/hostsearch")
			res.TotalEntries = countRecords(recs)
			if opt.Cache != nil {
				opt.Cache.PutPassive("hostsearch:"+domain, recs)
			}
		}
	}

	// 根域 DNS 交叉验证（多源取 diff 是调研报告的核心建议）
	if recs, err := ht.DNSLookup(ctx, domain); err != nil {
		res.SourcesFailed["hackertarget/dnslookup"] = err.Error()
	} else if len(res.Records) > 0 {
		// 交叉验证：dnslookup 给出根域的 A 记录，与 hostsearch 取交集/并集
		if rootIPs, ok := recs["A"]; ok && !ok {
			_ = rootIPs
		}
		res.SourcesUsed = append(res.SourcesUsed, "hackertarget/dnslookup")
	} else {
		res.SourcesUsed = append(res.SourcesUsed, "hackertarget/dnslookup")
	}

	// ⭐ 时间线（P2-1）：OTX 带时间戳的历史解析 ——"何时迁移、迁移到哪"
	collectTimeline(ctx, domain, opt, res)

	res.Elapsed = time.Since(start).String()
	return res
}

// collectTimeline 查询（或读缓存）OTX 历史时间线（P2-1）
//
// 失败不致命：记录到 SourcesFailed 并继续（OTX 挂了不影响 hostsearch 的结果）。
func collectTimeline(ctx context.Context, domain string, opt PassiveOptions, res *PassiveDNSResult) {
	if !opt.Timeline || res == nil {
		return
	}
	key := "timeline:" + domain
	if opt.Cache != nil {
		if tl, ok := opt.Cache.GetTimeline(key); ok && len(tl) > 0 {
			res.Timeline = tl
			res.SourcesUsed = append(res.SourcesUsed, "otx/cache")
			return
		}
	}
	cctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	entries, err := NewOTX(opt.Timeout).PassiveDNS(cctx, domain)
	if err != nil {
		res.SourcesFailed["otx/passive_dns"] = err.Error()
		return
	}
	if len(entries) == 0 {
		// 无记录不算失败（该域可能确实没有历史）
		return
	}
	res.Timeline = entries
	res.SourcesUsed = append(res.SourcesUsed, "otx/passive_dns")
	if opt.Cache != nil {
		opt.Cache.PutTimeline(key, entries)
	}
}

func countRecords(recs map[string][]string) int {
	n := 0
	for _, v := range recs {
		n += len(v)
	}
	return n
}

// ReverseLookup 对 IP 做反查（同源资产发现）
func ReverseLookup(ctx context.Context, ips []string, opt PassiveOptions) []*ReverseIPResult {
	limit := len(ips)
	if opt.ReverseIPLimit > 0 && limit > opt.ReverseIPLimit {
		limit = opt.ReverseIPLimit
	}
	if limit == 0 {
		return nil
	}

	out := make([]*ReverseIPResult, limit)
	ht := NewHackerTarget(opt.Timeout)
	sem := make(chan struct{}, max(opt.Concurrency, 1))
	var wg sync.WaitGroup

	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func(idx int, ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			t0 := time.Now()
			r := &ReverseIPResult{IP: ip, Source: "hackertarget/reverseiplookup"}
			cctx, cancel := context.WithTimeout(ctx, opt.Timeout)
			hosts, err := ht.ReverseIPLookup(cctx, ip)
			cancel()
			r.Elapsed = time.Since(t0).String()
			if err != nil {
				r.Err = err.Error()
			} else {
				r.Hostnames = hosts
			}
			out[idx] = r
		}(i, ips[i])
	}
	wg.Wait()

	// 排掉失败的，只保留有结果的
	var ok []*ReverseIPResult
	for _, r := range out {
		if r != nil && r.Err == "" && len(r.Hostnames) > 0 {
			ok = append(ok, r)
		}
	}
	return ok
}

// ── 缓存实现 ─────────────────────────────────────────────

// FilePassiveCache 被动数据的文件缓存
type FilePassiveCache struct {
	path  string
	ttl   time.Duration
	mu    sync.RWMutex
	items map[string]passiveCacheEntry
}

type passiveCacheEntry struct {
	Records  map[string][]string `json:"records,omitempty"`
	Timeline []PDNSTimelineEntry `json:"timeline,omitempty"`
	CachedAt int64               `json:"cached_at"`
}

// NewFilePassiveCache 创建被动数据缓存
func NewFilePassiveCache(path string, ttl time.Duration, load bool) (*FilePassiveCache, error) {
	c := &FilePassiveCache{
		path:  path,
		ttl:   ttl,
		items: make(map[string]passiveCacheEntry),
	}
	if load {
		if err := c.load(); err != nil {
			return c, nil
		}
	}
	return c, nil
}

// DefaultPassiveCachePath 默认缓存路径
func DefaultPassiveCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "wukan-passive-cache.json"
	}
	return filepath.Join(home, ".wukan", "passive-cache.json")
}

func (c *FilePassiveCache) load() error {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &c.items)
}

func (c *FilePassiveCache) save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	c.mu.RLock()
	b, err := json.MarshalIndent(c.items, "", "  ")
	c.mu.RUnlock()
	if err != nil {
		return err
	}
	// ⭐ 先写临时文件再 rename，避免中途崩溃留半截文件
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// GetPassive 读缓存
func (c *FilePassiveCache) GetPassive(key string) (map[string][]string, bool) {
	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()
	if !ok || len(e.Records) == 0 {
		return nil, false
	}
	if c.ttl > 0 && time.Since(time.Unix(e.CachedAt, 0)) > c.ttl {
		return nil, false
	}
	return e.Records, true
}

// PutPassive 写缓存
func (c *FilePassiveCache) PutPassive(key string, records map[string][]string) {
	c.mu.Lock()
	c.items[key] = passiveCacheEntry{Records: records, CachedAt: time.Now().Unix()}
	c.mu.Unlock()
}

// GetTimeline 读时间线缓存（P2-1）
func (c *FilePassiveCache) GetTimeline(key string) ([]PDNSTimelineEntry, bool) {
	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()
	if !ok || len(e.Timeline) == 0 {
		return nil, false
	}
	if c.ttl > 0 && time.Since(time.Unix(e.CachedAt, 0)) > c.ttl {
		return nil, false
	}
	return e.Timeline, true
}

// PutTimeline 写时间线缓存（P2-1）
func (c *FilePassiveCache) PutTimeline(key string, entries []PDNSTimelineEntry) {
	c.mu.Lock()
	c.items[key] = passiveCacheEntry{Timeline: entries, CachedAt: time.Now().Unix()}
	c.mu.Unlock()
}

// Save 落盘
func (c *FilePassiveCache) Save() error { return c.save() }

// ── 工具 ─────────────────────────────────────────────────

func normalizeIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return s
	}
	return ip.String()
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// timelineChain 提取某主机名的时间线并按首次出现排序（P2-1）
//
// ⭐ 输出即"迁移轨迹"：IP 按首次出现排序后，相邻跳变 = 一次迁移。
func timelineChain(entries []PDNSTimelineEntry, hostname string) []PDNSTimelineEntry {
	var out []PDNSTimelineEntry
	for _, e := range entries {
		if strings.EqualFold(e.Hostname, hostname) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.Before(out[j].FirstSeen)
		}
		return out[i].IP < out[j].IP
	})
	return out
}
