package httpprobe

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ⭐⭐ tech 结果缓存
//
// 为什么需要：
//
//	子域批量探测一次要打十几个 HTTP 请求（每个还含 favicon），
//	而渗透测试的典型工作流是「扫 → 复核 → 写报告 → 再复核」——
//	同一个目标会被反复探测多次。没有缓存时每次都要重新发一遍请求。
//
// ⭐ 缓存键的设计（本文件最关键的部分）：
//
//	**缓存键 = URL + HostHeader，不能只用 URL。**
//
//	原因：recon 阶段 URL 是 `http://1.2.3.4:80`（IP 形式，为了逐个探测
//	CDN 边缘节点），而 Host 头可能是 `a.example.com` 或 `b.example.com`。
//	**同一个 IP:80 上，不同 Host 头返回的是完全不同的站点** ——
//	用 URL 做键会导致 a.example.com 的结果被误用到 b.example.com 上。
//
//	这是本实现最容易写错、也最难被发现的地方。

// CacheTTL tech 结果默认有效期
//
// ⭐ 为什么是 1 天而不是 7 天：
//
//   - IP 归属（基础设施级）可以缓存 7 天
//
//   - CT 日志（只追加的历史记录）可以缓存 7 天
//
//   - ⭐ **HTTP 指纹是「当前状态」** —— 换版本、开关服务、
//     改安全头都会立刻改变指纹。缓存 7 天会给出严重过时的结论，
//     而过时的安全结论比没有结论更危险（会让人以为已经加固过了）。
//
//     1 天覆盖了「同一天内反复复核」这个主要场景，又不至于跨天误导。
const CacheTTL = 24 * time.Hour

// TechCache 是指纹结果缓存接口
type TechCache interface {
	// Get 查询缓存。cacheKey 应由 MakeCacheKey 生成。
	Get(cacheKey string) (*ProbeResult, bool)
	// Put 写入缓存
	Put(cacheKey string, r *ProbeResult)
	// Len 条目数
	Len() int
	// Save 落盘
	Save() error
}

// MakeCacheKey 生成缓存键
//
// ⭐ 关键：必须包含 HostHeader。理由见文件头注释。
//
//	同时纳入键的还有：
//	  - 跟随重定向开关（不同设置会得到不同的 FinalURL）
//	  - UserAgent（部分 WAF 对 UA 返回不同内容）
//	  - caps 采集能力开关（GrabFavicon/GrabH2/GrabJARM）——
//	    ⭐ 不含它会导致"先普通探测（JARM 关）→ 缓存写入空 JARM →
//	    再开 --tech-jarm 永远命中旧缓存"的静默失效（审查发现的 H1）。
//	    升级后旧键自然不命中，缓存自动重建。
func MakeCacheKey(url, hostHeader string, followRedirect bool, ua string, caps string) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(url))
	b.WriteString("\x00") // 分隔符，避免拼接歧义
	if hostHeader != "" {
		b.WriteString("host=")
		b.WriteString(strings.ToLower(hostHeader))
	}
	if followRedirect {
		b.WriteString("\x00follow")
	}
	// UA 只取前 40 字符（区分不同浏览器足够，又不至于键过长）
	if ua != "" {
		if len(ua) > 40 {
			ua = ua[:40]
		}
		b.WriteString("\x00ua=")
		b.WriteString(ua)
	}
	if caps != "" {
		b.WriteString("\x00caps=")
		b.WriteString(caps)
	}
	return b.String()
}

// CapabilityKey 把"影响结果的采集开关"编成缓存键片段
//
// 只列会改变 ProbeResult 内容的开关（favicon/H2/JARM 各自贡献字段）。
func CapabilityKey(grabFavicon, grabH2, grabJARM bool) string {
	var b strings.Builder
	if grabFavicon {
		b.WriteString("f")
	}
	if grabH2 {
		b.WriteString("h")
	}
	if grabJARM {
		b.WriteString("j")
	}
	return b.String()
}

// cacheEntry 单条缓存
type cacheEntry struct {
	Result   *ProbeResult `json:"result"`
	CachedAt int64        `json:"cached_at"` // Unix 纳秒（秒级精度对短 TTL 不可靠）
	// Neg 是否为负缓存（失败结果）
	Neg bool `json:"neg,omitempty"`
	// Host 供人工核对（键里有分隔符，这里单列便于查看）
	Host string `json:"host,omitempty"`
	URL  string `json:"url,omitempty"`
}

// ⭐ 负缓存 TTL（失败结果的缓存时长）
//
// 为什么需要负缓存：
//
//	实测发现 4 个子域是「重定向到 github.com 后超时」，
//	每次运行都要重试，单是这几个就吃掉 16 秒 —— 缓存对它们完全无效。
//
// 为什么 TTL 要短（10 分钟）：
//
//	失败结果**不应该**长期缓存，否则一次网络抖动会被缓存成
//	"该站点无指纹"，污染后续所有查询（这是 PassiveCache 踩过的坑）。
//	10 分钟足够覆盖「同一次排查里的多次重试」，
//	又短到不会把临时故障固化下来。
const NegativeCacheTTL = 10 * time.Minute

// FileTechCache 是基于 JSON 文件的指纹缓存
type FileTechCache struct {
	path string
	ttl  time.Duration
	// negTTL 失败结果的 TTL（0 = 不缓存失败）
	negTTL time.Duration

	mu    sync.RWMutex
	items map[string]*cacheEntry
	dirty bool

	// 统计（便于 CLI 展示命中率）
	hits   int
	misses int
}

// NewFileTechCache 创建指纹缓存
func NewFileTechCache(path string, ttl time.Duration, load bool) (*FileTechCache, error) {
	if ttl <= 0 {
		ttl = CacheTTL
	}
	c := &FileTechCache{
		path:   path,
		ttl:    ttl,
		negTTL: NegativeCacheTTL,
		items:  make(map[string]*cacheEntry),
	}
	if load {
		if err := c.load(); err != nil {
			// 首次运行无缓存是正常的，不当错误
			return c, nil
		}
	}
	return c, nil
}

// DefaultTechCachePath 返回默认缓存路径
func DefaultTechCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "wukan-tech-cache.json"
	}
	return filepath.Join(home, ".wukan", "tech-cache.json")
}

func (c *FileTechCache) load() error {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &c.items)
}

func (c *FileTechCache) save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	c.mu.RLock()
	// ⭐ 保存时剔除过期条目，避免文件无限膨胀
	now := time.Now().UnixNano()
	clean := make(map[string]*cacheEntry, len(c.items))
	for k, v := range c.items {
		ttl := int64(c.ttl)
		if v.Neg {
			ttl = int64(c.negTTL)
		}
		if now-v.CachedAt <= ttl {
			clean[k] = v
		}
	}
	b, err := json.MarshalIndent(clean, "", "  ")
	c.mu.RUnlock()
	if err != nil {
		return err
	}
	// ⭐ 先写临时文件再 rename —— 避免中途崩溃留半截文件
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// Get 查询缓存
func (c *FileTechCache) Get(cacheKey string) (*ProbeResult, bool) {
	c.mu.Lock()
	e, ok := c.items[cacheKey]
	if !ok {
		c.misses++
		c.mu.Unlock()
		return nil, false
	}
	// 过期检查（负缓存用更短的 TTL）
	ttl := c.ttl
	if e.Neg {
		ttl = c.negTTL
	}
	if ttl > 0 && time.Since(time.Unix(0, e.CachedAt)) > ttl {
		delete(c.items, cacheKey)
		c.dirty = true
		c.misses++
		c.mu.Unlock()
		return nil, false
	}
	c.hits++
	c.mu.Unlock()

	// ⭐ 返回深拷贝：调用方（冲突检测）不应修改缓存里的对象
	cp := *e.Result
	cp.Cached = true
	return &cp, true
}

// Put 写入缓存
func (c *FileTechCache) Put(cacheKey string, r *ProbeResult) {
	if r == nil {
		return
	}
	isFail := r.Err != ""
	// ⭐ 失败结果走**负缓存**（TTL 10 分钟）而不是完全不缓存：
	//   实测 4 个子域重定向后超时，每次重试吃掉 16 秒。
	//   但 TTL 必须短，否则一次抖动会被固化成"该站点无指纹"。
	if isFail && c.negTTL <= 0 {
		return
	}
	cp := *r
	cp.Cached = false // 标记由 Get 设置
	c.mu.Lock()
	c.items[cacheKey] = &cacheEntry{
		Result:   &cp,
		CachedAt: time.Now().UnixNano(),
		Neg:      isFail,
		Host:     r.HostHeaderUsed,
		URL:      r.URL,
	}
	c.dirty = true
	c.mu.Unlock()
}

// Len 条目数
func (c *FileTechCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// Save 落盘
func (c *FileTechCache) Save() error { return c.save() }

// Stats 命中统计
func (c *FileTechCache) Stats() (hits, misses, total int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses, c.hits + c.misses
}

// Clear 清空
func (c *FileTechCache) Clear() error {
	c.mu.Lock()
	c.items = make(map[string]*cacheEntry)
	c.dirty = false
	c.mu.Unlock()
	return os.Remove(c.path)
}

// ListEntries 列出缓存条目（供 --cache-stats 展示）
func (c *FileTechCache) ListEntries() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	type row struct {
		url  string
		host string
		age  time.Duration
		neg  bool
	}
	var rows []row
	for _, v := range c.items {
		rows = append(rows, row{
			url:  v.URL,
			host: v.Host,
			age:  time.Since(time.Unix(0, v.CachedAt)),
			neg:  v.Neg,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].url < rows[j].url })
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		line := fmt.Sprintf("%-44s", truncStr(r.url, 44))
		if r.host != "" {
			line += fmt.Sprintf(" Host=%-24s", truncStr(r.host, 24))
		}
		if r.neg {
			line += " [负缓存]"
		}
		line += fmt.Sprintf(" %s前", humanAge(r.age))
		out = append(out, line)
	}
	return out
}

func truncStr(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d秒", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d分", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d小时", int(d.Hours()))
	default:
		return fmt.Sprintf("%d天", int(d.Hours()/24))
	}
}
