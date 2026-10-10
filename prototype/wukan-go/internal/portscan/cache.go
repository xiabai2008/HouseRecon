package portscan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ⭐⭐ 端口扫描结果缓存
//
// 为什么需要：
//
//	同 tech 指纹缓存的思路 —— 渗透测试的典型工作流是「扫 → 复核 → 写报告」，
//	同一批主机端口会被反复扫描。没有缓存时每次都要重新建立连接，
//	而端口扫描比指纹更贵：**filtered 端口每个都要等满超时**。
//
// ⭐ 为什么 TTL 是 6 小时（tech 指纹是 1 天）：
//
//	端口状态变化比指纹快得多 —— 服务临时下线、部署窗口内端口短暂开启、
//	防火墙规则被调整，都会立刻改变端口状态。6 小时覆盖"同一天内的
//	反复复核"，又不会把隔夜的临时状态固化成过时结论。
//
// ⭐ 缓存键必须包含"实际会发送的 Host 头"：
//
//	同一个 IP:80 上，不同 Host 头返回的是完全不同的站点（CDN/虚拟主机），
//	进而影响 banner 与 Server 判断 —— 与 tech 缓存的键设计同一个教训。
const CacheTTL = 6 * time.Hour

// NegativeCacheTTL 不确定结果（filtered/error）的缓存时长
//
// ⭐ filtered 是**超时导致的不确定结论**（无法区分被 DROP 的开放端口与
// 不存在的端口）—— 一次网络抖动就可能把开放端口误判为 filtered。
// 长缓存会把抖动固化成错误结论（与 tech 负缓存同一个教训：宁可重试，不可固化）。
const NegativeCacheTTL = 10 * time.Minute

// PortCache 是端口结果缓存接口
type PortCache interface {
	// Get 查询缓存。cacheKey 应由 MakeCacheKey 生成。
	Get(cacheKey string) (*PortResult, bool)
	// Put 写入缓存
	Put(cacheKey string, r *PortResult)
	// Len 条目数
	Len() int
	// Save 落盘
	Save() error
}

// MakeCacheKey 生成缓存键
//
// ⭐ 键包含所有**会改变探测结果**的输入：
//   - ip + port：探测目标本身
//   - hostHeader：HTTP 类端口的 Host 头（不同 Host = 不同站点）
//   - grabBanner：不抓 banner 的结果与抓了的语义不同，不能互相复用
//   - tlsProbe：对 TLS 端口是否做握手，结果与置信度差异很大
//
// 不包含 timeout：超时只影响 filtered 的判定边界，而 filtered 走的是
// 10 分钟负缓存，风险窗口有限；把 timeout 放进键会让缓存无谓碎片化。
func MakeCacheKey(ip string, port int, hostHeader string, grabBanner, tlsProbe bool) string {
	var b strings.Builder
	b.WriteString(ip)
	b.WriteString("\x00") // 分隔符，避免拼接歧义
	b.WriteString(strconv.Itoa(port))
	if hostHeader != "" {
		b.WriteString("\x00host=")
		b.WriteString(strings.ToLower(hostHeader))
	}
	if grabBanner {
		b.WriteString("\x00banner")
	}
	if tlsProbe {
		b.WriteString("\x00tls")
	}
	return b.String()
}

// isInconclusive 判定结果是否为"不确定"（走负缓存短 TTL）
//
// ⭐ 判定依据是**状态**而不是 Err 字段：
//   - filtered：超时，不确定（可能被 DROP 的开放端口，也可能不存在）
//   - error：探测出错，不确定
//   - open + Err（如 TLS 握手失败）：端口开放本身是**确定**的
//     （三次握手已完成），只是细节缺失 —— 属正缓存
func isInconclusive(r *PortResult) bool {
	return r.State == StateFiltered || r.State == StateError
}

// portCacheEntry 单条缓存
type portCacheEntry struct {
	Result   *PortResult `json:"result"`
	CachedAt int64       `json:"cached_at"` // Unix 纳秒（秒级精度对短 TTL 不可靠）
	// Neg 是否为负缓存（不确定结果）
	Neg bool `json:"neg,omitempty"`
	// IP / Host / Port 供人工核对（键里有分隔符，这里单列便于查看）
	IP   string `json:"ip,omitempty"`
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
}

// FilePortCache 是基于 JSON 文件的端口结果缓存
type FilePortCache struct {
	path string
	ttl  time.Duration
	// negTTL 不确定结果的 TTL（0 = 不缓存不确定结果）
	negTTL time.Duration

	mu    sync.RWMutex
	items map[string]*portCacheEntry
	dirty bool

	// 统计（便于 CLI 展示命中率）
	hits   int
	misses int
}

// NewFilePortCache 创建端口缓存
func NewFilePortCache(path string, ttl time.Duration, load bool) (*FilePortCache, error) {
	if ttl <= 0 {
		ttl = CacheTTL
	}
	c := &FilePortCache{
		path:   path,
		ttl:    ttl,
		negTTL: NegativeCacheTTL,
		items:  make(map[string]*portCacheEntry),
	}
	if load {
		if err := c.load(); err != nil {
			// 首次运行无缓存是正常的，不当错误
			return c, nil
		}
	}
	return c, nil
}

// DefaultPortCachePath 返回默认缓存路径
func DefaultPortCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "wukan-ports-cache.json"
	}
	return filepath.Join(home, ".wukan", "ports-cache.json")
}

func (c *FilePortCache) load() error {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &c.items)
}

func (c *FilePortCache) save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	c.mu.RLock()
	// ⭐ 保存时剔除过期条目，避免文件无限膨胀
	now := time.Now().UnixNano()
	clean := make(map[string]*portCacheEntry, len(c.items))
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
func (c *FilePortCache) Get(cacheKey string) (*PortResult, bool) {
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
	age := time.Since(time.Unix(0, e.CachedAt))
	if ttl > 0 && age > ttl {
		delete(c.items, cacheKey)
		c.dirty = true
		c.misses++
		c.mu.Unlock()
		return nil, false
	}
	c.hits++
	c.mu.Unlock()

	// ⭐ 返回深拷贝：调用方不应修改缓存里的对象
	//   （PortResult 全部是值类型字段，直接结构体拷贝即深拷贝）
	cp := *e.Result
	cp.Cached = true
	cp.CacheAge = humanAge(age)
	return &cp, true
}

// Put 写入缓存
func (c *FilePortCache) Put(cacheKey string, r *PortResult) {
	if r == nil {
		return
	}
	neg := isInconclusive(r)
	// ⭐ 不确定结果走**负缓存**（TTL 10 分钟）而不是完全不缓存：
	//   filtered 端口每次重试都要等满超时，不缓存会让重复扫描非常慢。
	//   但 TTL 必须短，否则一次网络抖动会把开放端口固化成 filtered。
	if neg && c.negTTL <= 0 {
		return
	}
	cp := *r
	cp.Cached = false // 标记由 Get 设置
	cp.CacheAge = ""  // 年龄由 Get 计算
	c.mu.Lock()
	c.items[cacheKey] = &portCacheEntry{
		Result:   &cp,
		CachedAt: time.Now().UnixNano(),
		Neg:      neg,
		IP:       r.IP,
		Host:     r.Host,
		Port:     r.Port,
	}
	c.dirty = true
	c.mu.Unlock()
}

// Len 条目数
func (c *FilePortCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// Save 落盘
func (c *FilePortCache) Save() error { return c.save() }

// Stats 命中统计
func (c *FilePortCache) Stats() (hits, misses, total int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses, c.hits + c.misses
}

// Clear 清空
func (c *FilePortCache) Clear() error {
	c.mu.Lock()
	c.items = make(map[string]*portCacheEntry)
	c.dirty = false
	c.mu.Unlock()
	return os.Remove(c.path)
}

// ListEntries 列出缓存条目（供 --cache-stats 展示）
func (c *FilePortCache) ListEntries() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	type row struct {
		target string
		host   string
		state  string
		age    time.Duration
		neg    bool
	}
	var rows []row
	for _, v := range c.items {
		target := v.IP
		if target == "" {
			target = v.Host
		}
		target = fmt.Sprintf("%s:%d", target, v.Port)
		rows = append(rows, row{
			target: target,
			host:   v.Host,
			state:  string(v.Result.State),
			age:    time.Since(time.Unix(0, v.CachedAt)),
			neg:    v.Neg,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].target < rows[j].target })
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		line := fmt.Sprintf("%-26s", truncStr(r.target, 26))
		line += fmt.Sprintf(" %-8s", r.state)
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
