package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// SubdomainSource 子域发现来源
type SubdomainSource string

const (
	SourceCT    SubdomainSource = "ct"    // 证书透明度
	SourceDNS   SubdomainSource = "dns"   // 主动 DNS 解析验证
	SourceBrute SubdomainSource = "brute" // 字典爆破（需授权，默认关）
)

// CTEntry 单条 CT 日志记录
type CTEntry struct {
	ID        string    `json:"id,omitempty"`
	Names     []string  `json:"dns_names,omitempty"`
	NotBefore time.Time `json:"not_before,omitempty"`
	NotAfter  time.Time `json:"not_after,omitempty"`
	Revoked   bool      `json:"revoked,omitempty"`
	CertSHA   string    `json:"cert_sha256,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
}

// SubdomainInfo 子域信息
type SubdomainInfo struct {
	Name string `json:"name"`
	// FirstSeen 首次在 CT 中出现
	FirstSeen time.Time `json:"first_seen,omitempty"`
	// LastSeen 最近在 CT 中出现
	LastSeen time.Time `json:"last_seen,omitempty"`
	// IsWildcard 是否为通配符证书条目（*.example.com）
	IsWildcard bool `json:"is_wildcard,omitempty"`
	// IsSubOfBase 是否是目标域的子域（排除 baidu-int.com 这类平行域）
	IsSubOfBase bool `json:"is_sub_of_base,omitempty"`
	// Resolves DNS 是否能解析（第二阶段验证）
	Resolves bool `json:"resolves,omitempty"`
	// ResolveIPs 解析出的地址
	ResolveIPs []string `json:"resolve_ips,omitempty"`
	// Sources 发现来源
	Sources []SubdomainSource `json:"sources,omitempty"`
	// CertCount 出现在多少张证书里
	CertCount int `json:"cert_count,omitempty"`
	// RevokedCount 其中被吊销的证书数
	RevokedCount int `json:"revoked_count,omitempty"`
}

// SubdomainResult 子域收集结果
type SubdomainResult struct {
	Subdomains []*SubdomainInfo `json:"subdomains,omitempty"`
	// Sources 实际可用的数据源
	SourcesUsed []string `json:"sources_used,omitempty"`
	// SourcesFailed 失败的数据源及原因
	SourcesFailed map[string]string `json:"sources_failed,omitempty"`
	// TotalEntries CT 原始条目数
	TotalEntries int `json:"total_entries,omitempty"`
	// Elapsed 耗时
	Elapsed string `json:"elapsed,omitempty"`
}

// Names 返回子域名列表
func (s *SubdomainResult) Names() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.Subdomains))
	for _, v := range s.Subdomains {
		out = append(out, v.Name)
	}
	return out
}

// Active 返回仍在生效的子域（证书未过期）
func (s *SubdomainResult) Active() []*SubdomainInfo {
	if s == nil {
		return nil
	}
	now := time.Now()
	var out []*SubdomainInfo
	for _, v := range s.Subdomains {
		if v.LastSeen.IsZero() {
			out = append(out, v)
			continue
		}
		// 证书有效期通常 90 天，超过一年基本可认为已废弃
		if now.Sub(v.LastSeen) < 365*24*time.Hour {
			out = append(out, v)
		}
	}
	return out
}

// ── CT 数据源接口 ─────────────────────────────────────────

// CTProvider 证书透明度数据源
type CTProvider interface {
	Name() string
	// Query 查询与 base 相关的所有证书条目
	Query(ctx context.Context, base string) ([]CTEntry, error)
}

// ── certspotter ───────────────────────────────────────────

type certspotterProvider struct {
	client *http.Client
	base   string
}

// NewCertSpotter 创建 certspotter 客户端
func NewCertSpotter(timeout time.Duration) CTProvider {
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	return &certspotterProvider{
		client: &http.Client{Timeout: timeout},
		base:   "https://api.certspotter.com/v1/issuances",
	}
}

func (p *certspotterProvider) Name() string { return "certspotter" }

type certspotterEntry struct {
	ID        string   `json:"id"`
	TBS       string   `json:"tbs_sha256"`
	Cert      string   `json:"cert_sha256"`
	DNSNames  []string `json:"dns_names"`
	PubKey    string   `json:"pubkey_sha256"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	Revoked   bool     `json:"revoked"`
}

func (p *certspotterProvider) Query(ctx context.Context, base string) ([]CTEntry, error) {
	url := fmt.Sprintf("%s?domain=%s&include_subdomains=true&expand=dns_names&match_wildcards=true",
		p.base, base)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wukan-recon/0.1")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certspotter 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("certspotter 限流（免费层 100 次/小时），稍后再试")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certspotter 返回 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	var raw []certspotterEntry
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("解析 certspotter 响应失败: %w", err)
	}

	out := make([]CTEntry, 0, len(raw))
	for _, r := range raw {
		e := CTEntry{
			ID:        r.ID,
			Names:     r.DNSNames,
			Revoked:   r.Revoked,
			CertSHA:   r.Cert,
			NotBefore: parseCTTime(r.NotBefore),
			NotAfter:  parseCTTime(r.NotAfter),
		}
		out = append(out, e)
	}
	return out, nil
}

func parseCTTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ── crt.sh ────────────────────────────────────────────────

type crtshProvider struct {
	client  *http.Client
	retries int
}

// NewCrtSh 创建 crt.sh 客户端
//
// ⚠️ crt.sh 实测经常 502 / 超时（2026-10-04 连续 3 次失败），
//
//	所以默认重试 3 次，且作为**备源**使用。
func NewCrtSh(timeout time.Duration, retries int) CTProvider {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if retries < 0 {
		retries = 0
	}
	return &crtshProvider{client: &http.Client{Timeout: timeout}, retries: retries}
}

func (p *crtshProvider) Name() string { return "crt.sh" }

type crtshEntry struct {
	ID             string `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	IssuerName     string `json:"issuer_name"`
	SerialNumber   string `json:"serial_number"`
}

func (p *crtshProvider) Query(ctx context.Context, base string) ([]CTEntry, error) {
	var lastErr error
	for attempt := 0; attempt <= p.retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		entries, err := p.queryOnce(ctx, base)
		if err == nil {
			return entries, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (p *crtshProvider) queryOnce(ctx context.Context, base string) ([]CTEntry, error) {
	// exclude=expired 排除已过期证书，减少数据量
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json&exclude=expired", base)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) wukan-recon/0.1")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh 请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh 返回 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var raw []crtshEntry
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("解析 crt.sh 响应失败: %w", err)
	}

	out := make([]CTEntry, 0, len(raw))
	for _, r := range raw {
		names := strings.Split(r.NameValue, "\n")
		cleaned := make([]string, 0, len(names))
		for _, n := range names {
			n = strings.TrimSpace(n)
			if n != "" {
				cleaned = append(cleaned, n)
			}
		}
		out = append(out, CTEntry{
			ID:        r.ID,
			Names:     cleaned,
			NotBefore: parseCTTime(r.NotBefore),
			NotAfter:  parseCTTime(r.NotAfter),
			Issuer:    r.IssuerName,
		})
	}
	return out, nil
}

// ── 聚合与处理 ────────────────────────────────────────────

// CTOptions CT 收集选项
type CTOptions struct {
	// Providers 数据源列表（按顺序尝试，成功即用）
	Providers []CTProvider
	// Timeout 单源超时
	Timeout time.Duration
	// VerifyDNS 是否对发现的子域做 DNS 解析验证（第二阶段）
	VerifyDNS bool
	// Resolver 用于验证的解析器
	Resolver Resolver
	// VerifyConcurrency 验证并发数
	VerifyConcurrency int
	// IncludeParallelDomains 是否包含非子域条目（如 baidu-int.com）
	IncludeParallelDomains bool
	// Cache CT 结果缓存（⭐ 应对 certspotter 免费层 100 次/小时限流）
	Cache CTCache
	// CacheTTL 缓存有效期
	CacheTTL time.Duration
}

// CTCache 是 CT 查询结果的缓存接口
type CTCache interface {
	GetCT(base string) ([]CTEntry, bool)
	PutCT(base string, entries []CTEntry)
}

// DefaultCTOptions 返回默认选项
func DefaultCTOptions() CTOptions {
	return CTOptions{
		// ⭐ 实测 certspotter 稳定（3.1s），crt.sh 常 502
		//    所以 certspotter 优先，crt.sh 作为备源
		Providers:              []CTProvider{NewCertSpotter(25 * time.Second), NewCrtSh(30*time.Second, 2)},
		Timeout:                40 * time.Second,
		VerifyDNS:              true,
		Resolver:               NewDoHResolver("aliyun", DoHAlidns, 6*time.Second),
		VerifyConcurrency:      20,
		IncludeParallelDomains: false,
	}
}

// CollectSubdomains 从 CT 日志收集子域
func CollectSubdomains(ctx context.Context, base string, opt CTOptions) *SubdomainResult {
	start := time.Now()
	res := &SubdomainResult{
		SourcesFailed: map[string]string{},
	}

	// ⭐ 先查缓存 —— certspotter 免费层仅 100 次/小时
	if opt.Cache != nil {
		if cached, ok := opt.Cache.GetCT(base); ok && len(cached) > 0 {
			res.SourcesUsed = append(res.SourcesUsed, "cache")
			return buildSubdomainResult(base, cached, res, opt, ctx, start)
		}
	}

	// 逐个数据源尝试，直到有结果
	var entries []CTEntry
	for _, p := range opt.Providers {
		pctx, cancel := context.WithTimeout(ctx, opt.Timeout)
		e, err := p.Query(pctx, base)
		cancel()

		if err != nil {
			res.SourcesFailed[p.Name()] = err.Error()
			continue
		}
		if len(e) == 0 {
			res.SourcesFailed[p.Name()] = "返回 0 条"
			continue
		}
		entries = e
		res.SourcesUsed = append(res.SourcesUsed, p.Name())
		break
	}

	if len(entries) == 0 {
		res.Elapsed = time.Since(start).String()
		return res
	}
	// 写缓存
	if opt.Cache != nil && len(entries) > 0 {
		opt.Cache.PutCT(base, entries)
	}
	return buildSubdomainResult(base, entries, res, opt, ctx, start)
}

// buildSubdomainResult 从 CT 条目构建子域结果（在线与缓存共用）
func buildSubdomainResult(base string, entries []CTEntry, res *SubdomainResult,
	opt CTOptions, ctx context.Context, start time.Time) *SubdomainResult {

	res.TotalEntries = len(entries)

	// 聚合成子域 → 时间线
	baseLower := strings.ToLower(base)
	agg := map[string]*SubdomainInfo{}
	var wildcardOnly bool

	for _, e := range entries {
		for _, raw := range e.Names {
			name := strings.ToLower(strings.TrimSpace(raw))
			if name == "" {
				continue
			}
			// 去掉通配符前缀以判断，但保留信息
			isWild := strings.HasPrefix(name, "*.")
			bare := strings.TrimPrefix(name, "*.")

			if !opt.IncludeParallelDomains && !isSubOrEqual(bare, baseLower) {
				continue
			}

			info, ok := agg[bare]
			if !ok {
				info = &SubdomainInfo{
					Name:        bare,
					IsWildcard:  isWild,
					IsSubOfBase: isSubOrEqual(bare, baseLower),
					Sources:     []SubdomainSource{SourceCT},
				}
				agg[bare] = info
			}
			info.CertCount++
			if e.Revoked {
				info.RevokedCount++
			}
			if !e.NotBefore.IsZero() {
				if info.FirstSeen.IsZero() || e.NotBefore.Before(info.FirstSeen) {
					info.FirstSeen = e.NotBefore
				}
			}
			if !e.NotAfter.IsZero() {
				if info.LastSeen.IsZero() || e.NotAfter.After(info.LastSeen) {
					info.LastSeen = e.NotAfter
				}
			}
		}
	}
	_ = wildcardOnly

	// ⭐ 根域自身：DNS 已在第一阶段解析过，直接标记为存活。
	//   实测 bug：github.com 自身出现在 CT 结果里，若走 verifyDNS
	//   会因为它已在 DNS 段解析过（但 CT 段的 verify 走的是另一条路径）
	//   而被标成"不解析"，产生矛盾输出。
	for _, info := range agg {
		if strings.EqualFold(info.Name, base) {
			info.Resolves = true
			info.Sources = appendUniqueSource(info.Sources, SourceDNS)
		}
	}

	// 排序：先按 last_seen 倒序（新的在前），再按名字
	list := make([]*SubdomainInfo, 0, len(agg))
	for _, v := range agg {
		list = append(list, v)
	}
	sort.Slice(list, func(i, j int) bool {
		if !list[i].LastSeen.Equal(list[j].LastSeen) {
			return list[i].LastSeen.After(list[j].LastSeen)
		}
		return list[i].Name < list[j].Name
	})
	res.Subdomains = list

	// 第二阶段：DNS 解析验证
	//
	// ⭐ 泛域名会让这一步几乎全部成功，此时"能解析"不代表资产存活。
	//    调用方应结合 recon 的 Wildcard 字段一起判断。
	if opt.VerifyDNS && opt.Resolver != nil {
		verifyDNS(ctx, list, opt)
	}

	res.Elapsed = time.Since(start).String()
	return res
}

func verifyDNS(ctx context.Context, list []*SubdomainInfo, opt CTOptions) {
	workers := max(opt.VerifyConcurrency, 1)
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	// 限制验证数量，避免上百个域名把时间拉太长
	const maxVerify = 100
	limit := len(list)
	if limit > maxVerify {
		limit = maxVerify
	}

	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func(info *SubdomainInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			qctx, cancel := context.WithTimeout(ctx, 6*time.Second)
			defer cancel()
			// ⭐ 必须跟随 CNAME 链，否则会误判。
			//   实测（2026-10-04）：www.github.com 是 CNAME → github.com，
			//   只查 A 记录会得到空结果，被误判为"子域不存活"。
			//   而 net.LookupHost / dns 包会自动跟随，我们手写查询不会。
			ips := resolveWithCNAME(qctx, opt.Resolver, info.Name)
			if len(ips) == 0 {
				return
			}
			info.Resolves = true
			info.Sources = append(info.Sources, SourceDNS)
			info.ResolveIPs = ips
		}(list[i])
	}
	wg.Wait()
}

// isSubOrEqual 判断 name 是否是 base 的子域或等于 base
func isSubOrEqual(name, base string) bool {
	if name == base {
		return true
	}
	return strings.HasSuffix(name, "."+base)
}

// resolveWithCNAME 解析域名，自动跟随 CNAME 链
//
// ⭐ 为什么必须自己实现（net.LookupHost 会跟随，但只能给 A/AAAA）：
//
//	实测：www.github.com 是 CNAME → github.com → A 记录
//	只查 A 会得到空结果，被误判为"子域已下线"。
//
// 标准库的 LookupHost 虽然会跟随，但它**只返回地址，不返回记录类型**，
// 且对 NS/MX/TXT 无效 —— 所以这里手写跟随逻辑。
func resolveWithCNAME(ctx context.Context, r Resolver, name string) []string {
	seen := map[string]bool{}
	var ips []string
	host := name

	for hop := 0; hop < 6; hop++ { // 最多跟 6 跳
		lh := strings.ToLower(host)
		if seen[lh] {
			break // 防环
		}
		seen[lh] = true

		// 先查 A
		a, aerr := r.Query(ctx, host, TypeA)
		if aerr == nil && len(a) > 0 {
			for _, rr := range a {
				if net.ParseIP(rr.Value) != nil {
					ips = append(ips, rr.Value)
				}
			}
		}
		// 补 AAAA
		aaaa, aaaaErr := r.Query(ctx, host, TypeAAAA)
		if aaaaErr == nil && len(aaaa) > 0 {
			for _, rr := range aaaa {
				if net.ParseIP(rr.Value) != nil {
					ips = append(ips, rr.Value)
				}
			}
		}
		if len(ips) > 0 {
			return dedupeIPs(ips)
		}

		// 没有地址 → 查 CNAME 继续跟
		cn, cnErr := r.Query(ctx, host, TypeCNAME)
		if cnErr != nil || len(cn) == 0 {
			break
		}
		next := strings.TrimSuffix(cn[0].Value, ".")
		if next == "" || next == host {
			break
		}
		host = next
	}
	return nil
}

func dedupeIPs(ips []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range ips {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func appendUniqueSource(s []SubdomainSource, v SubdomainSource) []SubdomainSource {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// ── CT 结果缓存 ───────────────────────────────────────────

// FileCTCache 是 CT 结果的文件缓存（JSON）
//
// ⭐ 为什么必须有：
//
//	certspotter 免费层 **100 次/小时**（实测第 20+ 次查询即返回 429），
//	crt.sh 又经常 502。批量做 recon 时两个源会同时耗尽，
//	导致子域收集整段失效。
//	→ 缓存让"扫 → 复核 → 写报告"的循环零消耗。
type FileCTCache struct {
	path  string
	ttl   time.Duration
	mu    sync.RWMutex
	items map[string]ctCacheEntry
}

type ctCacheEntry struct {
	Entries  []CTEntry `json:"entries"`
	CachedAt int64     `json:"cached_at"`
}

// NewFileCTCache 创建 CT 缓存
func NewFileCTCache(path string, ttl time.Duration, load bool) (*FileCTCache, error) {
	c := &FileCTCache{
		path:  path,
		ttl:   ttl,
		items: make(map[string]ctCacheEntry),
	}
	if load {
		if err := c.load(); err != nil {
			return c, nil // 首次运行无缓存，不是错误
		}
	}
	return c, nil
}

// DefaultCTCachePath 默认缓存路径
func DefaultCTCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "wukan-ct-cache.json"
	}
	return filepath.Join(home, ".wukan", "ct-cache.json")
}

func (c *FileCTCache) load() error {
	b, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(b, &c.items)
}

func (c *FileCTCache) save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	c.mu.RLock()
	b, err := json.MarshalIndent(c.items, "", "  ")
	c.mu.RUnlock()
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// GetCT 读取缓存
func (c *FileCTCache) GetCT(base string) ([]CTEntry, bool) {
	c.mu.RLock()
	e, ok := c.items[strings.ToLower(base)]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if c.ttl > 0 && time.Since(time.Unix(e.CachedAt, 0)) > c.ttl {
		return nil, false
	}
	return e.Entries, true
}

// PutCT 写入缓存
func (c *FileCTCache) PutCT(base string, entries []CTEntry) {
	c.mu.Lock()
	c.items[strings.ToLower(base)] = ctCacheEntry{
		Entries:  entries,
		CachedAt: time.Now().Unix(),
	}
	c.mu.Unlock()
}

// Save 落盘
func (c *FileCTCache) Save() error { return c.save() }

// Len 缓存条目数
func (c *FileCTCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}
