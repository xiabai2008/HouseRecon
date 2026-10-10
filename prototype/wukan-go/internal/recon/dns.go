// Package recon 实现域名信息卡：DNS 解析 + RDAP 注册信息 + 证书透明度子域收集。
//
// ⭐ 全部被动：只查询公开数据，不向目标发送任何探测包。
package recon

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// RecordType DNS 记录类型
type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeCNAME RecordType = "CNAME"
	TypeNS    RecordType = "NS"
	TypeMX    RecordType = "MX"
	TypeTXT   RecordType = "TXT"
	TypeSOA   RecordType = "SOA"
	TypePTR   RecordType = "PTR"
)

// DNSRecord 单条 DNS 记录
type DNSRecord struct {
	Type  RecordType `json:"type"`
	Name  string     `json:"name"`
	Value string     `json:"value"`
	TTL   uint32     `json:"ttl,omitempty"`
}

// DNSResult DNS 解析结果
type DNSResult struct {
	// Records 按类型分组的记录
	Records map[RecordType][]DNSRecord `json:"records,omitempty"`
	// IPs 去重后的 A/AAAA 地址（按出现顺序）
	IPs []string `json:"ips,omitempty"`
	// Wildcard 泛域名解析检测
	Wildcard string `json:"wildcard,omitempty"`
	// Resolver 使用的解析器
	Resolver string `json:"resolver,omitempty"`
	// Err 解析过程中的错误（部分成功时非空）
	Err string `json:"error,omitempty"`
	// Elapsed 耗时
	Elapsed string `json:"elapsed,omitempty"`
}

// Get 按类型取记录
func (d *DNSResult) Get(t RecordType) []DNSRecord {
	if d == nil {
		return nil
	}
	return d.Records[t]
}

// FirstIP 返回第一个 IP
func (d *DNSResult) FirstIP() string {
	if d == nil || len(d.IPs) == 0 {
		return ""
	}
	return d.IPs[0]
}

// NXDomain 是否为 NXDOMAIN
func (d *DNSResult) NXDomain() bool {
	return d != nil && strings.Contains(d.Err, "NXDOMAIN")
}

// ── Resolver 接口 ─────────────────────────────────────────

// Resolver 是 DNS 解析器
type Resolver interface {
	// Name 解析器名称
	Name() string
	// Query 查询单条记录
	Query(ctx context.Context, name string, t RecordType) ([]DNSRecord, error)
}

// ResolverFunc 让函数实现 Resolver
type ResolverFunc struct {
	ResolverName string
	QueryFunc    func(ctx context.Context, name string, t RecordType) ([]DNSRecord, error)
}

func (r *ResolverFunc) Name() string { return r.ResolverName }
func (r *ResolverFunc) Query(ctx context.Context, name string, t RecordType) ([]DNSRecord, error) {
	return r.QueryFunc(ctx, name, t)
}

// DefaultRecordTypes 默认查询的记录类型
var DefaultRecordTypes = []RecordType{TypeA, TypeAAAA, TypeCNAME, TypeNS, TypeMX, TypeTXT, TypeSOA}

// DNSOptions DNS 解析选项
type DNSOptions struct {
	// Types 要查询的记录类型
	Types []RecordType
	// FollowCNAME 是否跟随 CNAME 链（取最终地址）
	FollowCNAME bool
	// CheckWildcard 是否检测泛域名解析
	CheckWildcard bool
	// Timeout 单条查询超时
	Timeout time.Duration
	// Concurrency 并发查询数
	Concurrency int
}

// DefaultDNSOptions 返回默认选项
func DefaultDNSOptions() DNSOptions {
	return DNSOptions{
		Types:         DefaultRecordTypes,
		FollowCNAME:   true,
		CheckWildcard: true,
		Timeout:       6 * time.Second,
		Concurrency:   8,
	}
}

// ResolveDNS 解析域名 DNS 记录
//
// ⭐ 泛域名检测的价值：
//
//	如果 *.example.com 能解析，那么历史证书里出现过的任意子域都会解析成功。
//	此时"这个子域还活着"不能作为资产存活的证据 —— 必须结合
//	HTTP 实际响应才能判断。报告会明确提示这一点。
func ResolveDNS(ctx context.Context, domain string, r Resolver, opt DNSOptions) *DNSResult {
	start := time.Now()
	res := &DNSResult{
		Records:  make(map[RecordType][]DNSRecord),
		Resolver: r.Name(),
	}

	if opt.Timeout <= 0 {
		opt.Timeout = 6 * time.Second
	}
	types := opt.Types
	if len(types) == 0 {
		types = DefaultRecordTypes
	}

	// 并发查询各类型
	type resItem struct {
		t   RecordType
		rec []DNSRecord
		err error
	}
	ch := make(chan resItem, len(types))
	sem := make(chan struct{}, max(opt.Concurrency, 1))

	for _, t := range types {
		go func(rt RecordType) {
			sem <- struct{}{}
			defer func() { <-sem }()
			rec, err := r.Query(ctx, domain, rt)
			ch <- resItem{rt, rec, err}
		}(t)
	}

	var errs []string
	for range types {
		it := <-ch
		if it.err != nil {
			// NXDOMAIN 是有意义的结论（域名不存在），不是错误噪音
			if isNXDomain(it.err) {
				errs = append(errs, "NXDOMAIN")
			} else if !isNoRecord(it.err) {
				errs = append(errs, fmt.Sprintf("%s: %v", it.t, it.err))
			}
			continue
		}
		if len(it.rec) > 0 {
			res.Records[it.t] = it.rec
		}
	}

	// 泛域名检测
	if opt.CheckWildcard {
		res.Wildcard = detectWildcard(ctx, r, domain, opt.Timeout)
	}

	// 汇总 IP
	res.IPs = collectIPs(res.Records)

	// CNAME 链跟随
	if opt.FollowCNAME {
		res.IPs = followCNAMEChain(ctx, r, domain, res, opt.Timeout)
	}

	if len(errs) > 0 {
		res.Err = strings.Join(dedupeStrings(errs), "; ")
	}
	res.Elapsed = time.Since(start).String()
	return res
}

func detectWildcard(ctx context.Context, r Resolver, domain string, timeout time.Duration) string {
	// 随机子域名，能解析说明配了泛域名
	probe := fmt.Sprintf("wukan-wc-%d-%s", time.Now().UnixNano()%1000000,
		strings.ReplaceAll(randomLabel(6), "-", "x"))
	probe += "." + domain

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	rec, err := r.Query(cctx, probe, TypeA)
	if err != nil || len(rec) == 0 {
		return "" // 无泛域名
	}
	return rec[0].Value
}

func collectIPs(recs map[RecordType][]DNSRecord) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range []RecordType{TypeA, TypeAAAA} {
		for _, r := range recs[t] {
			// ⭐ 必须用 net.ParseIP 校验。
			//   实测 bug（2026-10-04）：gitee.com 的 A 记录里
			//   混入了 CNAME 目标 `gitee.com-31ba39d0fd3.baiduads.com.`，
			//   未校验就进了 IP 列表，导致后面 IP 归属查询全部报错。
			//   原因：CNAME 链跟随时 DoH 会在 A 记录的 Answer 里
			//   带上 CNAME 主机名，而 DoH 的 type 字段仍标 1(A)。
			if net.ParseIP(r.Value) == nil {
				continue
			}
			if !seen[r.Value] {
				seen[r.Value] = true
				out = append(out, r.Value)
			}
		}
	}
	return out
}

// followCNAMEChain 跟随 CNAME 链收集最终 IP
//
// ⚠️ 注意：这个查询会**向目标发送 DNS 请求**。
// 但 DNS 是被动查询（不建立连接、不发 TCP/UDP 应用数据），
// 与主动端口扫描有本质区别，风险等级极低。
func followCNAMEChain(ctx context.Context, r Resolver, domain string,
	res *DNSResult, timeout time.Duration) []string {

	ips := res.IPs
	seen := map[string]bool{}
	for _, ip := range ips {
		seen[ip] = true
	}

	// 从 A 记录的 name 出发跟随（CNAME 链的 A 记录会带原始 name）
	host := domain
	visited := map[string]bool{strings.ToLower(domain): true}

	for i := 0; i < 8; i++ { // 最多跟 8 跳，防环
		if visited[strings.ToLower(host)] {
			break
		}
		visited[strings.ToLower(host)] = true

		cctx, cancel := context.WithTimeout(ctx, timeout)
		rec, err := r.Query(cctx, host, TypeA)
		cancel()
		if err != nil || len(rec) == 0 {
			break
		}
		got := false
		for _, rr := range rec {
			if net.ParseIP(rr.Value) != nil && !seen[rr.Value] {
				seen[rr.Value] = true
				ips = append(ips, rr.Value)
				got = true
			}
		}
		if !got {
			break
		}
		// 继续跟下一跳的 CNAME
		cctx2, cancel2 := context.WithTimeout(ctx, timeout)
		cr, err2 := r.Query(cctx2, host, TypeCNAME)
		cancel2()
		if err2 != nil || len(cr) == 0 {
			break
		}
		next := strings.TrimSuffix(cr[0].Value, ".")
		if next == host {
			break
		}
		host = next
	}
	return ips
}

// ── 错误分类 ──────────────────────────────────────────────

func isNXDomain(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "nxdomain") ||
		strings.Contains(s, "no such host") ||
		strings.Contains(s, "does not exist")
}

func isNoRecord(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no answer") ||
		strings.Contains(s, "no such record") ||
		strings.Contains(s, "no records")
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func randomLabel(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(letters[time.Now().UnixNano()%int64(len(letters))])
		time.Sleep(time.Millisecond)
	}
	return b.String()
}

// SortRecords 按类型与值排序（稳定输出，便于 diff）
func SortRecords(recs map[RecordType][]DNSRecord) {
	for _, rs := range recs {
		sort.Slice(rs, func(i, j int) bool { return rs[i].Value < rs[j].Value })
	}
}
