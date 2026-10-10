package ipinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── rDNS（PTR）反查 ───────────────────────────────────────
//
// ⭐ 这个能力的价值：把「IP」变成「IP + 域名」，
// 从而发现**同源资产** —— 共享主机 / 云主机 / CDN 回源上跑着的其他域。
//
// ⚠️ 三个必须如实告知的局限：
//
//  1. **大部分 IP 没有 PTR 记录**。
//     实测（2026-10-05）：6 个目标里只有 4 个有 PTR，
//     百度云（180.76.198.225）与 github（20.205.243.166）都是 NXDOMAIN。
//     → 所以「无 PTR」是**常态**，不是异常，更不代表"这个 IP 没有其他域"。
//
//  2. **PTR 可能是泛用主机名**（如 ecs-1-2-3-4.compute.hwclouds-dns.com），
//     只能说明"这是某台华为云主机"，**推不出上面跑了什么站点**。
//
//  3. **PTR 与正向解析不必一致**。
//     反向写 example.com 的 IP 也可以不配对应的 A 记录。
//
// → 所以 rDNS 是**线索来源**（能查到什么就报什么），
//   真正的同源资产发现要靠 reverseiplookup（IP → 托管的所有域名）。

// RDNSResult 单个 IP 的 rDNS 反查结果
type RDNSResult struct {
	IP string `json:"ip"`
	// Hostnames PTR 记录返回的域名（可能多个）
	Hostnames []string `json:"hostnames,omitempty"`
	// HasPTR 是否配置了 PTR
	HasPTR bool `json:"has_ptr"`
	// Source 查询源（system / doh）
	Source string `json:"source,omitempty"`
	// Err 错误（注意：**无 PTR 不是错误**，此时 Err 为空且 HasPTR=false）
	Err string `json:"error,omitempty"`
}

// Classified 主机名分类结果
type RDNSClassified struct {
	// Generic 泛用主机名（ecs-xxx / ec2-xxx / host-xxx 等），信息量低
	Generic []string `json:"generic,omitempty"`
	// Specific 具体域名，可能是真实的站点
	Specific []string `json:"specific,omitempty"`
}

// Classify 把 PTR 主机名分成"泛用"与"具体"
//
// ⭐ 为什么要分：
//
//	ecs-119-3-70-188.compute.hwclouds-dns.com  → 只是"某台华为云主机"，推不出站点
//	cdn-01.example.com                        → 可能是真实的子域
//
// 把两者混在一起报会让人误以为"发现了站点"。
func (r *RDNSResult) Classify() RDNSClassified {
	var c RDNSClassified
	for _, h := range r.Hostnames {
		if isGenericHostname(h) != "" {
			c.Generic = append(c.Generic, h)
		} else {
			c.Specific = append(c.Specific, h)
		}
	}
	return c
}

// genericPatterns 泛用主机名的标志
//
// ⭐⚠️ 设计教训（实测 2026-10-05）：
//
//	初版把 "cdn-" / "vip-" / "lb-" 放进列表，结果
//	`cdn-01.example.com` 这种**明显是具体子域**的名字被误判为泛用。
//
//	教训：**关键字匹配必须区分「厂商的默认 PTR 格式」与「真实站点名」**。
//	前者有很特征化的形态（含云厂商域名后缀 + 数字 IP 段），
//	后者虽然是具体域名，但形态千变万化。
//
//	所以改为**两段判定**：
//	  ① 命中云厂商的**域名后缀**（compute./amazonaws./cloudapp./hwclouds…）
//	     → 必然是云主机默认 PTR
//	  ② 形态是「前缀-数字-数字-…」（如 ecs-1-2-3-4 / ec2-1-2-3-4）
//	     且**总标签数少**（≤4）→ 大概率是默认 PTR
//	  ③ 其他一律视为具体域名（宁可误报为"具体"，也不要把真站点说成泛用）
var cloudSuffixes = []string{
	"compute", "compute-1", "amazonaws.com", "cloudapp.azure.com",
	"hwclouds-dns.com", "internal", "local", "localhost",
	"novalocal", "googleusercontent", "aliyun.com", "tencentcloud.com",
	"myqcloud.com", "ucloud.cn", "lxd", "docker.internal",
}

func isGenericHostname(h string) string {
	l := strings.ToLower(strings.TrimSuffix(h, "."))
	if l == "" {
		return ""
	}

	// ① 云厂商默认 PTR 域名后缀 —— 特征最可靠
	for _, suf := range cloudSuffixes {
		if strings.Contains(l, suf) {
			return suf
		}
	}

	labels := strings.Split(l, ".")
	// ② 「前缀-数字段-数字段」形态且标签数少 → 云主机默认命名
	//    例：ecs-119-3-70-188.compute.hwclouds-dns.com（命中①）
	//        1-2-3-4.static.example.com（标签少 + 数字形态）
	//    排除：cdn-01.example.com（只有一段数字，不构成 IP 形态）
	if len(labels) <= 4 {
		first := labels[0]
		if hasIPPattern(first) {
			return "ip-like-hostname"
		}
	}
	return ""
}

// hasIPPattern 判断形如 "1-2-3-4" / "ecs-1-2-3-4" / "ip-10-0-1-5" 的形态
//
// ⭐ 关键：要求**至少 3 段数字**才算 IP 形态。
// 这样 "cdn-01"（1 段）、"web-01"（1 段）就不会被误判，
// 而 "1-2-3-4"、"119-3-70-188" 会正确命中。
func hasIPPattern(s string) bool {
	parts := strings.Split(s, "-")
	nums := 0
	for _, p := range parts {
		if p == "" {
			continue
		}
		allDigits := true
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			nums++
		} else if !isAlphaWord(p) {
			return false // 出现非字母非数字的字符，不像主机名
		}
	}
	// ⭐ 至少 3 段数字才算 IP 形态
	return nums >= 3
}

func isAlphaWord(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return len(s) > 0
}

// genericMarker 返回泛用类型标记（用于报告展示）
func genericMarker(h string) string { return isGenericHostname(h) }

// ── 查询实现 ──────────────────────────────────────────────

// RDNSResolver 是 rDNS 反查器
//
// ⭐ 双源策略（实测互补性很强）：
//
//	system  系统 resolver —— 能查国内云主机的泛用 PTR
//	        （ecs-119-3-70-188.compute.hwclouds-dns.com）
//	doh     阿里 DoH PTR —— 0.1-0.2s，格式统一，可查 IPv6
//
// 两者都查，取并集。
type RDNSResolver struct {
	client *http.Client
	dohURL string
	system *net.Resolver

	mu    sync.Mutex
	stats map[string]int
}

// NewRDNSResolver 创建反查器
func NewRDNSResolver(timeout time.Duration) *RDNSResolver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &RDNSResolver{
		client: &http.Client{Timeout: timeout},
		dohURL: "https://dns.alidns.com/resolve",
		system: net.DefaultResolver,
		stats:  map[string]int{},
	}
}

// Lookup 反查单个 IP
func (r *RDNSResolver) Lookup(ipStr string) *RDNSResult {
	res := &RDNSResult{IP: ipStr, Source: "system+doh"}
	if net.ParseIP(ipStr) == nil {
		res.Err = "不是合法的 IP 地址"
		return res
	}

	seen := map[string]bool{}
	var all []string

	// ① 系统 resolver
	if names, err := r.lookupSystem(ipStr); err == nil {
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				all = append(all, n)
			}
		}
		r.count("system_ok")
	} else {
		r.count("system_fail")
	}

	// ② DoH PTR
	if names, err := r.lookupDoH(ipStr); err == nil {
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				all = append(all, n)
			}
		}
		r.count("doh_ok")
	} else {
		r.count("doh_fail")
	}

	sort.Strings(all)
	res.Hostnames = all
	// ⭐ 注意：HasPTR=false 且 Err="" 是**正常情况**（该 IP 没配 PTR），
	//   不能与"查询失败"混淆
	res.HasPTR = len(all) > 0
	return res
}

// lookupSystem 用系统 resolver 查 PTR
func (r *RDNSResolver) lookupSystem(ipStr string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	names, err := r.system.LookupAddr(ctx, ipStr)
	if err != nil {
		return nil, err
	}
	// ⭐ 必须过滤 ARPA 域：某些 resolver 会把查询名本身
	//   （如 188.70.3.119.in-addr.arpa）当 PTR 值返回 ——
	//   实测 114.114.114.114 与 119.3.70.188 都出现了这种情况。
	//   两个源（system/DoH）都要过滤，不能只改一个。
	out := make([]string, 0, len(names))
	for _, n := range names {
		if h := cleanPTRValue(n); h != "" {
			out = append(out, h)
		}
	}
	return out, nil
}

// cleanPTRValue 清洗 PTR 值：去结尾点、过滤 ARPA 反查域
//
// ⭐ 顺序很关键：必须**先去点再判断后缀**，否则过滤失效
//
//	（DoH 返回的值带结尾点，如 "8.8.8.8.in-addr.arpa."）。
func cleanPTRValue(raw string) string {
	n := strings.TrimSuffix(strings.TrimSpace(raw), ".")
	if n == "" {
		return ""
	}
	// ARPA 反查域是查询名，不是主机名
	if strings.HasSuffix(n, ".in-addr.arpa") || strings.HasSuffix(n, ".ip6.arpa") {
		return ""
	}
	// 纯数字形态的"主机名"（如 "188-70-3-119"）也不是有效 PTR
	if isNumericHost(n) {
		return ""
	}
	return n
}

func isNumericHost(h string) bool {
	hasDigit := false
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '.' || c == '-':
			// 允许
		default:
			return false
		}
	}
	return hasDigit
}

// lookupDoH 用 DoH 查 PTR（RFC 8484 type=12）
func (r *RDNSResolver) lookupDoH(ipStr string) ([]string, error) {
	arpa, err := reverseName(ipStr)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s?name=%s&type=12", r.dohURL, arpa)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", "wukan-ipinfo/0.1")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH 返回 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}

	var d struct {
		Status int `json:"Status"`
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, err
	}
	// ⭐ Status=3 (NXDOMAIN) 说明"该 IP 没有 PTR 记录"——
	//   这不是错误，而是一个有效结论。
	if d.Status == 3 {
		return nil, nil
	}
	if d.Status != 0 && len(d.Answer) == 0 {
		return nil, fmt.Errorf("DoH Status=%d", d.Status)
	}

	var out []string
	for _, a := range d.Answer {
		// ⭐ 两个源统一用 cleanPTRValue 清洗
		if h := cleanPTRValue(a.Data); h != "" {
			out = append(out, h)
		}
	}
	return out, nil
}

func (r *RDNSResolver) count(k string) {
	r.mu.Lock()
	r.stats[k]++
	r.mu.Unlock()
}

// Stats 返回查询统计（便于诊断"为什么没查到"）
func (r *RDNSResolver) Stats() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int, len(r.stats))
	for k, v := range r.stats {
		out[k] = v
	}
	return out
}

// ── reverseName 生成反向解析域名 ────────────────────────────

// reverseName 把 IP 转成 in-addr.arpa / ip6.arpa 域名
//
// ⭐ IPv6 的格式容易写错：要用 **32 个 nibble 逐个反序**，
//
//	  不是按 4 个十六进制分组反序。
//
//		IPv4  8.8.8.8            → 8.8.8.8.in-addr.arpa
//		IPv6  2400:3200::1        → 1.0.0.0.….0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.3.0.0.4.2.ip6.arpa
//		                            （32 个 nibble，各自反序）
func reverseName(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("不是合法的 IP: %q", ipStr)
	}

	if v4 := ip.To4(); v4 != nil {
		// IPv4：4 段各自反序
		parts := strings.Split(ipStr, ".")
		if len(parts) != 4 {
			return "", fmt.Errorf("IPv4 格式错误: %q", ipStr)
		}
		return fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa",
			parts[3], parts[2], parts[1], parts[0]), nil
	}

	// IPv6：展开成 32 个 hex digit，逐个反序
	ipv6 := ip.To16()
	if ipv6 == nil {
		return "", fmt.Errorf("无法解析为 IPv6: %q", ipStr)
	}
	// 去掉 IPv4-mapped 前缀（::ffff:a.b.c.d）
	if v4 := ipv6.To4(); v4 != nil {
		parts := strings.Split(v4.String(), ".")
		return fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa",
			parts[3], parts[2], parts[1], parts[0]), nil
	}

	const hexDigits = "0123456789abcdef"
	var rev []byte
	for i := len(ipv6) - 1; i >= 0; i-- {
		b := ipv6[i]
		rev = append(rev, hexDigits[b&0x0f])
		rev = append(rev, '.')
		rev = append(rev, hexDigits[b>>4])
		rev = append(rev, '.')
	}
	// 末尾已有一个点，再补 ip6.arpa
	return string(rev) + "ip6.arpa", nil
}

// ── 集成到 Info ────────────────────────────────────────────

// ReverseHosts rDNS 返回的域名（便于在表格里显示）
func (i *Info) ReverseHosts() string {
	if len(i.Hostnames) == 0 {
		return ""
	}
	return strings.Join(i.Hostnames, ", ")
}

// AddRDNS 把 rDNS 结果并入 Info
func (i *Info) AddRDNS(r *RDNSResult) {
	if r == nil {
		return
	}
	i.Hostnames = r.Hostnames
	i.HasPTR = r.HasPTR
	if r.Err != "" {
		i.RDNSErr = r.Err
	}
	// ⭐ 顺序很关键：必须**先 Classify 再加标签**。
	//
	//   Classify() 开头是 `i.Flags = nil`（无条件重置），
	//   若先加标签再 Classify，标签会被立刻冲掉 ——
	//   实测症状：PTR 明明含具体域名，Flags 却是空的。
	i.Classify()
	if c := r.Classify(); len(c.Specific) > 0 {
		i.Flags = appendUnique(i.Flags, "rdns-named")
	}
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
