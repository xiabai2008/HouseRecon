package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DoHResolver 是基于 DNS over HTTPS 的解析器。
//
// ⭐ 为什么默认用 DoH 而不是系统 resolver：
//
//  1. **可切换源**。实测（2026-10-04）：
//     Cloudflare DoH 在本环境 SSL 握手失败（UNEXPECTED_EOF），
//     而阿里 DoH 正常（0.1s）。系统 resolver 的上游不可控。
//     DoH 让"换源"变成改一个配置项。
//  2. **绕过本地污染与劫持**。国内运营商 DNS 可能返回改写结果。
//  3. **可并发**，不受本地 resolver 缓存与限速影响。
//
// ⚠️ 代价：DoH 端点知道你在查什么域名（隐私权衡）。
//
//	查敏感目标时应改用系统 resolver（-dns system）。
type DoHResolver struct {
	client  *http.Client
	baseURL string
	name    string
}

// NewDoHResolver 创建 DoH 解析器
func NewDoHResolver(name, baseURL string, timeout time.Duration) *DoHResolver {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &DoHResolver{
		client:  &http.Client{Timeout: timeout},
		baseURL: strings.TrimRight(baseURL, "/"),
		name:    name,
	}
}

// 内置 DoH 端点
const (
	DoHAlidns  = "https://dns.alidns.com/resolve" // 阿里（国内，实测最快）
	DoHCloudfl = "https://cloudflare-dns.com/dns-query"
	DoHGoogle  = "https://dns.google/resolve"
	DoHQuad9   = "https://dns.quad9.net:5053/dns-query"
	DoH360     = "https://doh.360.cn/dns-query"
	DoHDNSPod  = "https://doh.pub/dns-query"
)

// PredefinedDoH 返回预置 DoH 端点
func PredefinedDoH(name string) (*DoHResolver, bool) {
	switch strings.ToLower(name) {
	case "alidns", "ali", "default", "":
		// ⭐ 实测本环境可用且最快
		return NewDoHResolver("aliyun", DoHAlidns, 8*time.Second), true
	case "cloudflare", "cf":
		return NewDoHResolver("cloudflare", DoHCloudfl, 8*time.Second), true
	case "google", "g":
		return NewDoHResolver("google", DoHGoogle, 8*time.Second), true
	case "quad9":
		return NewDoHResolver("quad9", DoHQuad9, 8*time.Second), true
	case "360":
		return NewDoHResolver("360", DoH360, 8*time.Second), true
	case "dnspod", "tencent":
		return NewDoHResolver("dnspod", DoHDNSPod, 8*time.Second), true
	default:
		// 允许直接传 URL
		if strings.HasPrefix(name, "https://") {
			return NewDoHResolver("custom", name, 8*time.Second), true
		}
		return nil, false
	}
}

func (r *DoHResolver) Name() string { return "doh:" + r.name }

// dohResponse 是 DoH JSON 格式（RFC 8484 / Google 风格）
//
// ⚠️ 兼容性问题：DoH 服务的返回结构**不统一**（实测 2026-10-04）：
//
//	dns.alidns.com   → "Question": { "name": "...", "type": 1 }      ← 对象
//	cloudflare-dns   → "Question": [ { "name": "...", "type": 1 } ]  ← 数组
//
// 早期实现把 Question 固定声明为数组，导致阿里 DoH 全部 7 种记录类型
// 都报 "cannot unmarshal object into Go struct field Question"，
// DNS 段整体失效（而 RDAP 与 CT 正常，掩盖了问题）。
// → 用 QuestionField 自定义 UnmarshalJSON 兼容两种形态。
type dohResponse struct {
	Status   int           `json:"Status"` // 0=NOERROR 3=NXDOMAIN
	Question QuestionField `json:"Question"`
	Answer   []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  uint32 `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// QuestionField 兼容"对象 / 数组 / 缺省"三种形态
type QuestionField []struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

// UnmarshalJSON 同时兼容对象与数组两种形态
func (q *QuestionField) UnmarshalJSON(b []byte) error {
	t := skipJSONSpace(b)
	if len(t) == 0 || string(t) == "null" {
		*q = nil
		return nil
	}
	switch t[0] {
	case '[': // 数组形态（Cloudflare / Google / Quad9）
		var arr []struct {
			Name string `json:"name"`
			Type int    `json:"type"`
		}
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*q = arr
	case '{': // 对象形态（阿里 DoH）
		var obj struct {
			Name string `json:"name"`
			Type int    `json:"type"`
		}
		if err := json.Unmarshal(b, &obj); err != nil {
			return err
		}
		*q = []struct {
			Name string `json:"name"`
			Type int    `json:"type"`
		}{{Name: obj.Name, Type: obj.Type}}
	default:
		// 不认识的形态：Question 不是必需字段，忽略而不报错
		*q = nil
	}
	return nil
}

func skipJSONSpace(b []byte) []byte {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return b[i:]
}

func (r *DoHResolver) Query(ctx context.Context, name string, t RecordType) ([]DNSRecord, error) {
	qtype, ok := recordTypeToDNS(t)
	if !ok {
		return nil, fmt.Errorf("不支持的记录类型: %s", t)
	}
	url := fmt.Sprintf("%s?name=%s&type=%d", r.baseURL, name, qtype)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", "wukan-recon/0.1")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH 返回 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}

	var d dohResponse
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("解析 DoH 响应失败: %w", err)
	}

	// ⭐ RFC 8484 状态码
	switch d.Status {
	case 3:
		return nil, fmt.Errorf("NXDOMAIN: %s 不存在", name)
	case 0:
		// 继续
	default:
		return nil, fmt.Errorf("DoH Status=%d", d.Status)
	}

	if len(d.Answer) == 0 {
		return nil, fmt.Errorf("无记录")
	}

	var out []DNSRecord
	for _, a := range d.Answer {
		rec := DNSRecord{Type: t, Name: strings.TrimSuffix(a.Name, "."), TTL: a.TTL}
		rec.Value = normalizeAnswer(t, a.Data)
		if rec.Value == "" {
			continue
		}
		out = append(out, rec)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("无记录")
	}
	return out, nil
}

func recordTypeToDNS(t RecordType) (int, bool) {
	switch t {
	case TypeA:
		return 1, true
	case TypeNS:
		return 2, true
	case TypeCNAME:
		return 5, true
	case TypeSOA:
		return 6, true
	case TypeMX:
		return 15, true
	case TypeTXT:
		return 16, true
	case TypeAAAA:
		return 28, true
	case TypePTR:
		return 12, true
	default:
		return 0, false
	}
}

// normalizeAnswer 规范化 DoH 答案
//
// 各种 DoH 服务返回格式不一致：
//   - MX:  "10 mx.example.com."
//   - SOA: "ns1.example.com. hostmaster.example.com. 1 3600 600 86400 300"
//   - TXT: '"v=spf1 include:_spf.google.com ~all"'
//   - CNAME: "target.example.com."
func normalizeAnswer(t RecordType, data string) string {
	s := strings.TrimSpace(data)
	switch t {
	case TypeMX:
		// "10 mx.example.com." → "10 mx.example.com"
		fields := strings.Fields(s)
		if len(fields) == 2 {
			return fields[0] + " " + strings.TrimSuffix(fields[1], ".")
		}
		return strings.TrimSuffix(s, ".")
	case TypeSOA:
		// 只保留 MNAME（第一个），RNAME 等信息量大且用不上
		fields := strings.Fields(s)
		if len(fields) >= 1 {
			return strings.TrimSuffix(fields[0], ".")
		}
		return strings.TrimSuffix(s, ".")
	case TypeTXT:
		// 去掉外层引号
		s = strings.Trim(s, `"`)
		// DoH 可能把长 TXT 分段返回（如 "part1" "part2"）
		// 这里保持原样，由调用方决定如何处理
		return s
	case TypeCNAME, TypeNS, TypePTR:
		return strings.TrimSuffix(s, ".")
	case TypeA, TypeAAAA:
		return s
	default:
		return strings.TrimSuffix(s, ".")
	}
}

// ── 系统 resolver ─────────────────────────────────────────

// SystemResolver 使用 Go 标准库的本地解析器
type SystemResolver struct {
	client *net.Resolver
}

// NewSystemResolver 创建系统解析器
func NewSystemResolver() *SystemResolver {
	return &SystemResolver{client: net.DefaultResolver}
}

func (r *SystemResolver) Name() string { return "system" }

// Query 通过系统解析器查询
//
// ⚠️ Go 的 net.Resolver 只导出 LookupHost / LookupIP / LookupNetIP / LookupNetAddr，
//
//	**不提供按记录类型的查询**（小写 lookup 是内部方法）。
//	所以系统解析器只能覆盖 A/AAAA，其余类型返回"不支持"。
//	→ 需要完整记录类型时用 DoH（-dns alidns）。
func (r *SystemResolver) Query(ctx context.Context, name string, t RecordType) ([]DNSRecord, error) {
	switch t {
	case TypeA, TypeAAAA:
	default:
		return nil, fmt.Errorf("系统解析器不支持 %s 类型查询（请用 -dns alidns 走 DoH）", t)
	}

	addrs, err := r.client.LookupHost(ctx, name)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("无记录")
	}

	// 按请求类型过滤：LookupHost 返回 A + AAAA 混合结果
	wanted4 := t == TypeA
	var out []DNSRecord
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		is4 := ip.To4() != nil
		if is4 != wanted4 {
			continue
		}
		out = append(out, DNSRecord{Type: t, Name: name, Value: a})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("无 %s 记录", t)
	}
	return out, nil
}
