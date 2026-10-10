// Package ipinfo 实现 IP 归属信息查询。
//
// 数据源（两个，互补而非互斥）：
//
//	① ipwho.is   —— 主源
//	   ✅ HTTPS、免费 10000 次/月、字段最全
//	   （经纬度、时区、国家/省/城市、ASN、ISP、域名）
//	   ❌ 无 hosting / proxy / mobile 标识
//
//	② ip-api.com —— 补充源
//	   ✅ 提供 hosting（数据中心）/ proxy（代理）/ mobile（移动网络）标识
//	      —— 这是判断"这是不是 CDN 边缘节点 / 云主机"的关键字段
//	   ❌ 免费层仅 HTTP（明文），故仅用于补字段，不作为可信数据主源
//
// ⭐ 为什么必须做本地缓存：
//
//	ipwho.is 免费层 10000 次/月。渗透测试中同一批 IP 常被反复查询
//	（扫一次、复核一次、写报告一次）。实测批量接口不支持
//	（GET /ipwho.is/1.1.1.1,8.8.8.8 返回 404），必须逐个查。
//	查过的 IP 存下来，重复查询零消耗。
package ipinfo

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Info 单个 IP 的归属信息
type Info struct {
	IP          string  `json:"ip"`
	Valid       bool    `json:"valid"`
	Version     int     `json:"version"` // 4 或 6
	Type        string  `json:"type,omitempty"`
	Continent   string  `json:"continent,omitempty"`
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`

	// 网络归属
	ASN    uint   `json:"asn,omitempty"`
	ASOrg  string `json:"as_org,omitempty"`
	Org    string `json:"org,omitempty"`
	ISP    string `json:"isp,omitempty"`
	Domain string `json:"domain,omitempty"`

	// ⭐ rDNS（PTR）反查到的全部主机名
	Hostnames []string `json:"hostnames,omitempty"`
	// HasPTR 是否配置了 PTR 记录
	//
	// ⚠️ **无 PTR 是常态而非异常** —— 实测（2026-10-05）6 个目标里 2 个没有 PTR
	//   （百度云 180.76.198.225、github 20.205.243.166 均为 NXDOMAIN）。
	//   这不代表"该 IP 上没有其他域"，只代表"没人给它写过反向记录"。
	HasPTR bool `json:"has_ptr"`
	// RDNSErr rDNS 查询错误（与"无 PTR"是不同的事）
	RDNSErr string `json:"rdns_error,omitempty"`

	// ⭐ 来自 ip-api.com 的补充字段（判断云/代理/CDN）
	Hosting bool `json:"hosting,omitempty"` // 数据中心 / 云主机
	Proxy   bool `json:"proxy,omitempty"`   // 代理 / VPN
	Mobile  bool `json:"mobile,omitempty"`  // 移动网络

	// Flags 推导出的类型标签（见 Classify）
	Flags []string `json:"flags,omitempty"`
	// FlagSources 每个标签的来源（org=关键字匹配 高可靠 / ip-api.com 较低可靠）
	FlagSources []string `json:"flag_sources,omitempty"`

	// ⭐ 来源追踪：哪些字段来自哪个源，便于判断可信度
	SourcePrimary   string `json:"source_primary"`             // "ipwho.is" / "cache" / "invalid"
	SourceSecondary string `json:"source_secondary,omitempty"` // "ip-api.com"

	// Cached 是否来自本地缓存
	Cached bool `json:"cached,omitempty"`
	// Err 查询过程中的错误（部分成功时非空）
	Err string `json:"error,omitempty"`
}

// Classify 推导类型标签。
//
// ⭐ 渗透测试中最有价值的问题不是"这在哪"，而是"这是不是 CDN / 云主机" ——
// 因为 CDN 边缘 IP 会让端口扫描结果失真（你以为扫的是源站，其实扫的是 CDN）。
//
// ⚠️ 上游标签的可靠性（实测 2026-10-04）：
//
//	ip-api.com 的 hosting / proxy 判定**存在误报**。
//	实测 114.114.114.114（114 公共 DNS，AS137702 中国电信江苏）
//	被 ip-api.com 标为 hosting=true **且 proxy=true** —— 但它显然不是代理出口。
//	推测是该 IP 属于 hosting 段又被探测到开放代理特征所致。
//
//	→ 所以：
//	  1. proxy 标签必须降权看待，不能直接当结论
//	  2. 工具应标出每个标签的来源，让使用者自行判断可信度
//	  3. CDN 判定用 org/isp 关键字（较可靠），proxy 判定用上游标签（较不可靠）
func (i *Info) Classify() {
	i.Flags = nil
	i.FlagSources = nil
	add := func(f, src string) {
		for _, x := range i.Flags {
			if x == f {
				return
			}
		}
		i.Flags = append(i.Flags, f)
		i.FlagSources = append(i.FlagSources, src)
	}

	// ⭐ 高可靠：org/isp 关键字匹配
	if isCDNOrg(i.ISP) || isCDNOrg(i.Org) || isCDNOrg(i.ASOrg) {
		add("cdn", "org")
	}
	if isCloudOrg(i.ISP) || isCloudOrg(i.Org) || isCloudOrg(i.ASOrg) {
		add("cloud", "org")
	}
	if i.CountryCode == "CN" {
		add("cn", "self")
	}

	// ⚠️ 较低可靠：ip-api.com 的上游标签
	if i.Hosting {
		add("hosting", "ip-api.com")
	}
	if i.Mobile {
		add("mobile", "ip-api.com")
	}
	if i.Proxy {
		// ⭐ 明确标注这是上游判定且可能误报
		add("proxy?", "ip-api.com")
	}
}

// isCDNOrg 通过 org/isp 名称判定 CDN
//
// ⚠️ 这是**关键字匹配**，会有误报与漏报：
//   - 漏报：CDN 厂商用自有 ASN 名，或用了没收录的名字
//   - 误报：某些 ISP 名字里含这些词但不是 CDN
//     → 所以只能作为"提示"，不能作为结论。真正的验证方式是
//     查该 IP 的 rDNS 与 BGP 归属，或对同一 Host 多次解析看是否轮换。
var cdnKeywords = []string{
	"cloudflare", "akamai", "fastly", "akamaitechnologies",
	"cdn", "content delivery", "edgecast", "limelight",
	"cachefly", "incapsula", "sucuri", "keycdn",
	"stackpath", "cdnetworks", "bunnycdn", "vercel",
	"netlify", "cloudfront", "aliyuncdn", "alikunlun",
	"qcloudcdn", "wangsu", "baidubce", "ucloudcdn",
	// 国内 CDN（实测：23.225.22.1 = AS40065 CNSERVERS LLC 未被识别）
	"cnservers", "cdnplus", "cdn20", "chinacache",
	"drcdn", "cdnwl", "qbox", "ksyuncdn", "wscdns",
}

func isCDNOrg(s string) bool {
	ls := strings.ToLower(s)
	if ls == "" {
		return false
	}
	for _, k := range cdnKeywords {
		if strings.Contains(ls, k) {
			return true
		}
	}
	return false
}

// cloudKeywords 云厂商关键字
var cloudKeywords = []string{
	"amazon", "aws", "google", "microsoft", "azure",
	"alibaba", "aliyun", "tencent", "qcloud", "huawei",
	"cloud", "digitalocean", "linode", "vultr", "ovh",
	"hetzner", "oracle", "ibm cloud", "ucloud",
}

func isCloudOrg(s string) bool {
	ls := strings.ToLower(s)
	if ls == "" {
		return false
	}
	for _, k := range cloudKeywords {
		if strings.Contains(ls, k) {
			return true
		}
	}
	return false
}

// Label 返回简短标签（用于表格显示）
func (i *Info) Label() string {
	if !i.Valid {
		return "invalid"
	}
	if len(i.Flags) > 0 {
		return strings.Join(i.Flags, "/")
	}
	return "-"
}

// Location 返回 "国家(代码) 城市" 形式的位置
func (i *Info) Location() string {
	if !i.Valid {
		return "-"
	}
	var b strings.Builder
	if i.Country != "" {
		b.WriteString(i.Country)
		if i.CountryCode != "" {
			b.WriteString("(" + i.CountryCode + ")")
		}
	} else if i.CountryCode != "" {
		b.WriteString(i.CountryCode)
	}
	if i.Region != "" {
		if b.Len() > 0 {
			b.WriteString(" ")
		}
		b.WriteString(i.Region)
	}
	if i.City != "" {
		if b.Len() > 0 {
			b.WriteString(" ")
		}
		b.WriteString(i.City)
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

// ── 数据源实现 ────────────────────────────────────────────

// Provider 归属查询数据源
type Provider interface {
	// Name 源名称
	Name() string
	// Lookup 查询单个 IP。无效 IP 应返回 Valid=false 的 Info 而非 error。
	Lookup(ip string) (*Info, error)
}

// ── 主源：ipwho.is ───────────────────────────────────────

type ipwhoisProvider struct {
	client  *http.Client
	baseURL string
}

func newIPWhoIS(client *http.Client) *ipwhoisProvider {
	return &ipwhoisProvider{client: client, baseURL: "https://ipwho.is/"}
}

func (p *ipwhoisProvider) Name() string { return "ipwho.is" }

// ipwhoIsResponse 是主源的响应结构（只声明用到的字段）
type ipwhoIsResponse struct {
	Success     bool    `json:"success"`
	Message     string  `json:"message"`
	IP          string  `json:"ip"`
	Type        string  `json:"type"` // "IPv4" / "IPv6"
	Continent   string  `json:"continent"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Timezone    struct {
		ID string `json:"id"`
	} `json:"timezone"`
	Connection struct {
		ASN    uint   `json:"asn"`
		Org    string `json:"org"`
		ISP    string `json:"isp"`
		Domain string `json:"domain"`
	} `json:"connection"`
}

func (p *ipwhoisProvider) Lookup(ip string) (*Info, error) {
	req, err := http.NewRequest(http.MethodGet, p.baseURL+ip, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wukan-ipinfo/0.1 (+https://github.com/wukan)")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ipwho.is 请求失败: %w", err)
	}
	defer resp.Body.Close()

	// ipwho.is 对无效 IP 返回 200 + success:false，也用 404
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return &Info{IP: ip, Valid: false, SourcePrimary: p.Name(),
			Err: "该 IP 无归属数据（可能为私有/保留地址）"}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ipwho.is 返回 %d", resp.StatusCode)
	}

	var r ipwhoIsResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("解析 ipwho.is 响应失败: %w", err)
	}
	if !r.Success {
		msg := r.Message
		if msg == "" {
			msg = "查询失败"
		}
		return &Info{IP: ip, Valid: false, SourcePrimary: p.Name(),
			Err: "ipwho.is: " + msg}, nil
	}

	info := &Info{
		IP:            ip,
		Valid:         true,
		Type:          r.Type,
		Continent:     r.Continent,
		Country:       r.Country,
		CountryCode:   strings.ToUpper(r.CountryCode),
		Region:        r.Region,
		City:          r.City,
		Latitude:      r.Latitude,
		Longitude:     r.Longitude,
		Timezone:      r.Timezone.ID,
		ASN:           r.Connection.ASN,
		ASOrg:         r.Connection.Org,
		Org:           r.Connection.Org,
		ISP:           r.Connection.ISP,
		Domain:        r.Connection.Domain,
		SourcePrimary: p.Name(),
	}
	if r.Type == "IPv6" {
		info.Version = 6
	} else {
		info.Version = 4
	}
	return info, nil
}

// ── 补充源：ip-api.com（只取云/代理/移动标识）────────────

type ipapiProvider struct {
	client  *http.Client
	baseURL string
}

func newIPApi(client *http.Client) *ipapiProvider {
	return &ipapiProvider{client: client, baseURL: "http://ip-api.com/json/"}
}

func (p *ipapiProvider) Name() string { return "ip-api.com" }

// 只请求需要的字段，减少响应体
const ipapiFields = "status,country,countryCode,regionName,city,isp,org,as,asname,hosting,proxy,mobile"

type ipapiResponse struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	RegionName  string `json:"regionName"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	AS          string `json:"as"`
	ASName      string `json:"asname"`
	Hosting     bool   `json:"hosting"`
	Proxy       bool   `json:"proxy"`
	Mobile      bool   `json:"mobile"`
}

// enrich 补充云/代理/移动标识，并填补主源缺失的字段。
//
// ⚠️ 传输是 HTTP（明文），所以只用于补充"非敏感的分类标识"
//
//	（hosting/proxy/mobile），不作为位置/归属的可信来源。
//	若主源已有值，**不覆盖**。
func (p *ipapiProvider) enrich(in *Info) error {
	url := p.baseURL + in.IP + "?fields=" + ipapiFields
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "wukan-ipinfo/0.1")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ip-api.com 返回 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return err
	}
	var r ipapiResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return err
	}
	if r.Status != "success" {
		msg := r.Message
		if msg == "" {
			msg = "查询失败"
		}
		return fmt.Errorf("ip-api.com: %s", msg)
	}

	// 分类标识（主源没有，直接填）
	in.Hosting = r.Hosting
	in.Proxy = r.Proxy
	in.Mobile = r.Mobile

	// 位置字段：仅在主源缺失时填补
	if in.Region == "" {
		in.Region = r.RegionName
	}
	if in.City == "" {
		in.City = r.City
	}
	if in.ASOrg == "" {
		in.ASOrg = r.ASName
	}
	return nil
}

// ── 缓存 ──────────────────────────────────────────────────

// Cache 是 IP 归属结果的本地缓存接口
type Cache interface {
	Get(ip string) (*Info, bool)
	Put(ip string, info *Info)
	Len() int
}

// ── 客户端 ────────────────────────────────────────────────

// Client 是归属查询客户端
type Client struct {
	primary   Provider
	secondary *ipapiProvider
	rdns      *RDNSResolver
	cache     Cache
	rateLimit time.Duration // 每个 IP 之间的最小间隔
	timeout   time.Duration

	mu      sync.Mutex
	lastReq time.Time
}

// Option 配置选项
type Option func(*Client)

// WithCache 启用缓存
func WithCache(c Cache) Option {
	return func(cl *Client) { cl.cache = c }
}

// WithRateLimit 设置请求间隔（防触发限流）
func WithRateLimit(d time.Duration) Option {
	return func(cl *Client) { cl.rateLimit = d }
}

// WithTimeout 设置 HTTP 超时
func WithTimeout(d time.Duration) Option {
	return func(cl *Client) { cl.timeout = d }
}

// WithRDNS 启用/禁用 rDNS（PTR）反查
//
// ⭐ 默认关闭，原因有三：
//  1. rDNS 是**额外的 DNS 查询**，会增加耗时与 DNS 负载
//  2. ⭐ **大部分 IP 没有 PTR** —— 实测（2026-10-05）6 个目标里 2 个是 NXDOMAIN
//     （百度云 180.76.198.225、github 20.205.243.166），对批量场景收益有限
//  3. PTR 是"当前状态"类信息（云主机重装、IP 转售都会变），
//     不适合像归属信息那样缓存 7 天
//
// 需要看"这台机器上还有什么"时再显式开启。
func WithRDNS(enable bool) Option {
	return func(cl *Client) {
		cl.rdns = nil
		if enable {
			cl.rdns = NewRDNSResolver(5 * time.Second)
		}
	}
}

// WithSecondary 启用/禁用补充源
func WithSecondary(enable bool) Option {
	return func(cl *Client) {
		cl.secondary = nil
		if enable {
			cl.secondary = newIPApi(cl.httpClient())
		}
	}
}

func (cl *Client) httpClient() *http.Client {
	t := cl.timeout
	if t <= 0 {
		t = 15 * time.Second
	}
	return &http.Client{Timeout: t}
}

// New 创建客户端
func New(opts ...Option) *Client {
	hc := &http.Client{Timeout: 15 * time.Second}
	c := &Client{
		primary:   newIPWhoIS(hc),
		timeout:   15 * time.Second,
		rateLimit: 120 * time.Millisecond, // 默认 8 req/s，保守
	}
	c.secondary = newIPApi(hc)
	// ⭐ rDNS 默认关闭（需 --rdns 显式开启，理由见 WithRDNS 的注释）
	c.rdns = nil
	for _, o := range opts {
		o(c)
	}
	return c
}

// wait 限流等待
func (cl *Client) wait() {
	if cl.rateLimit <= 0 {
		return
	}
	cl.mu.Lock()
	elapsed := time.Since(cl.lastReq)
	need := cl.rateLimit - elapsed
	if need > 0 {
		time.Sleep(need)
	}
	cl.lastReq = time.Now()
	cl.mu.Unlock()
}

// Lookup 查询单个 IP
func (cl *Client) Lookup(ip string) (*Info, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil, fmt.Errorf("IP 为空")
	}
	// 先做格式校验 —— 避免浪费配额
	if parsed := net.ParseIP(ip); parsed == nil {
		return &Info{IP: ip, Valid: false, SourcePrimary: "invalid",
			Err: "不是合法的 IP 地址"}, nil
	} else if parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() {
		return &Info{IP: ip, Valid: false, SourcePrimary: "invalid",
			Err: "私有/环回/链路本地地址，无公网归属信息"}, nil
	}

	// 缓存命中
	if cl.cache != nil {
		if v, ok := cl.cache.Get(ip); ok {
			c := *v
			c.Cached = true
			c.SourcePrimary = "cache"
			c.Classify()
			// ⭐⭐ 缓存命中时**仍要跑 rDNS**。
			//
			//   实测踩到的坑：缓存里存的是 `--rdns` 关闭时查的结果
			//   （无 PTR 字段），若这里直接 return，开了 --rdns 也查不到东西 ——
			//   表现是"参数没生效"而非"报错"，极难定位。
			//
			//   另一层理由：PTR 是「当前状态」类信息（云主机重装、IP 转售都会变），
			//   而归属缓存 TTL 是 7 天，所以 PTR 不适合进缓存，每次实时查。
			if cl.rdns != nil {
				if r := cl.rdns.Lookup(ip); r != nil {
					c.AddRDNS(r)
				}
			}
			return &c, nil
		}
	}

	cl.wait()
	info, err := cl.primary.Lookup(ip)
	if err != nil {
		return nil, err
	}

	// 补充云/代理标识
	if info.Valid && cl.secondary != nil {
		if err := cl.secondary.enrich(info); err != nil {
			// 补充源失败不影响主结论
			info.Err = "补充源失败: " + err.Error()
		} else {
			info.SourceSecondary = cl.secondary.Name()
		}
	}

	info.Classify()

	if cl.cache != nil && info.Valid {
		cl.cache.Put(ip, info)
	}

	// ⭐ rDNS 反查（默认关闭，需显式开启）
	//
	// 放在缓存写入之后 —— 因为 PTR 数据比归属信息变化更快
	//（云主机重装、IP 转售都会改 PTR），而缓存 TTL 是 7 天。
	// 所以每次都重新查 PTR，保证准确性。
	if cl.rdns != nil && info.Valid {
		if r := cl.rdns.Lookup(ip); r != nil {
			info.AddRDNS(r)
		}
	}
	return info, nil
}

// LookupMany 并发查询多个 IP
func (cl *Client) LookupMany(ips []string, workers int) []*Info {
	if workers < 1 {
		workers = 8
	}
	results := make([]*Info, len(ips))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for i, ip := range ips {
		wg.Add(1)
		go func(idx int, target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			info, err := cl.Lookup(target)
			if err != nil {
				info = &Info{IP: target, Valid: false,
					SourcePrimary: "error", Err: err.Error()}
			}
			results[idx] = info
		}(i, ip)
	}
	wg.Wait()
	return results
}
