// Package httpprobe 实现 HTTP 探针与多源指纹采集。
//
// ⭐ 这个包存在的意义：为「指纹冲突矩阵」提供**相互独立**的指纹来源。
// 现有工具（httpx 等）只做"把多个来源的结果拼在一起输出"，
// 没有任何工具去**校验这些来源之间是否自相矛盾**。
// 而矛盾本身就是最有价值的发现 —— 详见 conflict.go。
package httpprobe

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProbeResult 单个 URL 的探测结果
type ProbeResult struct {
	URL  string `json:"url"`
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port"`

	// HostHeaderUsed 实际发送的 Host 头（URL 用 IP 时这里记域名）
	HostHeaderUsed string `json:"host_header_used,omitempty"`
	// Cached ⭐ 该结果是否来自本地缓存
	Cached bool `json:"cached,omitempty"`
	// CacheAge 缓存结果的年龄
	CacheAge string `json:"cache_age,omitempty"`
	// RetriedWith 结果来自降级重试时的重试方式（空 = 首次即成功）
	//
	//	"no-follow" 跳过重定向后成功
	//	"http"      https 失败后改试 http 成功
	//
	// ⭐ 必须如实标注：报告里 URL 显示的是 https，但数据可能实际来自
	//   http 回退 —— 不标注会让人误以为 HTTPS 正常工作。
	RetriedWith string `json:"retried_with,omitempty"`

	// ⭐ 以下是**相互独立**的指纹来源，冲突检测的输入
	// --- 来源 1：HTTP 响应头 ---
	Server    string `json:"server,omitempty"`
	PoweredBy string `json:"powered_by,omitempty"`
	Via       string `json:"via,omitempty"`
	Location  string `json:"location,omitempty"`
	// AltSvc Alt-Svc 响应头：声明可用的替代服务（如 h3=":443"）
	//
	// ⭐ 与 QUIC 探活交叉验证：声明了 h3 但 UDP/443 无响应 = 配置漂移线索
	AltSvc     string   `json:"alt_svc,omitempty"`
	SetCookies []string `json:"set_cookies,omitempty"`
	// JARM JARM TLS 指纹（62 字符；GrabJARM 开启时填充；P1-3）
	JARM string `json:"jarm,omitempty"`
	// H2Settings HTTP/2 SETTINGS 指纹（"settings|window_update"；P1-3）
	H2Settings   string            `json:"h2_settings,omitempty"`
	CFHeaders    map[string]string `json:"cf_headers,omitempty"`  // Cloudflare 特征
	CDNHeaders   map[string]string `json:"cdn_headers,omitempty"` // 其他 CDN 特征
	SecurityHdrs map[string]string `json:"security_headers,omitempty"`

	// --- 来源 2：TLS 层 ---
	TLSVersion string   `json:"tls_version,omitempty"`
	TLSCipher  string   `json:"tls_cipher,omitempty"`
	ALPN       string   `json:"alpn,omitempty"`
	CertIssuer string   `json:"cert_issuer,omitempty"`
	CertSANs   []string `json:"cert_sans,omitempty"`
	CertExpire string   `json:"cert_expire,omitempty"`

	// --- 来源 3：favicon 哈希（确定性）---
	// ⭐ 计算方式必须与 Shodan 一致才能比对：
	//   MurmurHash3 x86_32，Base64 输入**按 RFC 2045 每 76 字符换行**，
	//   输出为**有符号整数**。调研报告指出中文教程普遍抄错这点，
	//   导致自建工具算出的 hash 永远对不上 Shodan。
	FaviconMurmur int64 `json:"favicon_murmur,omitempty"`
	// FaviconProductName favicon 命中的产品名（表里有才填）
	//
	// ⚠️ 字段名带 Name 后缀：因为 ProbeResult 已有 FaviconProduct() 方法，
	//    Go 不允许字段与方法同名。
	FaviconProductName string `json:"favicon_product,omitempty"`
	// FaviconCategory 产品类别（数据库/CDN/代码托管…）
	//
	// ⭐ 这个字段让 favicon 结论能与**开放端口**交叉印证：
	//   favicon 说"Redis（数据库）"+ 6379 开放 → 两者一致，可信度高
	//   favicon 说"Redis（数据库）"+ 只开 80     → 矛盾，需人工核实
	FaviconCategory string `json:"favicon_category,omitempty"`
	FaviconMD5      string `json:"favicon_md5,omitempty"`
	FaviconLen      int    `json:"favicon_len,omitempty"`

	// --- 来源 4：正文特征 ---
	Title        string   `json:"title,omitempty"`
	BodyKeywords []string `json:"body_keywords,omitempty"`
	BodyLen      int      `json:"body_len,omitempty"`
	// Decompressed 是否成功解压（Go Transport 自动处理 gzip）
	Decompressed bool `json:"decompressed,omitempty"`
	// DecompressWarn 解压异常提示（非空时正文特征不可信）
	DecompressWarn string `json:"decompress_warn,omitempty"`
	// BodyTruncated 正文是否因超过上限被截断
	BodyTruncated bool `json:"body_truncated,omitempty"`

	// --- 来源 5：TLS 证书与主机名的关系 ---
	CertMatchesHost bool `json:"cert_matches_host,omitempty"`

	// StatusCode HTTP 状态码
	StatusCode int `json:"status_code,omitempty"`
	// FinalURL 跟随重定向后的最终 URL
	FinalURL string `json:"final_url,omitempty"`
	// RTT 往返时延
	RTT time.Duration `json:"-"`
	// Err 错误
	Err string `json:"error,omitempty"`
}

// Config 探测配置
type Config struct {
	// Timeout 超时
	Timeout time.Duration
	// Concurrency 并发
	Concurrency int
	// Insecure 跳过证书校验（内网自签证书常见）
	Insecure bool
	// FollowRedirect 跟随重定向
	FollowRedirect bool
	// RetryFallback 探测失败时是否降级重试（见 retryFallback）
	//
	// ⭐ 实测动机（2026-10-05）：4 个子域是「重定向到 github.com 后超时」，
	//   单次探测只能拿到错误（只能靠负缓存避免重复代价，但结论仍是缺失的）。
	//   降级链（每步只在失败时发生，最多 2 次额外请求）：
	//     ① 跳过重定向重试 —— 重定向链超时时，原始响应（301/302）本身
	//        就有完整指纹价值（Server / Location / Cookie）
	//     ② https 失败改试 http —— 子域可能只跑 HTTP（443 关闭或被过滤）
	//   代价：失败目标最多多花 2 个请求；全部失败后走负缓存（10 分钟），
	//   重复运行不会反复付这个代价。
	RetryFallback bool
	// MaxBodySize 正文最大读取字节（避免大页面）
	MaxBodySize int
	// GrabTLS 抓 TLS 细节
	GrabTLS bool
	// GrabFavicon 抓 favicon（每个 URL 多一次请求）
	GrabFavicon bool
	// GrabH2 HTTP/2 SETTINGS 指纹（每个 https 目标多一次连接，默认开）
	GrabH2 bool
	// GrabJARM JARM TLS 指纹（每个 https 目标多 10 次连接，默认关 —— 重）
	GrabJARM bool
	// GrabCert 单独抓证书（不依赖 HTTP 请求成功）
	GrabCert bool
	// UserAgent UA
	UserAgent string
	// Cache 指纹结果缓存（nil = 不缓存）
	Cache TechCache
	// HostHeader HTTP 请求里用的 Host 头（覆盖 URL 里的主机）
	//
	// ⭐ 为什么需要：recon 阶段用 **IP:端口** 构造 URL（这样才能逐个探测
	//   CDN 边缘节点），但 Host 头必须送**域名** ——
	//   否则 CDN 找不到匹配的站点配置，会返回默认站点，
	//   产出「看起来正常但完全错误」的指纹。
	HostHeader string
}

// DefaultConfig 默认配置
func DefaultConfig() Config {
	return Config{
		Timeout:        8 * time.Second,
		Concurrency:    16,
		Insecure:       true,
		FollowRedirect: true,
		// ⭐ 失败时降级重试（跳过重定向 / http 回退）
		RetryFallback: true,
		MaxBodySize:   512 * 1024,
		GrabTLS:       true,
		GrabFavicon:   true,
		// ⭐ HTTP/2 SETTINGS 指纹：1 个连接，默认开（P1-3）
		GrabH2: true,
		// ⭐ JARM：10 个连接，默认关（重；用 --jarm / --tech-jarm 显式开启）
		GrabJARM: false,
		GrabCert: true,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
			"(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
	}
}

// Prober HTTP 探针
type Prober struct {
	cfg    Config
	client *http.Client
	// clientNoFollow 跳过重定向的备用客户端（仅 RetryFallback 开启时创建）
	//
	// ⭐ 与主客户端**共享 transport** —— 否则两个连接池会让连接复用失效、
	//   白白多付 TLS 握手成本。
	clientNoFollow *http.Client
}

// noFollowRedirect 不跟随重定向（返回第一跳响应）
func noFollowRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// New 创建探针
func New(cfg Config) *Prober {
	if cfg.MaxBodySize <= 0 {
		cfg.MaxBodySize = 512 * 1024
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure},
		// ⭐ 保持默认连接复用：禁用复用会导致 banner 抓不到；
		//   而"复用导致指纹不可靠"（拿到上次连接的 TLS 状态）的问题
		//   靠独立的 TLS 抓取路径解决，不靠禁用复用。
		MaxIdleConns:        100,
		IdleConnTimeout:     10 * time.Second,
		TLSHandshakeTimeout: cfg.Timeout,
	}

	cl := &http.Client{Timeout: cfg.Timeout, Transport: tr}
	var clNoFollow *http.Client
	if !cfg.FollowRedirect {
		// 主客户端本来就不跟随重定向 → 无需备用客户端
		cl.CheckRedirect = noFollowRedirect
	} else if cfg.RetryFallback {
		clNoFollow = &http.Client{
			Timeout:       cfg.Timeout,
			Transport:     tr,
			CheckRedirect: noFollowRedirect,
		}
	}
	return &Prober{cfg: cfg, client: cl, clientNoFollow: clNoFollow}
}

// ProbeURL 探测单个 URL
//
// ⭐ 缓存命中时直接返回，零网络请求。
//
//	缓存键含 HostHeader —— 同一个 IP:80 上不同 Host 头是不同的站点，
//	用 URL 做键会导致结果串味。
//
// ⭐ 探测失败时的降级重试见 retryFallback（由 Config.RetryFallback 控制）。
func (p *Prober) ProbeURL(rawURL string) *ProbeResult {
	// 解析失败：不重试、不写负缓存（负缓存只针对真实网络失败）
	u, err := parseURL(rawURL)
	if err != nil {
		r := newProbeResult(rawURL)
		r.Err = err.Error()
		return r
	}

	// ⭐ 缓存查询（键含采集能力开关 —— 见 MakeCacheKey 注释）
	var cacheKey string
	if p.cfg.Cache != nil {
		cacheKey = MakeCacheKey(rawURL, p.cfg.HostHeader,
			p.cfg.FollowRedirect, p.cfg.UserAgent,
			CapabilityKey(p.cfg.GrabFavicon, p.cfg.GrabH2, p.cfg.GrabJARM))
		if cached, ok := p.cfg.Cache.Get(cacheKey); ok {
			// ⭐ 用原 URL 覆盖（缓存里的 URL 可能是旧格式）
			cached.URL = rawURL
			return cached
		}
	}

	r := p.probeOnce(rawURL, p.client)
	if r.Err != "" && p.cfg.RetryFallback {
		r = p.retryFallback(rawURL, r)
	}

	// ⭐ P1-3 附加指纹（仅成功的 https 探测才跑）：
	//   - 失败目标不可达 → 多打 10+ 连接纯属浪费
	//   - 降级到 http 的结果 → TLS 指纹对象已不存在
	//   - SNI 用 HostHeader（CDN/vhost 场景 IP 直连必须送域名，
	//     否则指纹反映的是默认站点 —— 项目的核心教训）
	if r.Err == "" && u.scheme() == "https" && r.RetriedWith != "http" {
		sni := u.hostname()
		if p.cfg.HostHeader != "" {
			sni = p.cfg.HostHeader
		}
		if p.cfg.GrabH2 && r.H2Settings == "" {
			r.H2Settings = H2Fingerprint(u.hostname(), u.port(), sni, capTimeout(p.cfg.Timeout, 5*time.Second))
		}
		if p.cfg.GrabJARM && r.JARM == "" {
			r.JARM = JARMFingerprint(u.hostname(), u.port(), sni, jarmProbeBudget(p.cfg.Timeout))
		}
	}

	// ⭐ 写缓存（失败结果由 Cache.Put 内部过滤）
	if p.cfg.Cache != nil {
		p.cfg.Cache.Put(cacheKey, r)
	}
	return r
}

// capTimeout 取 min(t, cap)
func capTimeout(t, cap time.Duration) time.Duration {
	if t <= 0 || t > cap {
		return cap
	}
	return t
}

// jarmProbeBudget JARM 的单探测超时预算
//
// ⭐ 交叉验证实测（2026-10-11，example.com/Cloudflare）：
//
//	TLS_1.1 探测耗时 **5.68s**（边缘对老版本握手有延迟策略），
//	4s 上限会把这类服务器误判成全零 —— 而参考实现用 20s。
//	JARM 是"忠实对齐生态指纹库"的采集，宁可慢不可偏：
//	预算 = max(cfg.Timeout, 10s)，上限 20s（与参考实现一致）。
func jarmProbeBudget(cfgTimeout time.Duration) time.Duration {
	budget := cfgTimeout
	if budget < 10*time.Second {
		budget = 10 * time.Second
	}
	if budget > 20*time.Second {
		budget = 20 * time.Second
	}
	return budget
}

// retryFallback 探测失败后的降级重试（最多 2 次额外请求）
//
// ⭐ 顺序有讲究（为什么不是反过来）：
//
//	① 跳过重定向（同 URL、同 scheme）—— 对"重定向链路跳转超时"最有效：
//	   原始主机是活的，只是跳转目标慢/不可达，不跟随即可立刻拿到
//	   301/302 响应（Server / Location / Cookie 全部有效）
//	② https → http —— 覆盖"子域只跑 HTTP"的情况（443 关闭或被过滤），
//	   此时跳过重定向重试仍会连接失败，必须换 scheme
//
// 两步都失败时返回**首次**的结果 —— 它的错误信息才是主 URL 的真实失败原因。
func (p *Prober) retryFallback(rawURL string, first *ProbeResult) *ProbeResult {
	// 回退 1：跳过重定向（仅当主客户端会跟随重定向时才有意义）
	if p.clientNoFollow != nil {
		if r := p.probeOnce(rawURL, p.clientNoFollow); r.Err == "" {
			r.RetriedWith = "no-follow"
			return r
		}
	}
	// 回退 2：https 失败 → 改试 http（同主机、同端口）
	if strings.HasPrefix(rawURL, "https://") {
		httpURL := "http://" + strings.TrimPrefix(rawURL, "https://")
		if r := p.probeOnce(httpURL, p.client); r.Err == "" {
			// ⭐ 身份保留原 URL（子域不变）；"数据实际来自 http"这件事
			//   由 RetriedWith 如实标注，FinalURL 记录实际地址
			r.URL = rawURL
			r.RetriedWith = "http"
			return r
		}
	}
	return first
}

// RetryLabel 返回降级重试的展示标签（空 = 未重试）
func (r *ProbeResult) RetryLabel() string {
	switch r.RetriedWith {
	case "no-follow":
		return "跳过重定向"
	case "http":
		return "http 回退"
	}
	return ""
}

// newProbeResult 创建初始结果（含必须初始化的 map 字段）
func newProbeResult(rawURL string) *ProbeResult {
	return &ProbeResult{URL: rawURL, CFHeaders: map[string]string{},
		CDNHeaders: map[string]string{}, SecurityHdrs: map[string]string{}}
}

// probeOnce 单次探测（不做缓存、不做降级重试）
func (p *Prober) probeOnce(rawURL string, cl *http.Client) *ProbeResult {
	r := newProbeResult(rawURL)
	u, err := parseURL(rawURL)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	r.Port = u.port()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	req.Header.Set("User-Agent", p.cfg.UserAgent)
	req.Header.Set("Accept", "*/*")
	// ⭐⭐ 不要手动设 Accept-Encoding: identity！
	//
	//   原本这么写是为了"避免压缩导致正文特征抓不到"，但适得其反：
	//   一旦手动设置了 Accept-Encoding，Go 的 Transport 就**关闭自动解压**
	//   （它的职责是"自己加 gzip 头 + 自己解 gzip"），
	//   而不礼貌的 CDN 会忽略 identity 继续返回 gzip ——
	//   结果读到的是二进制乱码。
	//
	//   实测症状（2026-10-05 gitee.com）：
	//     body_len = 524288（正好撞上 512KB 上限）→ 明显是没解压的数据
	//     关键词匹配到 "GitLab" → 但 gitee.com 页面里根本没有这字符串
	//
	//   正确做法：交给 Go 默认行为（自动 gzip + 自动解压），
	//   再按 resp.Uncompressed 确认解压成功。
	// ⭐ Host 头覆盖：URL 用 IP 时，靠它送正确的域名
	if p.cfg.HostHeader != "" {
		req.Host = p.cfg.HostHeader
	}

	start := time.Now()
	resp, err := cl.Do(req)
	r.RTT = time.Since(start)
	if err != nil {
		r.Err = err.Error()
		// ⭐ 即使 HTTP 失败，若端口是 TLS 的仍可抓证书
		if p.cfg.GrabCert {
			p.grabCertOnly(u, r)
		}
		return r
	}
	defer resp.Body.Close()

	r.StatusCode = resp.StatusCode
	r.FinalURL = resp.Request.URL.String()
	// ⭐ 记录实际使用的 Host 头（供证据追溯与冲突检测判读）
	if p.cfg.HostHeader != "" {
		r.HostHeaderUsed = p.cfg.HostHeader
	}
	if host, _, e := net.SplitHostPort(resp.Request.URL.Host); e == nil {
		r.IP = host
	} else {
		r.IP = resp.Request.URL.Host
	}

	// ⭐ 逐个提取响应头 —— 这些是**相互独立**的指纹来源
	for k, v := range resp.Header {
		lk := strings.ToLower(k)
		val := strings.Join(v, "; ")
		switch lk {
		case "server":
			r.Server = val
		case "x-powered-by":
			r.PoweredBy = val
		case "via":
			r.Via = val
		case "location":
			r.Location = val
		case "alt-svc":
			// ⭐ 替代服务声明（h3/quic 等），供与 QUIC 探活结果交叉验证
			r.AltSvc = val
		case "set-cookie":
			r.SetCookies = append(r.SetCookies, v...)
		case "cf-ray", "cf-cache-status", "cf-cache-id":
			r.CFHeaders[k] = val
		case "x-amz-cf-id", "x-amz-cf-pop":
			r.CDNHeaders[k] = val
		case "x-cache", "x-served-by", "x-fastly-request-id", "x-akamai-transformed",
			"x-sucuri-id", "x-cdn", "x-qcloud-log-pop":
			r.CDNHeaders[k] = val
		case "content-security-policy", "x-frame-options", "strict-transport-security",
			"x-content-type-options", "referrer-policy", "x-xss-protection":
			r.SecurityHdrs[k] = val
		}
	}

	// TLS 层细节
	if resp.TLS != nil {
		r.TLSVersion = tlsVersionName(resp.TLS.Version)
		r.ALPN = resp.TLS.NegotiatedProtocol
		r.TLSCipher = tlsCipherName(resp.TLS.CipherSuite)
		if len(resp.TLS.PeerCertificates) > 0 {
			c := resp.TLS.PeerCertificates[0]
			r.CertIssuer = c.Issuer.CommonName
			r.CertSANs = append(r.CertSANs, c.DNSNames...)
			r.CertExpire = c.NotAfter.Format("2006-01-02")
			// ⭐ 证书 SAN 是否覆盖当前主机 —— 这是独立的一致性信号
			r.CertMatchesHost = certCoversHost(c.DNSNames, u.hostname())
		}
	}

	// 正文
	// ⭐ 读完后确认解压成功（Uncompressed=true 表示 Go 已自动解压）
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(p.cfg.MaxBodySize)))
	if resp.Uncompressed {
		r.Decompressed = true
	} else if resp.Header.Get("Content-Encoding") != "" {
		// Content-Encoding 非空但 Go 没解压 → 内容不可信，不做关键词匹配
		r.DecompressWarn = "响应带 " + resp.Header.Get("Content-Encoding") +
			" 编码但未能解压，正文特征可能不准确"
	}
	if readErr != nil && len(body) == 0 {
		r.Err = "读取正文失败: " + readErr.Error()
	}
	r.BodyLen = len(body)
	// ⭐ 截断提示：页面超过上限时，尾部特征（往往才是框架标记）会丢失
	if len(body) >= p.cfg.MaxBodySize {
		r.BodyTruncated = true
		r.DecompressWarn = strings.TrimSpace(r.DecompressWarn +
			fmt.Sprintf("；正文超过 %d KB 上限已截断，尾部特征可能丢失",
				p.cfg.MaxBodySize/1024))
	}
	r.Title = extractTitle(string(body))
	// ⭐ 截断的正文不做关键词匹配 —— 在不完整内容里匹配必然产生误判
	//   （实测：gitee.com 页面 800KB+，截断到 512KB 后
	//     在二进制/片段里误匹配出 "GitLab"）
	if !r.BodyTruncated {
		r.BodyKeywords = extractKeywords(string(body))
	}

	// favicon（独立请求，因为多数站点不在 HTML 里给完整路径）
	if p.cfg.GrabFavicon {
		p.grabFavicon(u, r)
	}

	return r
}

// grabFavicon 抓取并计算 favicon 哈希
func (p *Prober) grabFavicon(u *urlInfo, r *ProbeResult) {
	favURL := u.scheme() + "://" + u.host() + "/favicon.ico"
	req, err := http.NewRequest("GET", favURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", p.cfg.UserAgent)
	if p.cfg.HostHeader != "" {
		req.Host = p.cfg.HostHeader
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil || len(data) == 0 {
		return
	}
	r.FaviconMurmur = ShodanFaviconHash(data)
	r.FaviconLen = len(data)
	// ⭐ 顺手解析出产品与类别（表里有才填）。
	//   类别让结论能与开放端口交叉印证：
	//   favicon 说"Redis（数据库）" + 6379 开放 → 两者印证，可信度高
	if n, c, ok := (&ProbeResult{FaviconMurmur: r.FaviconMurmur}).ProductInfo(); ok {
		r.FaviconProductName = n
		r.FaviconCategory = c
	}
	sum := md5.Sum(data)
	r.FaviconMD5 = hex.EncodeToString(sum[:])
}

// grabCertOnly 只抓证书（HTTP 请求失败时的兜底）
func (p *Prober) grabCertOnly(u *urlInfo, r *ProbeResult) {
	addr := net.JoinHostPort(u.hostname(), strconv.Itoa(u.port()))
	// ⭐ SNI 用域名（IP 访问时若用 IP 做 SNI，CDN 不会返回正确证书）
	sni := u.hostname()
	if p.cfg.HostHeader != "" {
		sni = p.cfg.HostHeader
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: p.cfg.Timeout}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, ServerName: sni})
	if err != nil {
		return
	}
	defer conn.Close()
	st := conn.ConnectionState()
	r.TLSVersion = tlsVersionName(st.Version)
	r.ALPN = st.NegotiatedProtocol
	r.TLSCipher = tlsCipherName(st.CipherSuite)
	if len(st.PeerCertificates) > 0 {
		c := st.PeerCertificates[0]
		r.CertIssuer = c.Issuer.CommonName
		r.CertSANs = append(r.CertSANs, c.DNSNames...)
		r.CertExpire = c.NotAfter.Format("2006-01-02")
		r.CertMatchesHost = certCoversHost(c.DNSNames, u.hostname())
		r.StatusCode = -1 // 标记：TCP 通但 HTTP 失败
	}
}

// ── favicon 哈希（Shodan 兼容）────────────────────────────────

// ShodanFaviconHash 计算 Shodan 兼容的 favicon 哈希
//
// ⭐ 实现要点（都是踩过的坑，调研报告 §第八章坑 5 有详细说明）：
//
//  1. MurmurHash3 **x86_32**（不是 x64_128，不是 crc32）
//  2. 输入先做 **Base64 编码**
//  3. Base64 结果**按 RFC 2045 每 76 字符换行**（多数实现直接漏掉这步）
//  4. 输出转为**有符号 32 位整数**（不是无符号！）
//
// 少任何一步，算出的 hash 就永远对不上 Shodan。
func ShodanFaviconHash(data []byte) int64 {
	// 1) Base64 编码
	encoded := base64.StdEncoding.EncodeToString(data)

	// 2) ⭐ 按 RFC 2045 每 76 字符插入换行
	//    MIME 的标准行长是 76，Shodan 的实现遵循这一点
	var sb strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		sb.WriteString(encoded[i:end])
		sb.WriteByte('\n')
	}
	mimeFormatted := sb.String()

	// 3) MurmurHash3 x86_32
	h := murmur3x86_32([]byte(mimeFormatted), 0)

	// 4) ⭐ 转有符号整数
	return int64(int32(h))
}

// murmur3x86_32 实现 MurmurHash3 x86_32
//
// 标准实现（Austin Appleby 的算法），Go 里没有标准库版本。
func murmur3x86_32(data []byte, seed uint32) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	h1 := seed

	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		j := i * 4
		k1 := uint32(data[j]) | uint32(data[j+1])<<8 |
			uint32(data[j+2])<<16 | uint32(data[j+3])<<24
		k1 *= c1
		k1 = rotl32(k1, 15)
		k1 *= c2
		h1 ^= k1
		h1 = rotl32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}

	// 尾部
	var k1 uint32
	tail := data[nblocks*4:]
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = rotl32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}

	// 收尾
	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return h1
}

func rotl32(x uint32, r uint8) uint32 {
	return (x << r) | (x >> (32 - r))
}

// ── 并发探测 ──────────────────────────────────────────────

// ProbeURLs 并发探测多个 URL
func (p *Prober) ProbeURLs(urls []string, onProgress func(done, total int, r *ProbeResult)) []*ProbeResult {
	results := make([]*ProbeResult, len(urls))
	workers := p.cfg.Concurrency
	if workers < 1 {
		workers = 1
	}
	if workers > len(urls) {
		workers = len(urls)
	}

	jobs := make(chan int, len(urls))
	var wg sync.WaitGroup
	done := 0
	var mu sync.Mutex

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				results[idx] = p.ProbeURL(urls[idx])
				mu.Lock()
				done++
				d := done
				mu.Unlock()
				if onProgress != nil {
					onProgress(d, len(urls), results[idx])
				}
			}
		}()
	}
	for i := range urls {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	return results
}

// ── 辅助 ─────────────────────────────────────────────────

// urlInfo 轻量 URL 解析（避免引入 net/url 的字段耦合）
type urlInfo struct {
	schemeStr string
	hostStr   string
	portNum   int
	pathStr   string
}

func parseURL(raw string) (*urlInfo, error) {
	u := &urlInfo{schemeStr: "http", portNum: 80, pathStr: "/"}
	rest := raw
	if strings.HasPrefix(rest, "https://") {
		u.schemeStr = "https"
		u.portNum = 443
		rest = rest[8:]
	} else if strings.HasPrefix(rest, "http://") {
		rest = rest[7:]
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		u.pathStr = rest[i:]
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		hostPart := rest[:i]
		portPart := rest[i+1:]
		n, err := strconv.Atoi(portPart)
		if err != nil {
			return nil, fmt.Errorf("端口号非法: %q", portPart)
		}
		u.hostStr = hostPart
		u.portNum = n
	} else {
		u.hostStr = rest
	}
	if u.hostStr == "" {
		return nil, fmt.Errorf("URL 缺少主机名: %q", raw)
	}
	return u, nil
}

func (u *urlInfo) String() string {
	return fmt.Sprintf("%s://%s%s", u.schemeStr, u.host(), u.pathStr)
}

func (u *urlInfo) host() string {
	// 默认端口不显示
	if (u.schemeStr == "http" && u.portNum == 80) ||
		(u.schemeStr == "https" && u.portNum == 443) {
		return u.hostStr
	}
	return net.JoinHostPort(u.hostStr, strconv.Itoa(u.portNum))
}

func (u *urlInfo) hostname() string { return u.hostStr }

func (u *urlInfo) scheme() string { return u.schemeStr }

func (u *urlInfo) port() int { return u.portNum }

func certCoversHost(dnsNames []string, host string) bool {
	host = strings.ToLower(host)
	for _, n := range dnsNames {
		n = strings.ToLower(n)
		if n == host {
			return true
		}
		if strings.HasPrefix(n, "*.") {
			suffix := n[1:] // 保留前导点
			if strings.HasSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case 0x0300:
		return "SSL 3.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

var cipherNames = map[uint16]string{
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0xc02b: "ECDHE-ECDSA-AES128-GCM-SHA256",
	0xc02f: "ECDHE-RSA-AES128-GCM-SHA256",
	0xc030: "ECDHE-RSA-AES256-GCM-SHA384",
	0xc013: "ECDHE-RSA-AES128-SHA",
	0xc014: "ECDHE-RSA-AES256-SHA",
	0x009c: "AES128-GCM-SHA256",
	0x009d: "AES256-GCM-SHA384",
}

func tlsCipherName(id uint16) string {
	if n, ok := cipherNames[id]; ok {
		return n
	}
	return fmt.Sprintf("0x%04x", id)
}

var titleRe = struct{ open, close string }{}

// extractTitle 提取 HTML 标题
func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	start += 6
	if gt := strings.IndexByte(body[start:], '>'); gt >= 0 {
		start += gt + 1
	}
	end := strings.Index(lower[start:], "</title>")
	if end < 0 {
		if len(body)-start > 120 {
			return sanitizeText(body[start : start+120])
		}
		return ""
	}
	return sanitizeText(body[start : start+end])
}

// bodyKeywordPatterns 正文特征关键词（用于识别 CMS/框架）
var bodyKeywordPatterns = map[string][]string{
	"WordPress":  {"wp-content", "wp-includes", "wordpress"},
	"Drupal":     {"drupal", "sites/all"},
	"Joomla":     {"joomla", "com_content"},
	"Discuz":     {"discuz", "uc_server"},
	"PHPMyAdmin": {"phpmyadmin", "pma_"},
	"ThinkPHP":   {"thinkphp", "public/index.php"},
	"Laravel":    {"laravel_session", "csrf-token"},
	"Django":     {"csrfmiddlewaretoken", "__admin_media_prefix__"},
	"Flask":      {"werkzeug", "flask"},
	"ASP.NET":    {"asp.net", "aspnet_version"},
	"React":      {"react", "__next_data__"},
	"Vue":        {"vue", "__vue__"},
	"jQuery":     {"jquery", "jquery-"},
	"Bootstrap":  {"bootstrap", "navbar-expand"},
	"VuePress":   {"vuepress", "__vuepress"},
	"Grafana":    {"grafana", "grafanaBootData"},
	"Kibana":     {"kibana", "kbn-version"},
	"GitLab":     {"gitlab", "gon.gitlab_url"},
	"Harbor":     {"harbor", "harbor-signin"},
	"MinIO":      {"minio", "minio console"},
	"Prometheus": {"prometheus", "prometheus_bearertoken"},
}

// extractKeywords 提取正文特征关键词
func extractKeywords(body string) []string {
	if len(body) > 200*1024 {
		body = body[:200*1024]
	}
	lower := strings.ToLower(body)
	var out []string
	seen := map[string]bool{}
	for tech, pats := range bodyKeywordPatterns {
		for _, p := range pats {
			if strings.Contains(lower, strings.ToLower(p)) {
				if !seen[tech] {
					seen[tech] = true
					out = append(out, tech)
				}
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func sanitizeText(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= 120 {
			break
		}
		if r < 32 || r == 127 {
			b.WriteByte(' ')
		} else {
			b.WriteRune(r)
		}
		n++
	}
	return strings.TrimSpace(b.String())
}
