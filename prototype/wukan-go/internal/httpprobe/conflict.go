package httpprobe

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// ConflictType 冲突类型
type ConflictType string

const (
	// ConflictFaviconVsServer favicon 判定与 HTTP 头矛盾
	ConflictFaviconVsServer ConflictType = "favicon_vs_server"
	// ConflictCDNLeak CDN 声称存在但源站特征泄露
	ConflictCDNLeak ConflictType = "cdn_leak"
	// ConflictVersionVersion Server 头声明的版本与 TLS 特征矛盾
	ConflictVersionVersion ConflictType = "version_version"
	// ConflictTechVsTitle 正文技术栈特征与标题矛盾
	ConflictTechVsTitle ConflictType = "tech_vs_title"
	// ConflictCertMismatch 证书 SAN 不覆盖访问的主机名
	ConflictCertMismatch ConflictType = "cert_mismatch"
	// ConflictWAFEvasion 安全头缺失但声称有防护
	ConflictSecurityGap ConflictType = "security_gap"
	// ConflictCookieFlag 会话 Cookie 缺 Secure/HttpOnly
	ConflictCookieFlag ConflictType = "cookie_flags"
	// ConflictTLSWeakTLS 版本过旧
	ConflictTLSWeak ConflictType = "tls_weak"
	// ConflictServerHide CDN 存在但 Server 头被完全隐藏（本身不冲突，只作信息）
	ConflictNone ConflictType = ""
)

// Conflict 一处指纹冲突
type Conflict struct {
	Type     ConflictType `json:"type"`
	Severity string       `json:"severity"` // high / medium / low / info
	Title    string       `json:"title"`
	Detail   string       `json:"detail"`
	// Sources 冲突涉及的各来源及其说法
	Sources []ConflictSource `json:"sources"`
	// Implication 这个矛盾意味着什么（可行动的判读）
	Implication string `json:"implication,omitempty"`
}

// ConflictSource 冲突中的一方
type ConflictSource struct {
	// Source 来源名（favicon / server-header / tls / body / cookie ...）
	Source string `json:"source"`
	// Says 该来源的说法
	Says string `json:"says"`
	// Trust 该来源的可信度（high/medium/low）
	Trust string `json:"trust"`
}

// ConflictReport 单个 URL 的冲突检测结果
type ConflictReport struct {
	URL       string     `json:"url"`
	Conflicts []Conflict `json:"conflicts,omitempty"`
	// Fingerprints 采集到的所有指纹（供人工核对）
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
	// Clean 是否无冲突
	Clean bool `json:"clean"`
}

// 高危（🔴）
const (
	SevHigh   = "high"
	SevMedium = "medium"
	SevLow    = "low"
	SevInfo   = "info"
)

// DetectConflicts ⭐⭐ 核心：交叉校验多个独立指纹来源，检测矛盾
//
// ⭐⭐ 这是本工具存在的核心理由 ——
//
//	现有工具（httpx / nuclei / Wappalyzer）全都只做"把多来源结果拼在一起输出"，
//	**没有任何工具校验这些来源之间是否自相矛盾**。
//	而矛盾本身就是最有价值的发现：
//	  · 矛盾说明某一方在说谎（被伪造、被代理、或被误识别）
//	  · 矛盾往往指向真实的安全问题（CDN 泄露、证书不匹配、Cookie 缺标志）
//
//	每条冲突都必须回答：**这意味着什么、能做什么**。
//
// 检测不到矛盾就明确说"无冲突"，不硬凑。
func DetectConflicts(p *ProbeResult) *ConflictReport {
	rep := &ConflictReport{
		URL:          p.URL,
		Clean:        true,
		Fingerprints: map[string]string{},
	}
	if p == nil {
		return rep
	}

	// 收集指纹（供人工核对）
	// ⭐ 判定本次访问用的是 IP 还是域名。
	//   用 IP 访问时，证书 SAN 不匹配是必然结果，不能报为冲突。
	accessedByIP := false
	if p.URL != "" {
		if h := hostOf(p.URL); net.ParseIP(h) != nil {
			accessedByIP = true
		}
	}

	addFP := func(k, v string) {
		if v != "" {
			rep.Fingerprints[k] = v
		}
	}
	if accessedByIP {
		addFP("访问形式", "IP 直连（证书 SAN 不匹配属正常）")
	}
	addFP("server", p.Server)
	addFP("powered-by", p.PoweredBy)
	addFP("via", p.Via)
	addFP("tls", p.TLSVersion)
	addFP("alpn", p.ALPN)
	addFP("cert-issuer", p.CertIssuer)
	addFP("title", p.Title)
	// ⭐ favicon 命中要连**类别**一起记录 ——
	//   "Redis（数据库）" 比 "Redis" 更有判断价值：
	//   它能���开放端口互相印证（6379 开着 → 印证）
	if n, c, ok := p.ProductInfo(); ok {
		if c != "" {
			addFP("favicon-product", n+"（"+c+"）")
		} else {
			addFP("favicon-product", n)
		}
	}
	if p.FaviconMurmur != 0 {
		addFP("favicon-murmur", strconv.FormatInt(p.FaviconMurmur, 10))
	}
	if len(p.BodyKeywords) > 0 {
		addFP("body-tech", strings.Join(p.BodyKeywords, ", "))
	}

	// ── 冲突 1：CDN 声称 vs 源站特征泄露 ──
	// ⭐ 最有实战价值的一条：CDN/反向代理会隐藏特征，但有些头会穿透
	//
	// ⭐⭐ 但必须先排除**自我矛盾**（实测发现的假阳性）：
	//
	//   aliyun.com 的 Server 头是 "Tengine"，而 Tengine 本身**就是**阿里云的
	//   服务器软件。我的 detectCDN 把它识别成"阿里云 CDN"，
	//   紧接着 detectSourceLeaks 又把同一个 Server 头当成"泄露的源站特征"——
	//   **同一行证据既当"声称"又当"反证"**，逻辑上自相矛盾。
	//
	//   正确做法：只有当 CDN 判定来自**独立于 Server 头**的信号
	//   （CF-RAY 之类的专用头、Set-Cookie 里的框架标记）时才报此冲突。
	if cdnName, independent := detectCDNIndependent(p); cdnName != "" && independent {
		leaks := detectSourceLeaks(p)
		if len(leaks) > 0 {
			rep.Conflicts = append(rep.Conflicts, Conflict{
				Type:     ConflictCDNLeak,
				Severity: SevMedium,
				Title:    fmt.Sprintf("声称使用 %s，但源站特征泄露", cdnName),
				Detail: fmt.Sprintf(
					"CDN/反向代理会隐藏源站特征，但以下响应头穿透了代理，"+
						"直接暴露了源站的实现：%s", strings.Join(leaks, "、")),
				Sources: []ConflictSource{
					{Source: "cdn-header", Says: cdnName, Trust: "high"},
					{Source: "leaked-header",
						Says: strings.Join(leaks, "、"), Trust: "high"},
				},
				Implication: "泄露的头会帮攻击者识别源站软件与版本，" +
					"进而匹配对应 CVE。修复方向：清理这些响应头或在代理层统一移除。",
			})
		}
	}

	// ── 冲突 2：Server 头 vs favicon 判定 ──
	// ⭐ favicon 误报是**结构性的**（只有几百字节，不同应用共用图标必然碰撞），
	//   但这不代表可以无视它 —— 冲突本身就是需要人工核的信号。
	if favProduct := p.FaviconProduct(); favProduct != "" {
		if serverProduct := serverProductOf(p.Server); serverProduct != "" {
			if !faviconCompatibleWith(favProduct, serverProduct) {
				rep.Conflicts = append(rep.Conflicts, Conflict{
					Type:     ConflictFaviconVsServer,
					Severity: SevLow,
					Title: fmt.Sprintf("favicon 判定为 %s，但 Server 头显示 %s",
						favProduct, serverProduct),
					Detail: "两个独立来源给出不一致的应用判定。" +
						"favicon 哈希**是确定性哈希**（零学习成分），" +
						"且图标只有几百字节，不同应用共用同一图标必然碰撞 —— " +
						"所以 favicon 侧误报率天然较高。",
					// ⭐ 附上类别，读者才能自行判断是否真的矛盾
					Sources: []ConflictSource{
						{Source: "favicon", Says: favProduct, Trust: "low"},
						{Source: "server-header", Says: serverProduct, Trust: "medium"},
					},
					Implication: "不能仅凭 favicon 断定技术栈。" +
						"以 Server 头 + 正文特征为准，favicon 仅作辅助参考。",
				})
			}
		}
	}

	// ── 冲突 3：证书 SAN 不覆盖主机名 ──
	// ⭐ 这是真实可利用的问题：说明证书配错了，或中间有代理在重签证书
	//
	// ⭐⭐ 但必须排除「用 IP 访问」造成的假阳性（实测 2026-10-05 发现的 bug）：
	//
	//   recon 阶段为了**逐个探测 CDN 边缘节点**，URL 构造为 `http://1.2.3.4:80`。
	//   此时证书 SAN 是 `*.example.com`，**IP 天然不匹配任何 SAN** ——
	//   但这不是证书配置错误，而是「用 IP 访问」这一形式的必然结果。
	//
	//   早期实现没排除这种情况，导致 3 个 CDN 节点全部误报
	//   "证书 SAN 未覆盖主机名"。→ 报冲突前先判断访问形式。
	if p.CertSANs != nil && !p.CertMatchesHost && !accessedByIP {
		rep.Conflicts = append(rep.Conflicts, Conflict{
			Type:     ConflictCertMismatch,
			Severity: SevMedium,
			Title:    "证书 SAN 未覆盖当前访问的主机名",
			Detail: fmt.Sprintf("证书的 SAN 列表（%s）不包含访问的主机名 %s。",
				truncateList(p.CertSANs, 4), hostOf(p.URL)),
			Sources: []ConflictSource{
				{Source: "tls-cert", Says: "SAN 不含访问主机", Trust: "high"},
				{Source: "dns/http", Says: "实际访问的主机名", Trust: "high"},
			},
			Implication: "浏览器会报证书错误；更危险的情况是" +
				"你在用一个配错证书的服务，或者中间有 TLS 终止代理在重签。",
		})
	}

	// ── 冲突 4：Server 声明的版本与 TLS 特征矛盾 ──
	if v := versionConflict(p); v != "" {
		rep.Conflicts = append(rep.Conflicts, Conflict{
			Type:     ConflictVersionVersion,
			Severity: SevLow,
			Title:    "Server 头声明与 TLS 特征不一致",
			Detail:   v,
			Sources: []ConflictSource{
				{Source: "server-header", Says: p.Server, Trust: "medium"},
				{Source: "tls", Says: p.TLSVersion + " / " + p.ALPN, Trust: "high"},
			},
			Implication: "可能存在：① 安全加固时伪造了 Server 头（常见）" +
				"② 中间代理改写了响应头 ③ 版本信息未同步更新。",
		})
	}

	// ── 冲突 5：正文技术栈与标题矛盾 ──
	if len(p.BodyKeywords) > 0 && p.Title != "" {
		if t := techTitleConflict(p); t != "" {
			rep.Conflicts = append(rep.Conflicts, Conflict{
				Type:     ConflictTechVsTitle,
				Severity: SevLow,
				Title:    "正文特征与页面标题暗示的技术栈不同",
				Detail:   t,
				Sources: []ConflictSource{
					{Source: "body", Says: strings.Join(p.BodyKeywords, ", "), Trust: "medium"},
					{Source: "title", Says: p.Title, Trust: "low"},
				},
				Implication: "常见于：① 标题是品牌名，看不出技术栈 " +
					"② 站点经过定制开发 ③ 使用了混合架构。需人工确认。",
			})
		}
	}

	// ── 安全项：Cookie 标志缺失 ──
	if bad := weakCookies(p.SetCookies); len(bad) > 0 {
		sev := SevMedium
		if p.CFHeaders != nil && len(p.CFHeaders) > 0 {
			// CDN 后面看不到真实的安全配置，置信度降级
			sev = SevLow
		}
		rep.Conflicts = append(rep.Conflicts, Conflict{
			Type:     ConflictCookieFlag,
			Severity: sev,
			Title:    "会话 Cookie 缺少安全标志",
			Detail:   fmt.Sprintf("以下 Cookie 缺少 Secure / HttpOnly：%s", strings.Join(bad, "、")),
			Sources: []ConflictSource{
				{Source: "set-cookie", Says: strings.Join(bad, "、"), Trust: "high"},
			},
			Implication: "缺少 HttpOnly → JS 可读取，会话可被 XSS 窃取；" +
				"缺少 Secure → 会话可被中间人劫持。",
		})
	}

	// ── 安全项：TLS 版本过旧 ──
	if p.TLSVersion == "TLS 1.0" || p.TLSVersion == "TLS 1.1" || p.TLSVersion == "SSL 3.0" {
		rep.Conflicts = append(rep.Conflicts, Conflict{
			Type:     ConflictTLSWeak,
			Severity: SevMedium,
			Title:    "使用了已弃用的 TLS 版本",
			Detail:   fmt.Sprintf("协商结果为 %s，该版本已被主流浏览器弃用。", p.TLSVersion),
			Sources: []ConflictSource{
				{Source: "tls", Says: p.TLSVersion, Trust: "high"},
			},
			Implication: "老版本 TLS 存在已知攻击面（如 BEAST、POODLE 相关问题），" +
				"且浏览器会直接拒绝连接。",
		})
	}

	// ── 安全项：声称有防护但缺安全头 ──
	if cdnName, independent := detectCDNIndependent(p); cdnName != "" &&
		independent && len(p.SecurityHdrs) == 0 {
		rep.Conflicts = append(rep.Conflicts, Conflict{
			Type:     ConflictSecurityGap,
			Severity: SevLow,
			Title:    "有 CDN/WAF 特征但完全缺少安全响应头",
			Detail: fmt.Sprintf("检测到 %s 的特征，但响应中没有 CSP / HSTS / "+
				"X-Frame-Options 等任何安全头。", cdnName),
			Sources: []ConflictSource{
				{Source: "cdn-header", Says: cdnName, Trust: "high"},
				{Source: "security-header", Says: "无安全头", Trust: "medium"},
			},
			Implication: "如果确实部署了 WAF/CDN，说明规则可能未覆盖全部路径，" +
				"或安全响应头需要单独配置。",
		})
	}

	rep.Clean = len(rep.Conflicts) == 0
	return rep
}

// ── 辅助：各来源的产品判定 ────────────────────────────────

// faviconProduct favicon 哈希对应的已知产品
type faviconProduct struct {
	name string
	// cat 所属类别（代码托管/数据库/CDN…），便于人工快速归类判断
	//
	// ⭐ 这个字段的价值：一个 favicon 命中到底意味着什么？
	//   "GitHub  → 代码托管类" 比 "GitHub" 更有判断价值
	//   "Apache  → Web 服务器" 与端口 80 开放是一致的（交叉印证）
	//   "Redis   → 数据库"   与 6379 开放是一致的（交叉印证）
	cat string
	// compatible 表示与该 Server 头是否兼容
	compatible func(serverProduct string) bool
}

// categoryOf 返回产品所属类别
//
// ⭐ 分类的价值：让 favicon 结论能与其它来源**交叉印证**。
//
//	favicon 说"数据库" + 端口 6379 开放 → 两者一致，可信度高
//	favicon 说"数据库" + 只有 80 开放       → 矛盾，需人工核实
func categoryOf(product string) string {
	switch product {
	// 代码托管 / CI
	case "GitHub", "GitLab", "Gitea", "Jenkins", "DEV Community":
		return "代码托管/CI"
	// 运维监控
	case "Grafana":
		return "运维监控"
	// 包管理
	case "PyPI", "RubyGems", "Packagist":
		return "包管理"
	// 数据库
	case "Redis", "PostgreSQL", "MongoDB":
		return "数据库"
	// Web 服务器
	case "Apache", "nginx":
		return "Web服务器"
	// CDN / 网络
	case "Cloudflare", "Traefik":
		return "CDN/代理"
	// 容器
	case "Docker":
		return "容器"
	// 语言与运行时
	case "PHP", "Python", "Node.js", "React":
		return "语言/框架"
	// CMS
	case "WordPress":
		return "CMS"
	// 浏览器
	case "Mozilla":
		return "浏览器"
	default:
		return ""
	}
}

// ProductInfo 返回 favicon 产品的完整信息（含类别）
func (p *ProbeResult) ProductInfo() (name, category string, ok bool) {
	if p.FaviconMurmur == 0 {
		return "", "", false
	}
	fp, ok := faviconHashTable[p.FaviconMurmur]
	if !ok {
		return "", "", false
	}
	return fp.name, fp.cat, true
}

func (f faviconProduct) compatibleWith(serverProduct string) bool {
	if f.compatible == nil {
		return true
	}
	return f.compatible(serverProduct)
}

// ⭐⭐ favicon 哈希表 —— **全部由本项目实测得出**
//
// 数据来源：2026-10-05 下载各站点 /favicon.ico，用本文件的
// ShodanFaviconHash 计算，逐条记录 md5 于 favicon_table.json 供核对。
//
// ⭐⚠️⚠️ 重要教训：**这些值绝不能凭记忆或"抄 Shodan 网页"得到**。
//
//	初版本表有 9 条凭印象填的哈希，实测后发现**几乎全是错的** ——
//	例如 Jenkins 实际是 1928290，初版写的是 1989169301（差了三个数量级）。
//	填错的哈希不会让程序崩溃，只会让 favicon 识别**静默失效**
//	（表现是"永远匹配不上"，没有报错，很难察觉）。
//	→ 扩充本表的唯一正确方法：下载 → 实测 → 写入 → 加测试固化。
//
// ⭐ 结构性局限（必须如实告知使用者）：
//
//	favicon 只有几百字节，**不同应用极可能共用同一图标**。
//	实测：grafana.com 与 grafana.net 的图标 md5 完全相同（cede20407ea3）。
//	→ 因此：
//	  1. 命中不等于确认技术栈，只能作为**线索**
//	  2. 未命中不代表不是该技术栈（本表仅覆盖常见产品）
//	  3. 与 Server 头等来源冲突时应**报告冲突**，而非二选一
//	     （见 faviconCompatibleWith）
//
// 覆盖率参考：本表 23 条，覆盖运维监控/CI/代码托管/数据库/
// Web服务器/CDN/语言与运行时等主流技术栈的**官网**图标。
// ⚠️ 注意：各家的**自建实例**（如自建 GitLab）可能换了图标而查不到。
var faviconHashTable = map[int64]faviconProduct{
	21411084:    {name: "Apache", cat: categoryOf("Apache")},
	-1261306053: {name: "Cloudflare", cat: categoryOf("Cloudflare")},
	1291258818:  {name: "DEV Community", cat: categoryOf("DEV Community")},
	1905926913:  {name: "Docker", cat: categoryOf("Docker")},
	1848946384:  {name: "GitHub", cat: categoryOf("GitHub")},
	1265477436:  {name: "GitLab", cat: categoryOf("GitLab")},
	-1668137428: {name: "Gitea", cat: categoryOf("Gitea")},
	1884118115:  {name: "Grafana", cat: categoryOf("Grafana")},
	1928290:     {name: "Jenkins", cat: categoryOf("Jenkins")},
	104027616:   {name: "MongoDB", cat: categoryOf("MongoDB")},
	-674472512:  {name: "Mozilla", cat: categoryOf("Mozilla")},
	864985040:   {name: "Node.js", cat: categoryOf("Node.js")},
	1783771745:  {name: "PHP", cat: categoryOf("PHP")},
	1535719526:  {name: "Packagist", cat: categoryOf("Packagist")},
	1261264597:  {name: "PostgreSQL", cat: categoryOf("PostgreSQL")},
	-1098357615: {name: "PyPI", cat: categoryOf("PyPI")},
	1195255730:  {name: "Python", cat: categoryOf("Python")},
	1349811561:  {name: "React", cat: categoryOf("React")},
	2111119328:  {name: "Redis", cat: categoryOf("Redis")},
	-825614509:  {name: "RubyGems", cat: categoryOf("RubyGems")},
	-706997553:  {name: "Traefik", cat: categoryOf("Traefik")},
	-2133341160: {name: "WordPress", cat: categoryOf("WordPress")},
	1117213901:  {name: "nginx", cat: categoryOf("nginx")},
}

// FaviconProduct 返回 favicon 哈希对应的产品名（空串表示未知）
func (p *ProbeResult) FaviconProduct() string {
	if p.FaviconMurmur == 0 {
		return ""
	}
	if fp, ok := faviconHashTable[p.FaviconMurmur]; ok {
		return fp.name
	}
	return ""
}

// FaviconProductInfo 返回 favicon 产品与兼容性判断
func (p *ProbeResult) FaviconProductInfo() faviconProduct {
	if p.FaviconMurmur == 0 {
		return faviconProduct{}
	}
	return faviconHashTable[p.FaviconMurmur]
}

// serverProductOf 从 Server 头推断产品
func serverProductOf(server string) string {
	l := strings.ToLower(server)
	switch {
	case strings.Contains(l, "nginx"):
		return "nginx"
	case strings.Contains(l, "apache"):
		return "Apache"
	case strings.Contains(l, "iis"):
		return "IIS"
	case strings.Contains(l, "caddy"):
		return "Caddy"
	case strings.Contains(l, "gunicorn"):
		return "Gunicorn"
	case strings.Contains(l, "openresty"):
		return "OpenResty"
	}
	return ""
}

// detectCDN 检测 CDN/WAF 特征
func detectCDN(p *ProbeResult) string {
	// Cloudflare：专用响应头最可靠
	if _, ok := p.CFHeaders["Cf-Ray"]; ok {
		return "Cloudflare"
	}
	if len(p.CFHeaders) > 0 {
		return "Cloudflare"
	}
	// 其他 CDN 的专用头
	cdnMarkers := map[string]string{
		"X-Amz-Cf-Id":                "CloudFront (AWS)",
		"X-Cache":                    "CDN (未识别厂商)",
		"X-Fastly-Request-Id":        "Fastly",
		"X-Sucuri-Id":                "Sucuri",
		"X-Cdn":                      "CDN (未识别厂商)",
		"X-Qcloud-Log-Pop":           "腾讯云 CDN",
		"X-Swift-Cachetime":          "OpenStack Swift",
		"X-Cache-Hits":               "CDN (未识别厂商)",
		"Akamai-Origin-Hop":          "Akamai",
		"X-Cache-Status-Ksyun":       "金山云 CDN",
		"X-Cache-Status-Tencent-Cos": "腾讯云 COS",
	}
	// Server 头里的 CDN 特征
	sl := strings.ToLower(p.Server)
	if strings.Contains(sl, "cloudflare") {
		return "Cloudflare"
	}
	if strings.Contains(sl, "tengine") {
		return "阿里云 (Tengine)"
	}
	if strings.Contains(sl, "qcloud") || strings.Contains(sl, "tencent") {
		return "腾讯云"
	}
	if strings.Contains(sl, "kunlun") || strings.Contains(sl, " Alibaba") {
		return "阿里云 CDN (Kunlun)"
	}

	// 收集 CDN 头
	all := map[string]string{}
	for k, v := range p.CDNHeaders {
		all[k] = v
	}
	for k, v := range respToMap(p) {
		all[k] = v
	}
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if name, ok := cdnMarkers[k]; ok {
			return name
		}
	}
	return ""
}

// respToMap 提取 CDN 相关头（从已解析的集合）
func respToMap(p *ProbeResult) map[string]string {
	out := map[string]string{}
	for k, v := range p.CDNHeaders {
		out[k] = v
	}
	return out
}

// ⭐ CDN 检测结果
type cdnDetect struct {
	Name string
	// Independent 该判定是否来自**独立于 Server 头**的证据
	//
	// ⭐ 这是避免自我矛盾的关键：
	//   Server 头说 "Tengine" → 它就是阿里云的服务器软件本身，
	//   不能既说"这是 CDN"又说"Server 头泄露了 CDN"。
	//   只有 CF-RAY 之类的**专用头**才是独立的 CDN 证据。
	Independent bool
	// Source 判定依据（供报告展示）
	Source string
}

// detectCDNIndependent 检测 CDN，区分判定是否独立
func detectCDNIndependent(p *ProbeResult) (string, bool) {
	// ① 专用响应头（最可靠，完全独立于 Server 头）
	if _, ok := p.CFHeaders["Cf-Ray"]; ok {
		return "Cloudflare", true
	}
	if len(p.CFHeaders) > 0 {
		return "Cloudflare", true
	}
	// ② 其他 CDN 专用头
	cdnHeaderMarkers := map[string]string{
		"X-Amz-Cf-Id":         "CloudFront (AWS)",
		"X-Fastly-Request-Id": "Fastly",
		"X-Sucuri-Id":         "Sucuri",
		"X-Cdn":               "CDN (未识别厂商)",
		"X-Qcloud-Log-Pop":    "腾讯云 CDN",
		"X-Cache":             "CDN (未识别厂商)",
		"Akamai-Origin-Hop":   "Akamai",
	}
	keys := make([]string, 0, len(p.CDNHeaders))
	for k := range p.CDNHeaders {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if name, ok := cdnHeaderMarkers[k]; ok {
			return name, true
		}
	}

	// ③ 只有 Server 头 —— ⭐ 不算独立证据
	//    记录下来但不作为冲突判据
	sl := strings.ToLower(p.Server)
	if strings.Contains(sl, "cloudflare") {
		return "Cloudflare", false
	}
	if strings.Contains(sl, "tengine") {
		return "阿里云 (Tengine)", false
	}
	if strings.Contains(sl, "kunlun") {
		return "阿里云 CDN (Kunlun)", false
	}
	return "", false
}

// detectSourceLeaks 检测穿透 CDN 泄露的源站特征
func detectSourceLeaks(p *ProbeResult) []string {
	var leaks []string

	// X-Powered-By 是最经典的泄露
	if p.PoweredBy != "" {
		leaks = append(leaks, "X-Powered-By: "+truncateS(p.PoweredBy, 30))
	}
	// Server 泄露具体软件
	if sl := strings.ToLower(p.Server); sl != "" {
		if strings.Contains(sl, "apache") || strings.Contains(sl, "nginx") ||
			strings.Contains(sl, "iis") || strings.Contains(sl, "tengine") {
			leaks = append(leaks, "Server: "+truncateS(p.Server, 30))
		}
	}
	// Cookie 里的框架标记
	for _, c := range p.SetCookies {
		cl := strings.ToLower(c)
		if strings.Contains(cl, "phpsessid") {
			leaks = append(leaks, "Cookie: PHPSESSID（PHP 确认）")
			break
		}
		if strings.Contains(cl, "jsessionid") {
			leaks = append(leaks, "Cookie: JSESSIONID（Java 确认）")
			break
		}
		if strings.Contains(cl, "asp.net") || strings.Contains(cl, "aspsessionid") {
			leaks = append(leaks, "Cookie: ASP.NET_SessionId")
			break
		}
		if strings.Contains(cl, "laravel_session") {
			leaks = append(leaks, "Cookie: laravel_session（Laravel 确认）")
			break
		}
	}
	// 正文技术栈（若 CDN 只代理静态资源不太可能出现）
	if len(p.BodyKeywords) > 0 {
		leaks = append(leaks, "正文特征: "+strings.Join(p.BodyKeywords, "/"))
	}
	return leaks
}

// versionConflict 检测 Server 声明版本与 TLS 特征的矛盾
func versionConflict(p *ProbeResult) string {
	if p.Server == "" || p.TLSVersion == "" {
		return ""
	}
	sl := strings.ToLower(p.Server)
	// nginx 声明了版本，但 TLS 是 1.3 且 cipher 是老套件 —— 正常，不是冲突
	// 真正的冲突：Server 头声称老版本（如 nginx/1.0）但 TLS 是最新
	if strings.Contains(sl, "apache/1.") || strings.Contains(sl, "nginx/0.") {
		return fmt.Sprintf("Server 头声称 %s，但 TLS 协商结果是 %s —— 版本信息可能未同步。",
			p.Server, p.TLSVersion)
	}
	// IIS 版本与 TLS 3 不兼容
	if strings.Contains(sl, "microsoft-iis/5") || strings.Contains(sl, "microsoft-iis/6") {
		if p.TLSVersion == "TLS 1.3" {
			return fmt.Sprintf("Server 声称 %s（不支持 TLS 1.3），但实际协商到 %s —— "+
				"说明 Server 头被伪造或中间有代理改写。", p.Server, p.TLSVersion)
		}
	}
	// Apache 2.2 不支持 TLS 1.2/1.3
	if strings.Contains(sl, "apache/2.2") {
		if p.TLSVersion == "TLS 1.2" || p.TLSVersion == "TLS 1.3" {
			return fmt.Sprintf("Server 声称 %s（最高 TLS 1.0），但协商到 %s —— "+
				"Server 头很可能被伪造。", p.Server, p.TLSVersion)
		}
	}
	return ""
}

// techTitleConflict 检测正文特征与标题的矛盾
func techTitleConflict(p *ProbeResult) string {
	tl := strings.ToLower(p.Title)
	// 标题是纯数字/英文但正文是 CMS —— 正常
	// 标题含具体技术名但正文特征是另一个 —— 值得报告
	techInTitle := ""
	for tech := range bodyKeywordPatterns {
		if strings.Contains(tl, strings.ToLower(tech)) {
			techInTitle = tech
			break
		}
	}
	if techInTitle == "" {
		return ""
	}
	// 标题里的技术在正文特征里没有
	found := false
	for _, k := range p.BodyKeywords {
		if k == techInTitle {
			found = true
			break
		}
	}
	if !found {
		return fmt.Sprintf("标题提到 %q，但正文特征里没有对应证据（正文显示 %s）。",
			techInTitle, strings.Join(p.BodyKeywords, "/"))
	}
	// 标题里的技术 A，正文是技术 B
	var others []string
	for _, k := range p.BodyKeywords {
		if k != techInTitle {
			others = append(others, k)
		}
	}
	if len(others) > 0 {
		return fmt.Sprintf("标题提到 %q，但正文特征显示 %s —— 可能是混合架构或定制开发。",
			techInTitle, strings.Join(others, "/"))
	}
	return ""
}

// weakCookies 检测缺少安全标志的会话 Cookie
func weakCookies(cookies []string) []string {
	var bad []string
	for _, c := range cookies {
		cl := strings.ToLower(c)
		// 只看会话类 Cookie
		isSession := strings.Contains(cl, "session") || strings.Contains(cl, "sid=") ||
			strings.Contains(cl, "token") || strings.Contains(cl, "auth")
		if !isSession {
			continue
		}
		var problems []string
		if !strings.Contains(cl, "secure") {
			problems = append(problems, "缺 Secure")
		}
		if !strings.Contains(cl, "httponly") {
			problems = append(problems, "缺 HttpOnly")
		}
		if len(problems) > 0 {
			name := c
			if i := strings.IndexByte(c, '='); i > 0 {
				name = c[:i]
			}
			bad = append(bad, fmt.Sprintf("%s（%s）", name, strings.Join(problems, "、")))
		}
	}
	return bad
}

// ── 批量冲突检测 ──────────────────────────────────────────

// DetectAll 批量检测
func DetectAll(results []*ProbeResult) []*ConflictReport {
	out := make([]*ConflictReport, 0, len(results))
	for _, r := range results {
		out = append(out, DetectConflicts(r))
	}
	return out
}

// Summary 冲突统计
type Summary struct {
	Total   int            `json:"total"`
	Clean   int            `json:"clean"`
	WithAny int            `json:"with_conflicts"`
	ByType  map[string]int `json:"by_type,omitempty"`
	BySev   map[string]int `json:"by_severity,omitempty"`
}

// Summarize 汇总
func Summarize(reports []*ConflictReport) Summary {
	s := Summary{
		Total:  len(reports),
		ByType: map[string]int{},
		BySev:  map[string]int{},
	}
	for _, r := range reports {
		if r == nil {
			continue
		}
		if len(r.Conflicts) == 0 {
			s.Clean++
			continue
		}
		s.WithAny++
		for _, c := range r.Conflicts {
			s.ByType[string(c.Type)]++
			s.BySev[c.Severity]++
		}
	}
	if len(s.ByType) == 0 {
		s.ByType = nil
	}
	if len(s.BySev) == 0 {
		s.BySev = nil
	}
	return s
}

// hostOf 从 URL 提取主机名
func hostOf(rawURL string) string {
	u, err := parseURL(rawURL)
	if err != nil {
		return rawURL
	}
	return u.hostname()
}

// faviconCompatibleWith 判断 favicon 判定与 Server 头是否兼容
//
// ⭐ 兼容的定义：两者**描述的是同一层的东西**。
//
//	favicon 说应用（Grafana/Jenkins），Server 头说 Web 服务器（nginx/Apache）
//	—— 这两者**本就不该一致**，它们是不同维度！
//
//	所以只有当两者**明显互斥**时才报冲突：
//	  favicon=Grafana  但 Server=IIS      → 矛盾（不像是 Grafana 的部署）
//	  favicon=Grafana  但 Server=nginx    → 正常（grafana 跑在 nginx 后面）
func faviconCompatibleWith(favProduct, serverProduct string) bool {
	// ── 第一步：favicon 指的是否为「服务端应用」 ──
	//
	// ⭐ 这类应用**本身就是服务端**（提供 TCP 端口、直接处理请求），
	//   不可能"跑在某个 Web 服务器后面"——
	//   Redis/MySQL/GitLab/Jenkins 自己就监听端口了。
	//   把它们当成"可以用任何反代兜着"是错的。
	//
	//   实测踩到（2026-10-05）：favicon=Redis + Server=IIS
	//   因为 IIS 在代理列表里而被判兼容 → 漏报了矛盾。
	serverSideApps := map[string]bool{
		"Redis": true, "PostgreSQL": true, "MongoDB": true, "Docker": true,
		"Jenkins": true, "GitLab": true, "Gitea": true, "GitHub": true,
		"PyPI": true, "RubyGems": true, "Packagist": true,
	}
	if serverSideApps[favProduct] {
		// 服务端应用 + 反代 = 可能（Redis 前面确实常有 nginx 做 TLS 终结）
		if serverProduct == "nginx" || serverProduct == "Apache" ||
			serverProduct == "Caddy" || serverProduct == "OpenResty" {
			return true
		}
		// 服务端应用 + IIS → 极不可能（Windows 上跑 Redis 的场景极罕见）
		if serverProduct == "IIS" {
			return false
		}
		// 其它没听过的组合：不报（避免噪音）
		return true
	}

	// ── 第二步：普通 Web 应用 ──
	//   它们通常跑在反代后面（Server 头显示的是反代而非应用本身），属正常
	proxyServers := map[string]bool{
		"nginx": true, "Apache": true, "Caddy": true, "IIS": true,
		"OpenResty": true, "Gunicorn": true,
	}
	if proxyServers[serverProduct] {
		return true
	}

	// ── 第三步：两者都不认识 → 不报 ──
	if serverProduct == "" {
		return true
	}

	// 明确知道是服务器软件，但 favicon 说是别的应用 → 矛盾
	return false
}

func truncateList(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" …(共 %d)", len(items))
}

func truncateS(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}
