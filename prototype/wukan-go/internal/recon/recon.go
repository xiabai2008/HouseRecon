package recon

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wukan/wukan/internal/httpprobe"
	"github.com/wukan/wukan/internal/ipinfo"
	"github.com/wukan/wukan/internal/portscan"
	"github.com/wukan/wukan/internal/quic"
)

// Target 是 recon 的目标域
type Target struct {
	Domain string `json:"domain"`
}

// Report 是完整的信息卡
type Report struct {
	Target string `json:"target"`
	// DNS 解析结果
	DNS *DNSResult `json:"dns,omitempty"`
	// RDAP 注册信息
	Domain *DomainInfo `json:"domain_info,omitempty"`
	// CT 证书透明度子域
	CT *SubdomainResult `json:"ct,omitempty"`
	// Passive 被动 DNS 历史解析
	Passive *PassiveDNSResult `json:"passive_dns,omitempty"`
	// ReverseIP 同源资产（IP 反查）
	ReverseIP []*ReverseIPResult `json:"reverse_ip,omitempty"`
	// QUIC UDP/443 探活结果（需显式 --quic 开启，因为这是主动探测）
	QUIC []quic.Result `json:"quic,omitempty"`
	// Ports 端口扫描结果（需显式 --ports 开启，主动探测）
	Ports []portscan.PortResult `json:"ports,omitempty"`
	// Tech HTTP 指纹采集结果（需显式 --tech 开启，主动探测）
	Tech []*httpprobe.ProbeResult `json:"tech,omitempty"`
	// TechConflicts 指纹冲突检测报告
	TechConflicts []*httpprobe.ConflictReport `json:"tech_conflicts,omitempty"`
	// RDNS 各 IP 的 rDNS（PTR）反查结果
	//
	// ⭐ 与 PassiveDNS 里的 ReverseIP **方向相反、语义不同，不重复**：
	//   ReverseIP   hackertarget 数据库 → 共享主机上「别人的域」（50次/天配额）
	//   RDNS        权威 DNS PTR      → IP 持有者自己声明的身份（无配额）
	RDNS []*ipinfo.RDNSResult `json:"rdns,omitempty"`
	// IP 归属（对根域 IP 查询）
	IPInfo []*ipinfo.Info `json:"ip_info,omitempty"`
	// Findings ⭐ 自动发现的可行动项
	Findings []Finding `json:"findings,omitempty"`
	// Diff ⭐ 与上次快照的差异（--snapshot 且存在历史快照时填充）
	Diff *SnapshotDiff `json:"snapshot_diff,omitempty"`
	// Timing 各阶段耗时
	Timing map[string]string `json:"timing,omitempty"`
	// Total 总耗时
	Total string `json:"total_elapsed,omitempty"`
	// PortsErr 端口扫描参数错误（如全端口被拒）
	PortsErr string `json:"ports_error,omitempty"`
	// PortsSpec 本次端口扫描的参数（快照覆盖率判定：参数不同则端口差异不可比）
	PortsSpec string `json:"ports_spec,omitempty"`
	// TechErr 指纹采集未执行的原因
	TechErr string `json:"tech_error,omitempty"`
}

// Finding 是一条可行动的发现
type Finding struct {
	// Level 严重程度：high / medium / low / info
	Level string `json:"level"`
	// Type 发现类型
	Type string `json:"type"`
	// Title 一句话结论
	Title string `json:"title"`
	// Detail 详细说明
	Detail string `json:"detail,omitempty"`
	// Evidence 支撑证据
	Evidence []string `json:"evidence,omitempty"`
}

// Options recon 选项
type Options struct {
	DNS     DNSOptions
	CT      CTOptions
	RDAP    RDAPOptions
	Passive PassiveOptions
	// ⭐ rDNS 反查（被动 DNS 查询，默认开启 —— 无需发包，只是查 PTR）
	RDNS bool
	// RDNSMaxIP 最多对多少个 IP 做反查（防超大域名跑太久）
	RDNSMaxIP int

	// QuicProbe 是否做 QUIC/UDP-443 探活（⚠ 主动探测，默认关）
	QuicProbe bool
	// QuicProbes 每目标探测包数
	QuicProbes int
	// QuicTimeout 单包超时
	QuicTimeout time.Duration

	// ⭐ 端口扫描（主动探测，默认关）
	PortsScan bool
	// PortsSpec 端口表达式（"80,443" / "top100" / "web,ssh,db"）
	PortsSpec string
	// PortsTimeout 单端口超时
	PortsTimeout time.Duration
	// PortsRate 限速
	PortsRate int
	// PortsGrabBanner 是否抓 banner
	PortsGrabBanner bool
	// PortsCache 端口扫描结果缓存（nil = 不缓存）
	//
	// ⭐ 与 TechCache 同属"性能优化"，不影响采集逻辑本身。
	//   缓存键由 portscan.MakeCacheKey 生成（含实际发送的 Host 头）。
	PortsCache portscan.PortCache

	// ⭐ HTTP 指纹采集（主动探测，默认关）
	TechProbe bool
	// TechTimeout 超时
	TechTimeout time.Duration
	// TechConcurrency 并发
	TechConcurrency int
	// TechMaxTargets 最多探测多少个 URL（防超时）
	TechMaxTargets int
	// TechNoFavicon 不抓 favicon（更快）
	TechNoFavicon bool
	// TechRetryFallback 失败目标是否降级重试（跳过重定向 / http 回退）
	//
	// ⭐ 实测有 4 个子域"重定向后超时"，降级重试能把它们从"探测失败"
	//   变成"可分析的结果"（原始 301/302 本身就有指纹价值）。
	TechRetryFallback bool
	// TechSubdomains ⭐ 是否对发现的存活子域也做指纹探测
	//
	// 这是"覆盖整个攻击面"的关键 —— 子域往往跑着不同的应用、
	// 不同的中间件、不同的安全配置，只探根域会漏掉绝大部分暴露面。
	TechSubdomains bool
	// TechSubMax 最多探测多少个子域
	TechSubMax int
	// TechCacheTTL 指纹缓存有效期
	TechCacheTTL time.Duration
	// TechCache 指纹缓存实例
	TechCache httpprobe.TechCache
	// DoIPInfo 是否对 IP 做归属查询
	DoIPInfo bool
	// IPInfoWorkers IP 归属并发
	IPInfoWorkers int
	// MaxSubdomains 报告中最多列多少子域
	MaxSubdomains int
	// IPInfoCache IP 归属缓存
	IPInfoCache ipinfo.Cache
	// IPInfoSecondary 是否启用 IP 归属补充源
	IPInfoSecondary bool
}

// DefaultOptions 返回默认选项
func DefaultOptions() Options {
	return Options{
		DNS:  DefaultDNSOptions(),
		CT:   DefaultCTOptions(),
		RDAP: RDAPOptions{Timeout: 12 * time.Second, Enabled: true},
		// ⭐ 必须显式初始化：Options.Passive 是零值时
		//   PassiveOptions.HostSearch=false，导致 CollectPassive 直接跳过所有采集
		//   （实测表现为 passive_dns=0s 且 sources_failed 为空）。
		Passive: DefaultPassiveOptions(),
		// ⭐ rDNS 反查默认开启（被动 DNS 查询，不向目标发任何包）
		RDNS:      true,
		RDNSMaxIP: 10,
		// ⭐ 主动探测，默认必须关
		QuicProbe:   false,
		QuicProbes:  2,
		QuicTimeout: 3 * time.Second,
		// ⭐ 端口扫描（主动，默认关）
		PortsScan:       false,
		PortsSpec:       "top100",
		PortsTimeout:    3 * time.Second,
		PortsRate:       100,
		PortsGrabBanner: true,
		// ⭐ 端口缓存默认 nil（由 CLI 注入；换机后缓存为空是正常的）
		PortsCache: nil,
		// ⭐ HTTP 指纹（主动，默认关）
		TechProbe:       false,
		TechTimeout:     8 * time.Second,
		TechConcurrency: 8,
		TechMaxTargets:  20,
		// ⭐ 失败目标降级重试（跳过重定向 / http 回退），默认开启
		TechRetryFallback: true,
		// ⭐ 子域探测默认开启 —— 这是"覆盖整个攻击面"的关键
		TechSubdomains:  true,
		TechSubMax:      15,
		DoIPInfo:        true,
		IPInfoWorkers:   8,
		MaxSubdomains:   30,
		IPInfoSecondary: true,
	}
}

// Runner 执行 recon
type Runner struct {
	opt Options
	// IPInfoClient IP 归属查询客户端
	IPInfoClient *ipinfo.Client
	// PassiveCache 被动数据缓存
	PassiveCache PassiveCache
}

// NewRunner 创建执行器
func NewRunner(opt Options) *Runner {
	opts := []ipinfo.Option{
		ipinfo.WithTimeout(12 * time.Second),
		ipinfo.WithRateLimit(120 * time.Millisecond),
		ipinfo.WithSecondary(opt.IPInfoSecondary),
	}
	if opt.IPInfoCache != nil {
		opts = append(opts, ipinfo.WithCache(opt.IPInfoCache))
	}
	return &Runner{opt: opt, IPInfoClient: ipinfo.New(opts...)}
}

// SetPassiveCache 设置被动数据缓存
func (r *Runner) SetPassiveCache(c PassiveCache) { r.PassiveCache = c }

// Run 对单个域执行完整 recon
//
// ⭐ 全流程被动：DNS 查询走公共解析器、RDAP 走注册局、CT 走公开日志、
//
//	IP 归属走第三方 API。除非显式开启主动探测，否则不向目标发任何包。
func (r *Runner) Run(ctx context.Context, domain string) *Report {
	start := time.Now()
	domain = normalizeDomain(domain)

	rep := &Report{
		Target: domain,
		Timing: map[string]string{},
	}

	// 阶段 1：DNS
	t0 := time.Now()
	rep.DNS = ResolveDNS(ctx, domain, r.opt.CT.Resolver, r.opt.DNS)
	rep.Timing["dns"] = time.Since(t0).String()

	// 阶段 2 & 3 & 3b：RDAP / CT / 被动DNS 并行（都是网络 IO，互不依赖）
	//
	// ⭐ 各 goroutine 只写**自己的局部变量**，wg.Wait() 后统一写入 rep.Timing ——
	//   此前三处直接写同一个 map，实测约 1/12 概率触发
	//   "fatal error: concurrent map writes" 直接崩进程（审查发现的真实崩溃）。
	var wg sync.WaitGroup
	var tRDAP, tCT, tPassive string
	wg.Add(3)

	go func() {
		defer wg.Done()
		t := time.Now()
		rep.Domain = LookupDomain(ctx, domain, r.opt.RDAP)
		tRDAP = time.Since(t).String()
	}()

	go func() {
		defer wg.Done()
		t := time.Now()
		rep.CT = CollectSubdomains(ctx, domain, r.opt.CT)
		tCT = time.Since(t).String()
	}()

	go func() {
		defer wg.Done()
		t := time.Now()
		opt := r.opt.Passive
		if r.PassiveCache != nil {
			opt.Cache = r.PassiveCache
		}
		rep.Passive = CollectPassive(ctx, domain, opt)
		tPassive = time.Since(t).String()
	}()

	wg.Wait()
	rep.Timing["rdap"] = tRDAP
	rep.Timing["ct"] = tCT
	rep.Timing["passive_dns"] = tPassive

	// 阶段 3c：IP 反查同源资产（用被动 DNS 拿到的历史 IP）
	//
	// ⭐ 价值：历史 IP 可能已释放给其他人，也能查出与目标共享
	//   服务器的其他域（共享主机/CDN 回源场景）。这是"你不知道的资产"。
	if r.opt.Passive.Enabled && r.opt.Passive.ReverseIPLimit > 0 && rep.Passive != nil {
		t := time.Now()
		// 优先用历史 IP（已下线的更有价值），不足则补当前 IP
		ips := rep.Passive.AllIPs()
		if len(ips) == 0 && rep.DNS != nil {
			ips = rep.DNS.IPs
		}
		rep.ReverseIP = ReverseLookup(ctx, ips, r.opt.Passive)
		rep.Timing["reverse_ip"] = time.Since(t).String()
	}

	// 阶段 4：IP 归属
	if r.opt.DoIPInfo && rep.DNS != nil {
		t := time.Now()
		rep.IPInfo = r.lookupIPInfo(dedupeStrings(rep.DNS.IPs))
		rep.Timing["ipinfo"] = time.Since(t).String()
	}

	// 阶段 4a2：rDNS 反查
	//
	// ⭐ 默认开启：它只是查 PTR 记录（纯被动 DNS 查询，不向目标发任何包），
	//   与"主动探测"性质不同。
	//
	//   价值：把「IP」变成「IP + 声明的身份」，是发现资产归属的第一线索。
	//   例：1.2.3.4 → static.cdn.example.com 说明这台机器在为 example.com 服务。
	if r.opt.RDNS && rep.DNS != nil && len(rep.DNS.IPs) > 0 {
		t := time.Now()
		res := ipinfo.NewRDNSResolver(4 * time.Second)
		ips := rep.DNS.IPs
		if r.opt.RDNSMaxIP > 0 && len(ips) > r.opt.RDNSMaxIP {
			ips = ips[:r.opt.RDNSMaxIP]
		}
		// 并发反查
		type rdnsJob struct {
			idx int
			res *ipinfo.RDNSResult
		}
		jobs := make(chan rdnsJob, len(ips))
		for i, ip := range ips {
			jobs <- rdnsJob{i, res.Lookup(ip)}
		}
		close(jobs)
		rep.RDNS = make([]*ipinfo.RDNSResult, len(ips))
		for j := range jobs {
			rep.RDNS[j.idx] = j.res
		}
		rep.Timing["rdns"] = time.Since(t).String()
	}

	// 阶段 4b：QUIC 探活（⚠ 主动探测，仅在显式开启时执行）
	//
	// ⭐ 这是 recon 里唯一需要向目标发包的阶段，所以：
	//   - 默认关闭，必须 --quic 显式开启
	//   - 只发 Version Negotiation 探测包（1200 字节 × N），不握手、不发应用数据
	//   - 价值：找出"只开放 HTTP/3、TCP/443 关闭"的资产
	//     —— 这类资产对所有 TCP-only 扫描器（naabu/httpx/Shodan/Censys/ZMap）
	//     都是**完全不可见**的
	if r.opt.QuicProbe && rep.DNS != nil && len(rep.DNS.IPs) > 0 {
		t := time.Now()
		cfg := quic.DefaultConfig()
		cfg.Probes = r.opt.QuicProbes
		cfg.Timeout = r.opt.QuicTimeout
		cfg.Concurrency = 8
		cfg.KeepRaw = false
		targets := make([]quic.Target, 0, len(rep.DNS.IPs))
		for _, ip := range rep.DNS.IPs {
			targets = append(targets, quic.Target{Host: ip, Port: 443})
		}
		rep.QUIC = quic.Scan(targets, cfg)
		rep.Timing["quic"] = time.Since(t).String()
	}

	// 阶段 4c：端口扫描（⚠ 主动探测，仅在显式开启时执行）
	//
	// ⭐ 与 QUIC 的区别：QUIC 只发 1200 字节的探测包拿一个判定，
	//   端口扫描会真正建立 TCP 连接并抓 banner —— 对目标的影响更大，
	//   所以端口必须显式指定（不可全端口），且限速更保守（默认 100/s）。
	if r.opt.PortsScan && rep.DNS != nil && len(rep.DNS.IPs) > 0 {
		t := time.Now()
		rep.PortsSpec = r.opt.PortsSpec
		spec, err := portscan.ParsePorts(r.opt.PortsSpec)
		if err != nil {
			rep.Ports = nil
			rep.PortsErr = err.Error()
		} else {
			ports := spec.Expand()
			pcfg := portscan.DefaultConfig()
			pcfg.Ports = ports
			pcfg.Timeout = r.opt.PortsTimeout
			pcfg.RateLimit = r.opt.PortsRate
			pcfg.GrabBanner = r.opt.PortsGrabBanner
			pcfg.Concurrency = 32
			// ⭐ 端口结果缓存（nil = 不缓存；命中时不会发起连接）
			pcfg.Cache = r.opt.PortsCache
			for _, ip := range rep.DNS.IPs {
				pcfg.Hosts = append(pcfg.Hosts, ip)
			}
			// ⭐ Host 用域名而不是 IP：让 banner 里的 Server 头能带上正确 Host，
			// 某些 CDN/WAF 会根据 Host 头返回不同内容。
			// 同时 IP 仍记在 result.IP 字段。
			pcfg.HostHeader = rep.Target
			sc := portscan.New(pcfg)
			rep.Ports = sc.ScanAll(nil)
			rep.Timing["ports"] = time.Since(t).String()
		}
	}

	// 阶段 4d：HTTP 指纹采集与冲突检测（⚠ 主动探测）
	//
	// ⭐⭐ 目标选取策略（本阶段最关键的设计决策）：
	//
	//	**只对"有开放 Web 端口的 IP"跑 tech**，而不是对所有解析出的 IP。
	//
	//	原因：
	//	  1. 大部分 IP 只开 22/3389 等非 Web 端口，对其发 HTTP 请求纯属浪费
	//	  2. ⭐ **CDN 节点会对没有匹配 Host 的请求返回默认站点**，
	//	     这会产出"看起来正常但完全错误"的指纹 —— 比不采集更糟
	//	  3. 减少请求数 = 降低被 IDS 记录的概率
	//
	//	没有 --ports 时退化为：假定 80/443 可能开放，取根域探测。
	if r.opt.TechProbe {
		t := time.Now()
		targets := r.techTargets(rep)
		if len(targets) == 0 {
			rep.TechErr = "未找到可探测的 Web 端口（是否忘了 --ports 80,443？）"
		} else {
			// ⭐ 每个目标可能有不同的 Host 头（根域 CDN 节点 vs 各子域），
			//   所以按 Host 头分组，每组一个 Prober。
			rep.Tech = r.probeTechTargets(targets)
			// ⭐ 核心：交叉校验各路指纹，检测矛盾
			rep.TechConflicts = httpprobe.DetectAll(rep.Tech)
			rep.Timing["tech"] = time.Since(t).String()
		}
	}

	// 阶段 5：分析发现
	rep.Findings = Analyze(rep)

	rep.Total = time.Since(start).String()
	return rep
}

func (r *Runner) lookupIPInfo(ips []string) []*ipinfo.Info {
	if len(ips) == 0 {
		return nil
	}
	// 限制数量，避免大域名时查询过多
	limit := len(ips)
	if limit > 10 {
		limit = 10
	}
	return r.IPInfoClient.LookupMany(ips[:limit], r.opt.IPInfoWorkers)
}

// normalizeDomain 规范化域名（去协议、去路径、去通配符）
//
// ⭐ 保留旧名作为别名 —— 快照/差异模块统一走 NormalizeTarget，
//
//	避免"recon 归一化了、diff 没归一化"的口径不一致（审查发现的真实问题：
//	`recon https://example.com --snapshot` 写入 example.com.json 后，
//	`diff https://example.com` 找不到快照）。
func normalizeDomain(s string) string { return NormalizeTarget(s) }

// NormalizeTarget 规范化目标（去协议、去路径、去通配符、小写、去尾点）
//
// ⭐ 必须**幂等**（normalize(normalize(x)) == normalize(x)）：
//
//	存储层会二次调用（SaveAndPrevious → snapshotPath），不幂等时
//	像 "../evil/../x"（第一次归一化成 "."，第二次成 ""）会产生
//	静默的文件名漂移。尾点用 TrimRight 一次去净。
func NormalizeTarget(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	for _, p := range []string{"https://", "http://"} {
		s = strings.TrimPrefix(s, p)
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "*.")
	return strings.TrimRight(s, ".")
}

// ── 分析：自动发现可行动项 ─────────────────────────────────

// Analyze 从 recon 结果中提取可行动发现
//
// ⭐ 这是 recon 的价值所在 —— 不是"打印一堆 DNS 记录"，
//
//	而是告诉使用者"哪些地方需要注意、可以行动"。
func Analyze(rep *Report) []Finding {
	var out []Finding
	if rep == nil {
		return out
	}

	add := func(level, typ, title, detail string, ev ...string) {
		out = append(out, Finding{
			Level: level, Type: typ, Title: title,
			Detail: detail, Evidence: ev,
		})
	}

	// ── DNS 相关 ──
	if rep.DNS != nil {
		if rep.DNS.NXDomain() {
			add("high", "nxdomain",
				"域名不存在（NXDOMAIN）",
				"该域名当前没有 DNS 记录。若这是你的资产，说明域名已被注销或未正确配置。",
				"可能拼写错误", "可能已过期未续费")
		}

		// ⭐ 泛域名提示 —— 这直接影响子域存活判断的可靠性
		if rep.DNS.Wildcard != "" {
			add("info", "wildcard",
				fmt.Sprintf("检测到泛域名解析 *.%s", rep.Target),
				"泛域名会让任意子域都解析成功，因此**子域能解析不能作为资产存活的证据**。"+
					"判断子域是否真实存在，必须结合 HTTP 响应（返回内容、状态码）。",
				"泛域名解析到: "+rep.DNS.Wildcard)
		}

		if len(rep.DNS.IPs) == 0 && !rep.DNS.NXDomain() {
			add("high", "no_ip",
				"域名未解析出任何 IP（A/AAAA 均为空）",
				"可能原因：① 只配了 CNAME 但 CNAME 目标无 A 记录；② 服务已下线；③ 解析器被污染。",
				"建议换解析器重试：-dns cloudflare / -dns 8.8.8.8")
		}

		// 多 IP 提示（可能含 CDN）
		if len(rep.DNS.IPs) > 3 {
			add("low", "multi_ip",
				fmt.Sprintf("解析出 %d 个 IP", len(rep.DNS.IPs)),
				"多个 IP 可能意味着 CDN 轮询或负载均衡。"+
					"对全部 IP 做端口扫描会产生大量重复结果，应先识别 CDN。",
				strings.Join(rep.DNS.IPs, ", "))
		}

		// ⭐ TXT 记录里的第三方验证 token
		//   实测（2026-10-04）：github.com 的 TXT 泄露了 18 条第三方验证 token
		//   （Shopify / Stripe / Facebook / Google / Miro / Loom…）。
		//   这些 token 在正常情况下不对外可见，出现在公开 DNS 里说明
		//   域的所有权验证被配置过 —— 它们是**社工与钓鱼的现成素材**
		//   （攻击者可用这些 token 冒充品牌在第三方平台发起操作）。
		var tokens []string
		for _, t := range rep.DNS.Get(TypeTXT) {
			if v := thirdPartyToken(t.Value); v != "" {
				tokens = append(tokens, v)
			}
		}
		if len(tokens) > 0 {
			add("low", "txt_tokens",
				fmt.Sprintf("TXT 记录暴露 %d 个第三方平台验证 token", len(tokens)),
				"这些 token 通常用于验证域名对第三方平台（Shopify/Stripe/Facebook…）的所有权，"+
					"正常情况不对外可见。\n"+
					"风险：可用于品牌冒充、钓鱼站点搭建，或在某些平台发起未授权操作。"+
					"若不需要这些验证，建议从 DNS 记录中移除。",
				tokens...)
		}

		// SPF / DMARC 邮件安全配置
		var hasSPF, hasDMARC bool
		for _, t := range rep.DNS.Get(TypeTXT) {
			lv := strings.ToLower(t.Value)
			if strings.HasPrefix(lv, "v=spf1") {
				hasSPF = true
			}
			if strings.HasPrefix(lv, "v=dmarc1") {
				hasDMARC = true
			}
		}
		if rep.DNS.Get(TypeMX) != nil {
			if !hasSPF {
				add("medium", "no_spf",
					"配置了 MX 但没有 SPF 记录",
					"无 SPF 时，攻击者可用你的域发送任意发件人邮件（邮件仿冒）。"+
						"这是低成本高影响的社工攻击入口。",
					"建议添加: v=spf1 include:... -all")
			}
			if !hasDMARC {
				add("low", "no_dmarc",
					"未配置 DMARC 记录",
					"DMARC 告诉收件方如何处理 SPF/DKIM 验证失败的邮件。"+
						"没有它，仿冒邮件更容易进入收件箱。",
					"建议添加: v=DMARC1; p=none; rua=mailto:...")
			}
		}

		// 邮件配置检查（域是否有被仿冒风险）
		if len(rep.DNS.Get(TypeMX)) == 0 {
			add("low", "no_mx",
				"未配置 MX 记录",
				"若该域需要收邮件，注意邮件仿冒风险（无 SPF/DMARC 会让钓鱼邮件更容易伪造发件人。",
				"检查 TXT 记录中是否有 v=spf1")
		}
	}

	// ── 域名注册信息相关 ──
	if rep.Domain != nil {
		if age, ok := rep.Domain.Age(); ok {
			if rep.Domain.IsNew(180 * 24 * time.Hour) {
				add("medium", "new_domain",
					fmt.Sprintf("域名很新（注册仅 %d 天）", int(age.Hours()/24)),
					"新注册域名在攻击活动与钓鱼中更常见。"+
						"若这是你的资产，建议确认是否为测试/抢注用途。",
					"注册时间: "+rep.Domain.Events["registration"])
			}
			if int(age.Hours()/24) < 30 {
				add("high", "very_new_domain",
					fmt.Sprintf("⚠ 域名注册仅 %d 天", int(age.Hours()/24)),
					"极短时间内注册的域名需高度警惕。"+
						"已知攻击模式：新注册域名 → 搭建钓鱼/仿冒站点。",
					"注册时间: "+rep.Domain.Events["registration"])
			}
		}

		if exp, ok := rep.Domain.ExpiresIn(); ok {
			if exp < 0 {
				add("high", "expired",
					"域名已过期",
					"域名已过注册有效期，可能随时被释放。",
					"过期时间: "+rep.Domain.Events["expiration"])
			} else if rep.Domain.IsExpiringSoon(90 * 24 * time.Hour) {
				add("medium", "expiring",
					fmt.Sprintf("域名将在 %d 天后过期", int(exp.Hours()/24)),
					"注意及时续费。域名过期后可能被他人注册并用于仿冒。",
					"过期时间: "+rep.Domain.Events["expiration"])
			}
		}

		if !rep.Domain.SecureDNS && rep.Domain.Source == "rdap.org" {
			add("low", "no_dnssec",
				"未启用 DNSSEC",
				"DNS 记录可被中间人篡改。对安全敏感的组织建议启用。",
				"RDAP SecureDNS 字段为 false")
		}

		// NS 数量异常
		if n := len(rep.Domain.Nameservers); n > 0 && n <= 1 {
			add("medium", "single_ns",
				"仅有 1 个 NS 记录",
				"单 NS 存在单点故障风险：任一 NS 故障则整个域无法解析。",
				fmt.Sprintf("NS: %v", rep.Domain.Nameservers))
		}
	}

	// ── 子域相关 ──
	if rep.CT != nil && len(rep.CT.Subdomains) > 0 {
		// ⭐ 影子资产：证书里有、但当前解析不了的历史子域
		var ghosts []*SubdomainInfo
		for _, s := range rep.CT.Subdomains {
			// ⭐ 排除根域自身与通配符条目：
			//   - 根域存活性由 DNS 段判定，不该在这里重复算
			//   - "*.xxx" 不是可访问的资产
			if strings.EqualFold(s.Name, rep.Target) {
				continue
			}
			if !s.Resolves && !s.IsWildcard {
				ghosts = append(ghosts, s)
			}
		}
		if len(ghosts) > 0 {
			names := make([]string, 0, min(len(ghosts), 8))
			for i, g := range ghosts {
				if i >= 8 {
					break
				}
				names = append(names, g.Name)
			}
			level := "medium"
			detail := "这些域名出现在历史证书中，但当前已无法解析。"
			if rep.DNS != nil && rep.DNS.Wildcard != "" {
				detail += "\n⚠ 注意：该域有泛域名解析，所以「能解析」也不能证明资产存活。" +
					"这些域名的真实状态需用 HTTP 探测确认。"
			}
			add(level, "shadow_asset",
				fmt.Sprintf("发现 %d 个历史证书中的子域当前不解析", len(ghosts)),
				detail, names...)
		}

		// 活跃子域统计
		active := rep.CT.Active()
		if len(active) > 0 {
			var names []string
			for i, a := range active {
				if i >= 10 {
					break
				}
				names = append(names, a.Name)
			}
			add("info", "active_subdomains",
				fmt.Sprintf("证书记录中 %d 个子域仍在有效期内", len(active)),
				"这些是攻击面候选。建议对它们逐个做 HTTP 探测确认存活与指纹。",
				names...)
		}

		// 被吊销证书
		var revoked []*SubdomainInfo
		for _, s := range rep.CT.Subdomains {
			if s.RevokedCount > 0 && s.RevokedCount == s.CertCount {
				revoked = append(revoked, s)
			}
		}
		if len(revoked) > 0 {
			add("info", "revoked_certs",
				fmt.Sprintf("%d 个子域的证书已被全部吊销", len(revoked)),
				"证书吊销通常是正常的（密钥轮换），但也可能是泄露后紧急吊销。"+
					"若子域仍在服务，值得一探。",
				"")
		}
	}

	// ── rDNS 相关 ──
	//
	// ⭐ rDNS 在 recon 里的独特价值：
	//   三个来源回答三个不同的问题，缺一不可：
	//     ① 正向 DNS（阶段1）  → 现在指向哪里
	//     ② rDNS（阶段4a2）     → IP 持有者**声明**自己是谁
	//     ③ reverseiplookup    → 这台机器上**实际**还有谁的域（第三方数据库）
	//
	//   ② 与 ③ 的关键差异：**rDNS 是资产自己声明的身份**。
	//   若 ② 指向的域名不属于本域 → 说明 IP 可能被转售/挪用，
	//   这在渗透测试中是判断「资产归属」的直接证据。
	if len(rep.RDNS) > 0 {
		var withPTR, noPTR int
		var genericPtr, specificPtr []string
		for _, r := range rep.RDNS {
			if r == nil {
				continue
			}
			if !r.HasPTR {
				noPTR++
				continue
			}
			withPTR++
			c := r.Classify()
			for _, h := range c.Generic {
				genericPtr = append(genericPtr, r.IP+" → "+h)
			}
			for _, h := range c.Specific {
				specificPtr = append(specificPtr, r.IP+" → "+h)
			}
		}

		// ⭐⭐ 核心发现：rDNS 指向的域名不属于本域 → 资产归属异常
		//
		// 这是 rDNS 独有的发现：其他来源都发现不了，
		// 因为正向 DNS 只能告诉你「域名指到哪」，
		// 而 rDNS 告诉你「IP 的主人自称是谁」—— 两者矛盾就是线索。
		target := strings.ToLower(strings.TrimSuffix(rep.Target, "."))
		// ⭐ 归属判定用统一的辅助函数，避免各处重复写判定逻辑
		//   —— 实测踩到两个 bug 都源于此：
		//     ① 根域自身（PTR = example.com）被判为外部域名
		//     ② 大小写没归一（GITHUB.COM vs github.com）
		belongsTo := func(host string) bool {
			h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
			if h == "" {
				return true // 查不到就不判异常
			}
			// 根域自身
			if h == target {
				return true
			}
			// 本域子域
			return strings.HasSuffix(h, "."+target)
		}

		var mismatched []string
		for _, item := range specificPtr {
			// ⭐ SplitN 而非 Index+偏移（"→" 是 3 字节 UTF-8）
			parts := strings.SplitN(item, " → ", 2)
			if len(parts) != 2 {
				continue
			}
			if belongsTo(parts[1]) {
				continue
			}
			mismatched = append(mismatched, item)
		}
		if len(mismatched) > 0 {
			ev := mismatched
			if len(ev) > 10 {
				ev = ev[:10]
			}
			add("high", "rdns_identity_mismatch",
				fmt.Sprintf("IP 的 PTR 记录指向不属于本域的域名（%d 个）", len(mismatched)),
				"⭐ **这是资产归属的直接证据。**\n\n"+
					"正向 DNS 告诉你「域名现在指到哪」，而 rDNS 告诉你「IP 的主人自称是谁」——\n"+
					"**两者矛盾时，以 PTR 为线索追查。**\n\n"+
					"可能的含义：\n"+
					"  ① IP 已被转售/挪用，现在属于其他组织\n"+
					"  ② 历史遗留：域名换了主机，旧主机仍保留旧的 PTR\n"+
					"  ③ 共享主机：多租户环境下的正常现象\n\n"+
					"建议：确认这些 IP 的实际归属。若已不属于你的资产，"+
					"应从资产台账中移除（留着会误导蓝队，也让扫描报告失真）。",
				ev...)
		}

		// rDNS 指向本域但正向 DNS 没有的子域 → 影子资产线索
		var declaredNotInDNS []string
		for _, item := range specificPtr {
			// ⭐⭐ 必须用 SplitN 而非 Index+固定偏移。
			//
			//   箭头 "→" 是 3 字节的 UTF-8 字符，原来的 `idx+3` 落在
			//   箭头的第 2 个字节上，切出来的 host 形如 "\x92 GITHUB.COM"
			//   → 所有归属比较全部失效。
			//   实测症状：GITHUB.COM 被判成「外部域名」。
			parts := strings.SplitN(item, " → ", 2)
			if len(parts) != 2 {
				continue
			}
			ip := parts[0]
			host := strings.ToLower(strings.TrimSuffix(parts[1], "."))
			// ⭐ 统一用 belongsTo（它内部做 lowercase + 结尾点处理）
			//   旧实现直接比 host == target，漏了大小写与子域两种情况
			if belongsTo(host) {
				continue
			}
			// 检查这个子域是否在 CT / 被动 DNS / 正向解析里出现过
			found := false
			if rep.CT != nil {
				for _, sb := range rep.CT.Subdomains {
					if strings.EqualFold(sb.Name, host) {
						found = true
						break
					}
				}
			}
			if !found && rep.Passive != nil {
				if _, ok := rep.Passive.Records[host]; ok {
					found = true
				}
			}
			if !found && rep.DNS != nil {
				if rep.DNS.Wildcard == "" {
					// 没有泛域名时，未在 CT/被动DNS 出现过的 PTR 域名值得注意
					// （但可能是外部域，不一定是自己的资产）
					if strings.HasSuffix(host, "."+target) {
						declaredNotInDNS = append(declaredNotInDNS, ip+" → "+host)
					}
				}
			}
		}
		if len(declaredNotInDNS) > 0 {
			ev := declaredNotInDNS
			if len(ev) > 8 {
				ev = ev[:8]
			}
			add("low", "rdns_only_subdomain",
				fmt.Sprintf("%d 个 PTR 声明的子域未出现在其他来源", len(declaredNotInDNS)),
				"这些子域出现在 IP 的 PTR 记录里，但**证书透明度、被动 DNS 都没有它**。\n"+
					"可能原因：① 内部系统（不对外签证书）② 已废弃的后端\n"+
					"  ③ 泛域名解析（若该域有泛域名，则此判断不可靠）",
				ev...)
		}

		// 汇总信息
		if withPTR > 0 {
			ev := append(append([]string{}, specificPtr...), genericPtr...)
			if len(ev) > 10 {
				ev = ev[:10]
			}
			level := "info"
			detail := "IP 持有者自己声明的身份。⭐ 注意区分：\n" +
				"  · 泛用名（ecs-1-2-3-4.compute.*）只说明是某台云主机，推不出站点\n" +
				"  · 具体域名（如 static.cdn.example.com）才是有价值的资产线索"
			if len(mismatched) > 0 {
				level = "medium"
			}
			add(level, "rdns_identity",
				fmt.Sprintf("%d/%d 个 IP 配置了 PTR 记录", withPTR, withPTR+noPTR),
				detail, ev...)
		}
		if noPTR > 0 && noPTR == withPTR+noPTR {
			add("info", "rdns_none",
				"所有 IP 都没有 PTR 记录",
				"这不是异常 —— 实测约 1/3 的公网 IP 没有 PTR（多数云厂商不默认配置）。\n"+
					"但也意味着：**无法通过 rDNS 确认这些 IP 的归属**，需要靠其他手段"+
					"（WHOIS/BGP/资产台账）。")
		}
	}

	// ── HTTP 指纹冲突相关 ──
	//
	// ⭐ 把 tech 模块的冲突检测结果转成 recon 的可行动发现。
	//   这样 `wukan recon x.com --ports 80,443 --tech` 一条命令就能
	//   拿到"资产 + 端口风险 + 指纹矛盾"三类结论。
	if rep.TechErr != "" {
		add("low", "tech_skipped", "HTTP 指纹采集未执行", rep.TechErr)
	} else if len(rep.TechConflicts) > 0 {
		// 统计各严重程度
		var high, medium, low []string
		for i, cr := range rep.TechConflicts {
			if cr == nil || len(cr.Conflicts) == 0 || i >= len(rep.Tech) {
				continue
			}
			url := rep.Target
			if rep.Tech[i] != nil {
				url = rep.Tech[i].URL
			}
			for _, c := range cr.Conflicts {
				line := fmt.Sprintf("%s — %s", shortURL(url), c.Title)
				switch c.Severity {
				case "high":
					high = append(high, line)
				case "medium":
					medium = append(medium, line)
				default:
					low = append(low, line)
				}
			}
		}

		// ⭐ 高危冲突单独提级（指纹矛盾指向的是被伪造/配置错误）
		if len(high) > 0 {
			add("high", "tech_conflict_high",
				fmt.Sprintf("HTTP 指纹存在 %d 处严重矛盾", len(high)),
				"多个独立来源（响应头 / TLS / favicon / 正文）对同一目标的描述互相冲突。\n"+
					"⭐ 这类矛盾通常意味着：响应头被伪造、证书配错、或前面有非预期的代理。\n"+
					"**不要直接采信任一方的结论** —— 先人工核实。",
				high...)
		}
		if len(medium) > 0 {
			add("medium", "tech_conflict",
				fmt.Sprintf("HTTP 指纹存在 %d 处需关注的矛盾", len(medium)),
				"已排除无意义的噪音（如 favicon 与 Server 头本就分属不同维度）。\n"+
					"剩下的矛盾一般指向：CDN 源站泄露、证书配置错误、Cookie 缺安全标志。",
				medium...)
		}
		if len(low) > 0 {
			// 低危不逐条报，避免噪音淹没重点
			add("info", "tech_conflict_low",
				fmt.Sprintf("另有 %d 处低优先级矛盾", len(low)),
				"这类矛盾通常来自 favicon 误报（图标只有几百字节，"+
					"不同应用共用图标必然碰撞）或过于宽松的版本声明。",
				low...)
		}

		// ⭐ 联动：指纹冲突 + 端口开放 = 源站暴露面判断
		if len(high) > 0 || len(medium) > 0 {
			var techPorts []string
			for _, t := range rep.Tech {
				if t == nil || t.Err != "" {
					continue
				}
				techPorts = append(techPorts, fmt.Sprintf("%d/tcp", t.Port))
			}
			if len(techPorts) > 0 {
				add("info", "tech_exposure",
					fmt.Sprintf("上述指纹均取自 %d 个开放 Web 端口", len(techPorts)),
					"这些端口是攻击者可以直接访问的入口。指纹矛盾意味着你看到的"+
						"可能不是全部真相（若前面有代理/网关）。",
					techPorts...)
			}
		}

		// 采集到的技术栈（即使无冲突也有价值）
		var techs []string
		for _, t := range rep.Tech {
			if t == nil || len(t.BodyKeywords) == 0 {
				continue
			}
			techs = append(techs, t.URL+": "+strings.Join(t.BodyKeywords, "/"))
		}
		if len(techs) > 0 {
			if len(techs) > 8 {
				techs = append(techs[:8], "…")
			}
			add("info", "tech_stack", "采集到技术栈特征", "来自正文关键词匹配（规则匹配，非 ML）。", techs...)
		}
	}

	// ── 被动 DNS 相关 ──
	if rep.Passive != nil && len(rep.Passive.Records) > 0 {
		histIPs := rep.Passive.AllIPs()
		histSubs := rep.Passive.Subdomains()

		// ⭐ 核心价值：历史 IP 与当前 IP 的差集
		//   "域现在解析到 A，历史上还解析过 B" —— 说明发生过迁移。
		//   B 可能已释放给别人，也可能是内部遗留基础设施。
		var currentIPs map[string]bool
		if rep.DNS != nil {
			currentIPs = make(map[string]bool, len(rep.DNS.IPs))
			for _, ip := range rep.DNS.IPs {
				currentIPs[ip] = true
			}
		}
		var staleIPs []string
		for _, ip := range histIPs {
			if !currentIPs[ip] {
				staleIPs = append(staleIPs, ip)
			}
		}
		if len(staleIPs) > 0 {
			ev := staleIPs
			if len(ev) > 10 {
				ev = ev[:10]
			}
			add("medium", "stale_passive_ip",
				fmt.Sprintf("发现 %d 个历史 IP 已不在当前解析中", len(staleIPs)),
				"⭐ 这些 IP 是该域**曾经**解析到的，现在不再使用。\n"+
					"可能含义：① 迁移后遗留（内部系统还指向老 IP）→ 真实风险；\n"+
					"           ② IP 已被释放转卖给他人 → 若上面跑着别的业务，与你无关；\n"+
					"           ③ 曾经做过后端切换但未清理 DNS。\n"+
					"建议：对这几个 IP 做 rDNS 与归属查询，确认是否还有残留服务。",
				ev...)
		}

		// ⭐ 被动 DNS 有、但 CT 与当前 DNS 都没有的子域
		//   这是"你不知道的、已经存在过的资产"
		if rep.CT != nil {
			ctNames := map[string]bool{}
			for _, sb := range rep.CT.Subdomains {
				ctNames[strings.ToLower(sb.Name)] = true
			}
			var onlyPassive []string
			for _, h := range histSubs {
				hl := strings.ToLower(h)
				if hl == strings.ToLower(rep.Target) || hl == "*."+hl {
					continue
				}
				if !ctNames[hl] {
					onlyPassive = append(onlyPassive, h)
				}
			}
			if len(onlyPassive) > 0 {
				ev := onlyPassive
				if len(ev) > 10 {
					ev = ev[:10]
				}
				add("medium", "passive_only_subdomain",
					fmt.Sprintf("%d 个子域只在被动 DNS 中出现（证书透明度无记录）", len(onlyPassive)),
					"⭐ 这些子域曾经解析过，但**没有签发过公开证书**。\n"+
						"这通常是：内网系统、不对外暴露的服务、或已废弃的后端。\n"+
						"它们比证书里的子域更'隐蔽'，因为没人给它们签过证书。",
					ev...)
			}
		}

		// IP 反查发现的同源资产
		for _, r := range rep.ReverseIP {
			if r == nil || len(r.Hostnames) == 0 {
				continue
			}
			// ⭐⭐ 抑制共享基础设施噪音（实测 2026-10-04 gitee.com）
			//
			// 反查 CDN/云厂商的共享 IP 会返回**上千个毫不相干的域名**：
			//   111.20.254.35 → 500 个主机名（0557.me / 06movie.com / 0735xty.zgyey.com…）
			//   112.45.27.158 → 500 个主机名（全是百度云 CDN 上的其他站）
			//
			// 这些不是"你不知道的资产"，而是"和别人共用的基础设施"。
			// 判定：主机数超过阈值（默认 50）→ 判为共享基础设施，不报。
			const sharedInfraThreshold = 50
			if len(r.Hostnames) > sharedInfraThreshold {
				add("info", "shared_infra",
					fmt.Sprintf("IP %s 是共享基础设施（%d 个虚拟主机，非本域资产）",
						r.IP, len(r.Hostnames)),
					"该 IP 承载了大量互不相关的域名，通常是 CDN 或云厂商的共享节点。"+
						"⭐ 关键含义：**对这类 IP 做端口扫描或指纹识别，得到的不是源站结果。**\n"+
						"要找源站需做 CDN 绕过：查历史 DNS 解析、证书历史、rDNS 反查。",
					fmt.Sprintf("反查返回 %d 个主机名，超过 %d 阈值，判定为共享基础设施",
						len(r.Hostnames), sharedInfraThreshold))
				continue
			}
			// 过滤掉属于自己的
			var others []string
			for _, h := range r.Hostnames {
				hl := strings.ToLower(h)
				if hl == strings.ToLower(rep.Target) ||
					strings.HasSuffix(hl, "."+strings.ToLower(rep.Target)) {
					continue
				}
				others = append(others, h)
			}
			if len(others) == 0 {
				continue
			}
			ev := others
			if len(ev) > 8 {
				ev = ev[:8]
			}
			add("info", "shared_ip",
				fmt.Sprintf("IP %s 上还挂着 %d 个不属于本域的域名", r.IP, len(others)),
				"共享主机 / CDN 回源 / 云主机的典型特征。\n"+
					"如果是共享主机，这些域与你无关；如果是自有服务器，说明上面跑着"+
					"**你不知道的站点** —— 值得确认归属。",
				ev...)
		}

		// 数据源失败提示
		if len(rep.Passive.SourcesFailed) > 0 {
			var reasons []string
			for src, e := range rep.Passive.SourcesFailed {
				reasons = append(reasons, src+": "+e)
			}
			sort.Strings(reasons)
			add("low", "passive_partial",
				"被动 DNS 数据源部分失败",
				"被动 DNS 的价值在于发现「已下线但仍可注册」的资产，"+
					"数据源不可用会漏掉这部分。建议稍后重试（免费额度 50 次/天）。",
				reasons...)
		}
	}

	// ── QUIC 相关 ──
	if len(rep.QUIC) > 0 {
		var confirmed []quic.Result
		for _, q := range rep.QUIC {
			if q.IsQUIC() {
				confirmed = append(confirmed, q)
			}
		}
		if len(confirmed) > 0 {
			// ⭐ 核心价值：找出"QUIC 存活但 TCP/443 不可达"的资产
			//    这是所有 TCP-only 扫描器的系统性盲区
			var quicOnly []string
			for i := range confirmed {
				if !tcpReachable(rep, confirmed[i].Host) {
					quicOnly = append(quicOnly, confirmed[i].Host)
				}
			}
			if len(quicOnly) > 0 {
				add("high", "quic_only",
					fmt.Sprintf("发现 %d 个「只开放 QUIC」的资产", len(quicOnly)),
					"⭐⭐ **这是传统扫描器的系统性盲区。**\n\n"+
						"这些资产的 UDP/443 上运行 HTTP/3，但 TCP/443 关闭。\n"+
						"→ naabu / httpx / Shodan / Censys / ZMap / masscan **全部看不到它们**，"+
						"因为这些工具只扫 TCP。\n\n"+
						"可能的影响：\n"+
						"  ① 你的资产台账漏掉了这些入口\n"+
						"  ② 蓝队/WAF 规则可能未覆盖 HTTP/3 流量\n"+
						"  ③ 若它们配置不当但仍可访问，就是绕过入口\n\n"+
						"建议：用浏览器（支持 HTTP/3）访问确认，或用 curl --http3 验证。",
					quicOnly...)
			} else {
				add("info", "quic_alive",
					fmt.Sprintf("%d 个 IP 的 UDP/443 运行 QUIC/HTTP/3", len(confirmed)),
					"这些 IP 同时支持 TCP 与 QUIC。\n"+
						"注意：QUIC 加密了传输层头部，**基于四元组的网络行为检测会失效**"+
						"（连接用 CID 而非四元组标识）。",
					quicIPList(confirmed)...)
			}
		}
	}

	// ── IP 归属相关 ──
	// ⭐ 同一个 IP 可能同时有 cloud 与 hosting 标签（两标签由不同依据产生），
	//   所以收集证据时必须去重，否则同一个 IP 会在报告里出现两次
	//   （实测 github.com 的 20.205.243.166 重复出现）。
	//   ⭐ 同时区分可信度：cloud/cdn 来自 org 关键字匹配（可靠），
	//   hosting 来自上游 API（可能误报），分开报避免混淆。
	var cdnIPs, cloudIPs, hostingIPs []string
	for _, ip := range rep.IPInfo {
		if ip == nil || !ip.Valid {
			continue
		}
		isCDN, isCloud, isHosting := false, false, false
		for idx, f := range ip.Flags {
			// 依据为 ip-api.com 的标签可信度较低，单独归类
			fromAPI := idx < len(ip.FlagSources) && ip.FlagSources[idx] == "ip-api.com"
			switch f {
			case "cdn":
				isCDN = true
			case "cloud":
				if !fromAPI {
					isCloud = true
				} else {
					isHosting = true
				}
			case "hosting":
				isHosting = true
			}
		}
		if isCDN {
			cdnIPs = append(cdnIPs, ip.IP)
		}
		if isCloud && !isCDN {
			cloudIPs = append(cloudIPs, ip.IP)
		}
		if isHosting && !isCDN && !isCloud {
			hostingIPs = append(hostingIPs, ip.IP)
		}
	}
	cdnIPs = dedupeStrings(cdnIPs)
	cloudIPs = dedupeStrings(cloudIPs)
	hostingIPs = dedupeStrings(hostingIPs)

	if len(cdnIPs) > 0 {
		add("medium", "cdn_detected",
			fmt.Sprintf("检测到 CDN 边缘节点（%d 个 IP）", len(cdnIPs)),
			"⭐ 关键：CDN 边缘 IP 会让端口扫描结果失真 —— "+
				"你以为扫的是源站，实际扫的是 CDN 边缘节点。\n"+
				"要找源站需做 CDN 绕过：查历史 DNS 解析、证书历史、rDNS 反查。",
			cdnIPs...)
	}
	if len(cloudIPs) > 0 {
		add("low", "cloud_detected",
			fmt.Sprintf("IP 属于云服务商（%d 个）", len(cloudIPs)),
			"云主机通常有安全组控制，暴露面受网络策略限制。"+
				"（此标签来自 ISP/org 名称匹配，可靠）",
			cloudIPs...)
	}
	if len(hostingIPs) > 0 {
		add("info", "hosting_detected",
			fmt.Sprintf("%d 个 IP 被标记为数据中心/云主机", len(hostingIPs)),
			"该标签来自第三方 API 判定，**可能误报**（实测 114DNS 这类公共 DNS 会被误标）。"+
				"仅作提示，使用前请核实。",
			hostingIPs...)
	}

	// ── 子域技术栈差异（子域批量探测的独特价值）──
	//
	// ⭐ 只探根域会漏掉的关键信息：
	//   同一个域下，不同子域可能跑着**完全不同的技术栈**。
	//   实测 github.com：emails 用 cloudflare、mailing 用 nginx、
	//   其余用 github.com 自建 —— 三种不同的栈与安全配置。
	//   这类差异往往是配置漂移或历史遗留，是真实的安全问题。
	if len(rep.Tech) > 1 {
		stacks := map[string][]string{}
		var order []string
		for _, t := range rep.Tech {
			if t == nil || t.Err != "" || t.StatusCode == 0 {
				continue
			}
			tech := strings.Join(t.BodyKeywords, "/")
			if t.Server == "" && tech == "" {
				continue
			}
			// 栈标签：Server + 正文特征
			label := t.Server
			if label == "" {
				label = "未知服务器"
			}
			if tech != "" {
				label += " + " + tech
			}
			if _, ok := stacks[label]; !ok {
				order = append(order, label)
			}
			stacks[label] = append(stacks[label], shortURL(t.URL))
		}

		// 只报告出现 ≥2 次的栈（出现 1 次的不算"系统性差异"）
		var lines []string
		for _, label := range order {
			hosts := stacks[label]
			if len(hosts) < 2 {
				continue
			}
			names := hosts
			if len(names) > 4 {
				names = append(names[:4:4], "…")
			}
			lines = append(lines, fmt.Sprintf("%d 个 [%s]: %s",
				len(hosts), label, strings.Join(names, ", ")))
		}

		if len(lines) > 0 {
			// ⭐ 降序：按数字大小排，不能按字符串（"3" < "2" 会排错）
			sort.SliceStable(lines, func(i, j int) bool {
				return leadingInt(lines[i]) > leadingInt(lines[j])
			})
			add("info", "subdomain_stack_diversity",
				fmt.Sprintf("子域技术栈存在 %d 种不同配置", len(lines)),
				"⭐ 同一个域下不同子域跑着不同的服务器软件 / 技术栈。\n"+
					"这在实践中通常意味着：配置漂移、历史遗留、或多团队各自部署。\n"+
					"⭐ 安全含义：**你对根域做的加固不代表对子域同样生效** —— "+
					"子域可能有完全不同的漏洞暴露面。\n"+
					"建议：对每一类栈单独确认版本与补丁状态。",
				lines...)
		}
	}

	// ── 端口扫描相关 ──
	if rep.PortsErr != "" {
		add("high", "ports_denied", "端口扫描未执行", rep.PortsErr)
	} else if len(rep.Ports) > 0 {
		var open []portscan.PortResult
		ps := portscan.Summarize(rep.Ports)
		for _, p := range rep.Ports {
			if p.Open() {
				open = append(open, p)
			}
		}

		if len(open) == 0 {
			add("low", "no_open_ports",
				fmt.Sprintf("扫描 %d 个端口，全部未开放", ps.Total),
				"在指定端口范围内没有发现开放服务。\n"+
					"可能原因：① 服务在未扫描的端口上；② 被防火墙过滤（表现为 filtered）；"+
					"③ 该 IP 是 CDN 边缘或已下线。\n"+
					"提示：filtered 状态无法区分「被丢掉的开放端口」与「不存在的端口」。")
		} else {
			// ⭐ 风险端口识别（这是端口扫描最有价值的输出）
			var risky []string
			var admin []string
			for _, p := range open {
				tag := portRisk(p.Port, p.Service, p.Banner)
				switch tag {
				case "risk":
					risky = append(risky, fmt.Sprintf("%d/tcp %s %s", p.Port,
						dashOr(p.Service), p.Banner))
				case "admin":
					admin = append(admin, fmt.Sprintf("%d/tcp %s", p.Port, dashOr(p.Service)))
				}
			}
			if len(risky) > 0 {
				add("high", "risky_ports",
					fmt.Sprintf("发现 %d 个高风险端口直接暴露在公网", len(risky)),
					"⭐ 这些端口一旦被利用，后果通常是**数据泄露或系统控制**。\n"+
						"典型风险源：数据库（MySQL/Postgres/Mongo/Redis）"+
						"可被直接访问或弱口令；"+
						"远程管理（RDP/VNC）常是勒索软件入口。\n"+
						"建议：① 改绑内网或走跳板机 ② 限制来源 IP ③ 检查是否有弱口令",
					risky...)
			}
			if len(admin) > 0 {
				add("medium", "admin_ports",
					fmt.Sprintf("发现 %d 个管理/运维端口", len(admin)),
					"这些端口本应限制访问。暴露在公网意味着攻击者可以直接尝试凭据。\n"+
						"建议：限制来源 IP，或改用 VPN/堡垒机访问。",
					admin...)
			}

			// ⭐ 低置信度端口（可能是 honeypot 或特殊握手服务）
			var lowConf []string
			for _, p := range open {
				if p.Confidence < 70 {
					lowConf = append(lowConf, fmt.Sprintf("%d/tcp conf=%d %s",
						p.Port, p.Confidence, dashOr(p.Banner)))
				}
			}
			if len(lowConf) > 0 {
				add("low", "low_confidence_ports",
					fmt.Sprintf("%d 个开放端口缺少可识别特征", len(lowConf)),
					"这些端口开放但没抓到任何可识别的 banner。可能是：\n"+
						"  · 需要特定握手才响应的服务（如 SMTP 要先发数据）\n"+
						"  · 蜜罐 / honeypot（故意伪装成高价值服务诱导攻击）\n"+
						"  · 非标准协议\n"+
						"建议人工确认 —— **如果这是你自己的资产**，蜜罐的存在也值得知道。",
					lowConf...)
			}

			// ⭐ 端口 × CDN 的矛盾（联动判定）
			if len(cdnIPs) > 0 || len(cloudIPs) > 0 {
				var onShared []string
				for _, p := range open {
					if isSharedIP(p.IP, cdnIPs, cloudIPs, hostingIPs) {
						onShared = append(onShared, fmt.Sprintf("%d/tcp on %s", p.Port, p.IP))
					}
				}
				if len(onShared) > 0 {
					add("medium", "ports_on_shared_ip",
						fmt.Sprintf("%d 个开放端口位于 CDN/云节点上", len(onShared)),
						"⭐ 关键判读：这些端口的扫描结果反映的是 **CDN 边缘或云节点的行为**，"+
							"不是你的源站。\n"+
							"常见情况：边缘节点会统一回应 80/443，把所有站点都表现为「开放」。\n"+
							"要摸清源站的真实暴露面，必须先做 CDN 绕过。",
						onShared...)
				}
			}

			// 正常情况：列出开放端口作为信息
			if len(risky) == 0 && len(admin) == 0 {
				var list []string
				for _, p := range open {
					list = append(list, fmt.Sprintf("%d/tcp %s %s", p.Port,
						dashOr(p.Service), truncateS(p.Banner, 30)))
				}
				if len(list) > 10 {
					list = append(list[:10], fmt.Sprintf("…(共 %d 个)", len(open)))
				}
				add("info", "open_ports",
					fmt.Sprintf("发现 %d 个开放端口（未发现高风险端口）", len(open)),
					"在指定端口范围内的开放服务清单。这是资产台账的基本项。", list...)
			}
		}
	}

	// ── 数据源失败提示 ──
	if rep.CT != nil && len(rep.CT.Subdomains) == 0 && len(rep.CT.SourcesFailed) > 0 {
		var reasons []string
		for src, err := range rep.CT.SourcesFailed {
			reasons = append(reasons, src+": "+err)
		}
		sort.Strings(reasons)
		add("low", "ct_unavailable",
			"证书透明度数据源全部不可用",
			"子域收集未完成。可稍后重试或手动访问 crt.sh 查询。",
			reasons...)
	}

	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// LevelIcon 返回严重程度图标
func LevelIcon(level string) string {
	switch level {
	case "high":
		return "🔴"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	default:
		return "ℹ️"
	}
}

// thirdPartyToken 判断 TXT 值是否是第三方平台验证 token
//
// ⭐ 实测发现的模式（2026-10-04，github.com 的 18 条 TXT）：
//
//	shopify-verification-code=xxx
//	stripe-verification=xxx
//	facebook-domain-verification=xxx
//	google-site-verification=xxx
//	loom-site-verification=xxx
//	miro-verification=xxx
//
// 这些都是「域名所有权验证」凭据。不该出现在公开 DNS 里。
var tokenPrefixes = []string{
	"shopify-verification", "stripe-verification",
	"facebook-domain-verification", "google-site-verification",
	"goog-site-verification", "ms=ms", "msdomain",
	"loom-site-verification", "miro-verification",
	"cisco-ci-domain-verification", "atlassian-domain-verification",
	"adobe-idp-site-verification", "docusign-domain-verification",
	"dropbox-domain-verification", "zoom-domain-verification",
	"slack-domain-verification", "hubspot-domain-verification",
	"openai-domain-verification", "apple-domain-verification",
	"brave-ledger-verification", "gitlab-verification",
	"linear-domain-verification", "notion-domain-verification",
	"discord-domain-verification", "twilio-domain-verification",
	"bitbucket-domain-verification", "pantheon-domain-verification",
	"cloudflare-domain-verification", "fastly-domain-verification",
	"statuspage-domain-verification", "newrelic-domain-verification",
	"datadog-domain-verification", "segment-domain-verification",
	"intercom-domain-verification", "zendesk-domain-verification",
	"sendgrid-domain-verification", "mailgun-domain-verification",
	"postmark-domain-verification", "sparkpost-domain-verification",
	"brave-search-verification", "yandex-domain-verification",
	"twitter-domain-verification", "linkedin-domain-verification",
	"tiktok-domain-verification", "pinterest-domain-verification",
	"bitly-domain-verification", "wistia-domain-verification",
	"youtube-domain-verification", "facebook-domain-verification",
}

func thirdPartyToken(txt string) string {
	l := strings.ToLower(txt)
	for _, p := range tokenPrefixes {
		if strings.Contains(l, p) {
			// 只返回前缀（不打印 token 全文，避免把凭据写进报告）
			if i := strings.IndexAny(txt, "=:"); i > 0 {
				return txt[:i] + "=***（已隐藏）"
			}
			return p
		}
	}
	return ""
}

// tcpReachable 判断该 IP 是否在当前 TCP 解析结果中
func tcpReachable(rep *Report, ip string) bool {
	if rep == nil || rep.DNS == nil {
		return false
	}
	for _, cur := range rep.DNS.IPs {
		if cur == ip {
			return true
		}
	}
	return false
}

func quicIPList(rs []quic.Result) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		line := r.Host
		if r.StackHint != "" {
			line += " (" + r.StackHint + ")"
		}
		if r.Confidence > 0 && r.Confidence < 100 {
			line += fmt.Sprintf(" conf=%d", r.Confidence)
		}
		out = append(out, line)
	}
	return out
}

// portRisk 判断端口的风险等级
//
// ⭐ 依据：端口开放时的**默认后果**，不是端口号本身的高低。
//
//	数据库端口直接暴露 = 数据可能被拖库，这是最高危的一类。
//	远程管理端口 = 弱口令即可拿下主机，是勒索软件的主要入口。
//
// ⭐ 不判断的：80/443 等 Web 端口本身不是风险
//
//	（暴露 Web 服务是正常的），风险在应用层，不在端口层。
func portRisk(port int, service, banner string) string {
	// 高危：数据库（直接暴露 = 数据泄露）
	switch port {
	case 3306, 5432, 27017, 6379, 9200, 9300, 5984, 9042, 1433, 1521, 8529:
		return "risk"
	}
	// 高危：文件/对象存储管理
	switch port {
	case 9000, 9001: // MinIO / PHP-FPM
		return "risk"
	case 15672, 25672: // RabbitMQ 管理台
		return "risk"
	}
	// 中危：远程管理与运维
	switch port {
	case 3389, 3390, 5900, 5901, 5800, 22, 23, 21, 445, 139:
		return "admin"
	case 9090, 9100, 5601, 15672, 4848: // 监控/控制台
		return "admin"
	}
	// 其他常见数据库端口（用服务名兜底）
	s := strings.ToLower(service)
	if strings.Contains(s, "mysql") || strings.Contains(s, "postgres") ||
		strings.Contains(s, "mongo") || strings.Contains(s, "redis") ||
		strings.Contains(s, "elasticsearch") || strings.Contains(s, "mssql") {
		return "risk"
	}
	// banner 里出现数据库特征
	bl := strings.ToLower(banner)
	if strings.Contains(bl, "mysql") || strings.Contains(bl, "postgresql") ||
		strings.Contains(bl, "mongodb") {
		return "risk"
	}
	return ""
}

func isSharedIP(ip string, cdn, cloud, hosting []string) bool {
	for _, s := range cdn {
		if s == ip {
			return true
		}
	}
	for _, s := range cloud {
		if s == ip {
			return true
		}
	}
	return false
}

func dashOr(s string) string {
	if s == "" {
		return "-"
	}
	return s
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

// techTarget 一条 tech 探测目标
type techTarget struct {
	// URL 实际请求的 URL（可能是 IP:端口，也可能是域名）
	URL string
	// HostHeader HTTP Host 头（IP 访问时送域名）
	HostHeader string
	// Label 报告中显示的名称
	Label string
	// IsSubdomain 是否是子域（不是根域）
	IsSubdomain bool
}

// techTargets 选取要跑 tech 探测的目标
//
// ⭐⭐ 三层目标来源（按优先级）：
//
//	① 根域的每个 CDN 节点（用 IP:端口 + 域名 Host 头）
//	   —— 逐节点探测，能发现边缘节点配置不一致
//	② ⭐ CT + 被动 DNS 发现的**存活子域**（用子域名 + 子域自己的 IP）
//	   —— 这是"覆盖整个攻击面"的关键：子域往往跑着不同的应用、
//	      不同的中间件、不同的安全配置
//	③ 无端口/子域数据时退化为根域探测
//
// ⚠️ 子域必须用**它自己的 IP + 它自己的域名**：
//
//	用根域的 IP 探子域会拿到错误站点（CDN 按 Host 路由）。
//	根域的 URL 结构是「IP + 根域名」，子域是「IP + 子域名」，两者不能混。
func (r *Runner) techTargets(rep *Report) []techTarget {
	var out []techTarget
	seen := map[string]bool{}

	webPorts := map[int]bool{80: true, 443: true, 8080: true, 8443: true,
		8000: true, 8888: true, 3000: true, 5000: true, 9000: true}

	schemeOf := func(port int) string {
		if port == 443 || port == 8443 {
			return "https"
		}
		return "http"
	}

	// ① 根域：每个 CDN 节点探一次
	if len(rep.Ports) > 0 {
		perIP := map[string]int{}
		for _, p := range rep.Ports {
			if !p.Open() || !webPorts[p.Port] {
				continue
			}
			if cur, ok := perIP[p.IP]; !ok || p.Port < cur {
				perIP[p.IP] = p.Port
			}
		}
		ips := make([]string, 0, len(perIP))
		for ip := range perIP {
			ips = append(ips, ip)
		}
		sort.Strings(ips) // 稳定输出，便于多次运行 diff
		for _, ip := range ips {
			port := perIP[ip]
			u := fmt.Sprintf("%s://%s:%d", schemeOf(port), ip, port)
			if seen[u] {
				continue
			}
			seen[u] = true
			out = append(out, techTarget{
				URL:        u,
				HostHeader: rep.Target, // ⭐ IP 访问必须送根域名
				Label:      rep.Target,
			})
		}
	}

	// ② ⭐ 子域：用子域名 + 子域自己的 IP
	subCount := 0
	if r.opt.TechSubdomains && rep.CT != nil {
		for _, sb := range rep.CT.Subdomains {
			if r.opt.TechSubMax > 0 && subCount >= r.opt.TechSubMax {
				break
			}
			// 跳过通配符（不是可访问的资产）与不解析的（探测无意义）
			if sb.IsWildcard || !sb.Resolves || len(sb.ResolveIPs) == 0 {
				continue
			}
			// 根域已单独探测，跳过
			if strings.EqualFold(sb.Name, rep.Target) {
				continue
			}
			// ⭐ 优先用 https（更常见且信息更丰富），无 https 则试 http
			ip := sb.ResolveIPs[0]
			u := fmt.Sprintf("https://%s", sb.Name)
			if seen[u] {
				continue
			}
			seen[u] = true
			out = append(out, techTarget{
				URL:         u,
				HostHeader:  sb.Name, // ⭐ 子域用自己的域名作 Host
				Label:       sb.Name,
				IsSubdomain: true,
			})
			_ = ip // 保留：若需强制走 IP 探测时用
			subCount++
		}
	}

	// ③ 兜底：没有任何目标时探根域
	if len(out) == 0 && rep.DNS != nil {
		out = append(out,
			techTarget{URL: "https://" + rep.Target, HostHeader: rep.Target,
				Label: rep.Target},
			techTarget{URL: "http://" + rep.Target, HostHeader: rep.Target,
				Label: rep.Target},
		)
	}

	// ④ 限量（根域优先，子域其次）
	if r.opt.TechMaxTargets > 0 && len(out) > r.opt.TechMaxTargets {
		out = out[:r.opt.TechMaxTargets]
	}
	return out
}

// probeTechTargets 执行 tech 探测，按 Host 头分组
//
// ⭐ 为什么要分组：不同目标的 Host 头不同（根域 CDN 节点用根域名、
//
//	各子域用各自域名），而 httpprobe 的 HostHeader 是配置级而非请求级。
//	所以按 Host 头分组，每组一个 Prober。
//
// ⭐ 为什么要并发：子域可能有几十个，逐个串行太慢。
//
//	但**分组内串行、组间并发**，避免单个 Host 打太多请求。
func (r *Runner) probeTechTargets(targets []techTarget) []*httpprobe.ProbeResult {
	// 按 HostHeader 分组，保留首次出现顺序（稳定输出，便于多次运行 diff）
	var order []string
	groups := map[string][]int{} // host → targets 里的下标
	for i, t := range targets {
		h := t.HostHeader
		if _, ok := groups[h]; !ok {
			order = append(order, h)
		}
		groups[h] = append(groups[h], i)
	}

	results := make([]*httpprobe.ProbeResult, len(targets))
	var wg sync.WaitGroup

	// 组间并发（限制 4 组并行，避免瞬时请求过多）
	sem := make(chan struct{}, 4)
	for _, host := range order {
		idxs := groups[host]
		wg.Add(1)
		go func(h string, idx []int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			tcfg := httpprobe.DefaultConfig()
			tcfg.Timeout = r.opt.TechTimeout
			tcfg.Concurrency = r.opt.TechConcurrency
			tcfg.GrabFavicon = !r.opt.TechNoFavicon
			tcfg.RetryFallback = r.opt.TechRetryFallback // ⭐ 失败降级重试
			tcfg.HostHeader = h                          // ⭐ 本组统一的 Host 头
			tcfg.Cache = r.opt.TechCache                 // ⭐ 传入缓存

			urls := make([]string, len(idx))
			for k, i := range idx {
				urls[k] = targets[i].URL
			}
			prober := httpprobe.New(tcfg)
			rs := prober.ProbeURLs(urls, nil)

			// ⭐ 各组写自己独占的下标，无需加锁
			for k, i := range idx {
				if k < len(rs) {
					results[i] = rs[k]
				}
			}
		}(host, idxs)
	}
	wg.Wait()
	return results
}

// shortURL 去掉 scheme 前缀，让报告更紧凑
func shortURL(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	return u
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// leadingInt 取字符串开头的数字（用于 "12 个 [x]: ..." 这类计数排序）
func leadingInt(s string) int {
	n := 0
	found := false
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			if found {
				break
			}
			continue
		}
		found = true
		n = n*10 + int(s[i]-'0')
	}
	return n
}
