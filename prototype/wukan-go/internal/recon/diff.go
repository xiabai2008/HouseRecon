package recon

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// ⭐⭐ 快照差异引擎（P1-1）
//
// 设计纪律（对齐项目"零假阳性"原则）：
//  1. 只比较**稳定字段** —— banner（含时间戳/主机名等动态内容）结构性排除，
//     快照类型里根本没有 banner 字段
//  2. **单侧为空的字段不参与比较** —— 识别能力变化 ≠ 资产变化
//     （比如这次没抓到 Server 头，不等于 Server 变了）
//  3. **覆盖范围不同不比增删** —— "不在快照里"可能是"本次没采"，
//     按类别做覆盖门控，不可比时输出 coverage_changed（审查发现的 H1）
//  4. **CDN 节点轮换不是暴露面变化** —— 同一端口随解析 IP 移动时
//     归并为 port_ip_changed（low），而不是 port_added(high)+port_removed
//  5. 归一化先行（与 recon 共用 NormalizeTarget），避免格式差异被当成变化
//  6. 每条变化必须带判读（Detail）—— 只报"变了"不给"意味着什么"等于没报
//     （有测试固化：TestDiffSnapshots_EveryChangeHasDetail）

// 变化类型
const (
	ChangeSubdomainAdded     = "subdomain_added"
	ChangeSubdomainRemoved   = "subdomain_removed"
	ChangeIPAdded            = "ip_added"
	ChangeIPRemoved          = "ip_removed"
	ChangePortAdded          = "port_added"
	ChangePortRemoved        = "port_removed"
	ChangePortServiceChanged = "port_service_changed"
	ChangePortIPChanged      = "port_ip_changed"
	ChangeTechStatusChanged  = "tech_status_changed"
	ChangeTechServerChanged  = "tech_server_changed"
	ChangeTechFaviconChanged = "tech_favicon_changed"
	ChangeTechTitleChanged   = "tech_title_changed"
	ChangeTechJARMChanged    = "tech_jarm_changed"
	ChangeTechH2Changed      = "tech_h2_changed"
	ChangeCoverageChanged    = "coverage_changed"
)

// 覆盖类别（coverage_changed 的 Target 取值）
const (
	CoverageCategorySubdomains = "subdomains"
	CoverageCategoryIPs        = "ips"
	CoverageCategoryPorts      = "ports"
	CoverageCategoryTech       = "tech"
)

// Change 一条资产变化
type Change struct {
	Kind  string `json:"kind"`
	Level string `json:"level"` // high / medium / low / info
	// Target 受影响资产（子域名 / IP / ip:port / URL / 覆盖类别）
	Target string `json:"target"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
	// Detail 判读：这条变化意味着什么、该做什么
	Detail string `json:"detail"`
}

// SnapshotDiff 两次快照之间的差异
type SnapshotDiff struct {
	Target  string    `json:"target"`
	PrevAt  time.Time `json:"prev_at"`
	CurrAt  time.Time `json:"curr_at"`
	Changes []Change  `json:"changes,omitempty"`
}

// AlertCount 可告警的变化数
//
// ⭐ coverage_changed 是"不可比说明"（数据源失败/参数变化），不是资产变化 ——
//
//	不计入告警信号，否则一次数据源抖动会导致每轮监控都误报。
func (d *SnapshotDiff) AlertCount() int {
	if d == nil {
		return 0
	}
	n := 0
	for _, c := range d.Changes {
		if c.Kind != ChangeCoverageChanged {
			n++
		}
	}
	return n
}

// IsEmpty 是否无变化
func (d *SnapshotDiff) IsEmpty() bool {
	return d == nil || len(d.Changes) == 0
}

// DiffSnapshots 计算两次快照的差异
//
// 输入非法（nil / 不同目标）时返回 nil —— 调用方负责展示"无对比基准"。
// 不同目标绝不能互相 diff：那会把两个无关资产的差异报成"变化"。
func DiffSnapshots(prev, curr *Snapshot) *SnapshotDiff {
	if prev == nil || curr == nil {
		return nil
	}
	if NormalizeTarget(prev.Target) != NormalizeTarget(curr.Target) {
		return nil
	}
	d := &SnapshotDiff{
		Target: NormalizeTarget(curr.Target),
		PrevAt: prev.TakenAt,
		CurrAt: curr.TakenAt,
	}

	// ── 覆盖率门控（H1）──
	//
	// ⭐ 每个类别只在"两侧都完整采集"时才做增删判定；
	//   一侧完整、另一侧缺失时输出 coverage_changed（不可比）。
	//   两侧都缺失 → 静默（本来就没采这类数据，无可比性也无误导）。
	ipsOK := prev.Coverage.DNS && curr.Coverage.DNS
	subOK := prev.Coverage.SubdomainsOK() && curr.Coverage.SubdomainsOK()
	portsOK := prev.Coverage.Ports && curr.Coverage.Ports
	specSame := prev.Coverage.PortsSpec == curr.Coverage.PortsSpec
	techOK := prev.Coverage.Tech && curr.Coverage.Tech

	if ipsOK {
		diffStringSets(prev.IPs, curr.IPs, ChangeIPAdded, ChangeIPRemoved, d)
	} else if prev.Coverage.DNS != curr.Coverage.DNS {
		d.Changes = append(d.Changes, coverageChange(CoverageCategoryIPs,
			prev.Coverage.DNS, curr.Coverage.DNS))
	}

	if subOK {
		diffStringSets(prev.Subdomains, curr.Subdomains,
			ChangeSubdomainAdded, ChangeSubdomainRemoved, d)
	} else if prev.Coverage.SubdomainsOK() != curr.Coverage.SubdomainsOK() {
		d.Changes = append(d.Changes, coverageChange(CoverageCategorySubdomains,
			prev.Coverage.SubdomainsOK(), curr.Coverage.SubdomainsOK()))
	}

	switch {
	case portsOK && specSame:
		diffPorts(prev, curr, d)
	case portsOK && !specSame:
		// 参数不同 → 扫描集合不可比
		ch := coverageChange(CoverageCategoryPorts, true, true)
		ch.Before = prev.Coverage.PortsSpec
		ch.After = curr.Coverage.PortsSpec
		ch.Detail = "端口扫描参数与基准不同（" + prev.Coverage.PortsSpec + " → " +
			curr.Coverage.PortsSpec + "），两次扫描的端口集合不可比。" +
			"请用相同参数重跑后再对比。"
		d.Changes = append(d.Changes, ch)
	case prev.Coverage.Ports != curr.Coverage.Ports:
		d.Changes = append(d.Changes, coverageChange(CoverageCategoryPorts,
			prev.Coverage.Ports, curr.Coverage.Ports))
	}

	if techOK {
		diffTech(prev, curr, d)
	} else if prev.Coverage.Tech != curr.Coverage.Tech {
		d.Changes = append(d.Changes, coverageChange(CoverageCategoryTech,
			prev.Coverage.Tech, curr.Coverage.Tech))
	}

	sortChanges(d.Changes)
	return d
}

// coverageChange 生成一条"覆盖不可比"说明
func coverageChange(category string, prevOK, currOK bool) Change {
	label := map[string]string{
		CoverageCategorySubdomains: "子域（证书透明度/被动 DNS）",
		CoverageCategoryIPs:        "解析 IP（DNS）",
		CoverageCategoryPorts:      "端口扫描",
		CoverageCategoryTech:       "HTTP 指纹采集",
	}[category]
	if label == "" {
		label = category
	}
	return Change{
		Kind:   ChangeCoverageChanged,
		Level:  "info",
		Target: category,
		Before: coverageText(prevOK),
		After:  coverageText(currOK),
		Detail: "本次与基准的「" + label + "」覆盖情况不同（数据源失败、限额或运行参数变化），" +
			"该类别的增删差异不可比，已跳过判定。建议确保数据源可用、参数一致后重跑再对比。",
	}
}

func coverageText(ok bool) string {
	if ok {
		return "完整"
	}
	return "不完整"
}

// diffStringSets 集合差异（子域 / IP 通用）
func diffStringSets(prev, curr []string, addedKind, removedKind string, d *SnapshotDiff) {
	p := normSet(prev)
	c := normSet(curr)
	for name := range c {
		if !p[name] {
			d.Changes = append(d.Changes, changeFor(addedKind, name))
		}
	}
	for name := range p {
		if !c[name] {
			d.Changes = append(d.Changes, changeFor(removedKind, name))
		}
	}
}

func normSet(items []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range items {
		if n := NormalizeTarget(s); n != "" {
			m[n] = true
		}
	}
	return m
}

// diffPorts 端口差异（含 IP 轮换归并与扫描集门控）
func diffPorts(prev, curr *Snapshot, d *SnapshotDiff) {
	// ⭐ H5 修复：只有**两次都扫描过**的 IP 上的"纯新增/纯消失"才可信 ——
	//   子域选择集/解析 IP 漂移时，未共同扫描的 IP 上"新出现"的端口
	//   不能断言是新暴露（可能一直开着，只是上次没扫）。
	//   例外：同端口跨 IP 的"轮换"（CDN 节点移动）仍归并为低危提示。
	prevIPs := map[string]bool{}
	for _, ip := range prev.Coverage.PortsIPs {
		prevIPs[ip] = true
	}
	currIPs := map[string]bool{}
	for _, ip := range curr.Coverage.PortsIPs {
		currIPs[ip] = true
	}
	prevHasPorts := len(prev.OpenPorts) > 0
	currHasPorts := len(curr.OpenPorts) > 0
	if (len(prevIPs) == 0 && prevHasPorts) || (len(currIPs) == 0 && currHasPorts) {
		// 缺少扫描集记录（旧格式快照，且确实有端口要对比）→ 不可比
		ch := coverageChange(CoverageCategoryPorts, true, true)
		ch.Detail = "缺少扫描主机集合记录（旧格式快照），端口差异不可比。" +
			"用新版本重跑一次即可恢复对比。"
		d.Changes = append(d.Changes, ch)
		return
	}
	if !prevHasPorts && !currHasPorts {
		return // 两边都没有开放端口可对比，静默
	}
	common := map[string]bool{}
	for ip := range prevIPs {
		if currIPs[ip] {
			common[ip] = true
		}
	}

	p := portMap(prev.OpenPorts)
	c := portMap(curr.OpenPorts)

	var added, removed []string
	for key := range c {
		if _, ok := p[key]; !ok {
			added = append(added, key)
		}
	}
	for key := range p {
		if _, ok := c[key]; !ok {
			removed = append(removed, key)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)

	// ⭐ IP 轮换归并：新增端口与消失端口的**端口号相同、服务兼容**时，
	//   更可能是 CDN 节点轮换/迁移（example.com 这类域名每轮解析都在变），
	//   归并为一条 port_ip_changed（low），而不是 port_added(high) 误导用户。
	//   轮换判定不受"共同扫描 IP"门控限制（它本身就是跨 IP 的解释）。
	usedRemoved := map[string]bool{}
	suppressed := 0
	for _, ak := range added {
		ap := c[ak]
		match := ""
		for _, rk := range removed {
			if usedRemoved[rk] {
				continue
			}
			rp := p[rk]
			if rp.Port == ap.Port && serviceCompatible(rp.Service, ap.Service) {
				match = rk
				break
			}
		}
		if match != "" {
			usedRemoved[match] = true
			ch := changeFor(ChangePortIPChanged, ak)
			ch.Before = match
			ch.After = ak
			d.Changes = append(d.Changes, ch)
			continue
		}
		// 纯新增：仅在"共同扫描过"的 IP 上才可信
		if common[portHostOf(ak)] {
			d.Changes = append(d.Changes, changeFor(ChangePortAdded, ak))
		} else {
			suppressed++
		}
	}
	for _, rk := range removed {
		if usedRemoved[rk] {
			continue
		}
		if common[portHostOf(rk)] {
			d.Changes = append(d.Changes, changeFor(ChangePortRemoved, rk))
		} else {
			suppressed++
		}
	}

	// 两端都在：服务识别变化（键在两侧都存在 ⇒ 其 IP 必然共同扫描过）
	for key, cp := range c {
		pp, ok := p[key]
		if !ok {
			continue
		}
		// ⭐ 只在**双方都识别出服务**且不同时报变化：
		//   单侧为空多半是 banner 抓取抖动，报出来就是假阳性
		if pp.Service != "" && cp.Service != "" && pp.Service != cp.Service {
			ch := changeFor(ChangePortServiceChanged, key)
			ch.Before = pp.Service
			ch.After = cp.Service
			d.Changes = append(d.Changes, ch)
		}
	}

	// 扫描集完全无交集且没有任何轮换配对 → 明确说明不可比
	if len(common) == 0 && suppressed > 0 && len(d.Changes) == 0 {
		ch := coverageChange(CoverageCategoryPorts, true, true)
		ch.Detail = "两次扫描的 IP 集合不重叠（解析或子域选择变化），端口差异不可比。"
		d.Changes = append(d.Changes, ch)
	}
}

// serviceCompatible 服务是否"兼容"（用于 IP 轮换归并）
//
// 任一侧识别不出服务 → 视为兼容（轮换判定优先，宁可少报高危）；
// 两侧都有且不同 → 不兼容（如 443 上 https vs smtp，是真变化）
func serviceCompatible(a, b string) bool {
	return a == "" || b == "" || a == b
}

func portMap(ports []SnapshotPort) map[string]SnapshotPort {
	m := map[string]SnapshotPort{}
	for _, p := range ports {
		m[portKey(p.IP, p.Host, p.Port)] = p
	}
	return m
}

// portHostOf 从端口键（ip:port）取主机部分（IPv6 含冒号，按最后一个冒号切）
func portHostOf(key string) string {
	if i := strings.LastIndex(key, ":"); i >= 0 {
		return key[:i]
	}
	return key
}

// jarmIsFailed JARM 是否为"探测失败"哨兵（62 个 0）
//
// ⭐ 快照层已把全 0 归一化为空；这里再做一层防御（手工编辑的快照文件）。
func jarmIsFailed(s string) bool { return s == strings.Repeat("0", 62) }

// h2Core H2 指纹的比较核心（仅 SETTINGS 段）
//
// ⭐ 审查 M1：WINDOW_UPDATE 的到达时机有采样抖动（300ms 补读窗口），
//
//	用完整串比较会产生假"指纹变化"；只比 SETTINGS 部分。
func h2Core(s string) string {
	if i := strings.IndexByte(s, '|'); i >= 0 {
		return s[:i]
	}
	return s
}

// diffTech HTTP 端点指纹差异（只比较两端都在的 URL）
//
// ⭐ 刻意**不产出** tech_added / tech_removed：
//
//	快照里的 tech 列表包含失败探测（Status=0），所以"URL 不在本次列表里"
//	只能说明**本次没探测它**（目标选择随 CT/被动结果、tech-max 截断而洗牌），
//	不能说明它消失 —— 端点真的不可达时会以 status_changed（→探测失败）出现。
//	"新端点"也由 subdomain_added / port_added 覆盖。产出增删只会是噪音。
func diffTech(prev, curr *Snapshot, d *SnapshotDiff) {
	p := techMap(prev.Tech)
	c := techMap(curr.Tech)
	for url, ct := range c {
		pt, ok := p[url]
		if !ok {
			continue // 本次新探测到的 URL：不报（见函数注释）
		}
		// 状态码总是比较（0 = 探测失败也是有效状态）
		if pt.Status != ct.Status {
			ch := changeFor(ChangeTechStatusChanged, url)
			ch.Before = statusText(pt.Status)
			ch.After = statusText(ct.Status)
			d.Changes = append(d.Changes, ch)
		}
		// ⭐ 其余字段：双方非空且不同才报（零假阳性纪律）
		if pt.Server != "" && ct.Server != "" && pt.Server != ct.Server {
			ch := changeFor(ChangeTechServerChanged, url)
			ch.Before = truncateS(pt.Server, 40)
			ch.After = truncateS(ct.Server, 40)
			d.Changes = append(d.Changes, ch)
		}
		if pt.FaviconProduct != "" && ct.FaviconProduct != "" && pt.FaviconProduct != ct.FaviconProduct {
			ch := changeFor(ChangeTechFaviconChanged, url)
			ch.Before = pt.FaviconProduct
			ch.After = ct.FaviconProduct
			d.Changes = append(d.Changes, ch)
		}
		if pt.Title != "" && ct.Title != "" && pt.Title != ct.Title {
			ch := changeFor(ChangeTechTitleChanged, url)
			ch.Before = truncateS(pt.Title, 40)
			ch.After = truncateS(ct.Title, 40)
			d.Changes = append(d.Changes, ch)
		}
		if pt.JARM != "" && ct.JARM != "" && pt.JARM != ct.JARM &&
			!jarmIsFailed(pt.JARM) && !jarmIsFailed(ct.JARM) {
			ch := changeFor(ChangeTechJARMChanged, url)
			ch.Before = pt.JARM
			ch.After = ct.JARM
			d.Changes = append(d.Changes, ch)
		}
		if pt.H2Settings != "" && ct.H2Settings != "" &&
			h2Core(pt.H2Settings) != h2Core(ct.H2Settings) {
			ch := changeFor(ChangeTechH2Changed, url)
			ch.Before = truncateS(pt.H2Settings, 40)
			ch.After = truncateS(ct.H2Settings, 40)
			d.Changes = append(d.Changes, ch)
		}
	}
}

func techMap(items []SnapshotTech) map[string]SnapshotTech {
	m := map[string]SnapshotTech{}
	for _, t := range items {
		m[strings.TrimSpace(t.URL)] = t
	}
	return m
}

// statusText 状态码的展示文本（0 = 探测失败）
func statusText(s int) string {
	if s == 0 {
		return "探测失败"
	}
	return strconv.Itoa(s)
}

// changeFor 按类型生成一条变化（级别与判读集中定义，便于统一审查）
func changeFor(kind, target string) Change {
	c := Change{Kind: kind, Target: target}
	switch kind {
	case ChangeSubdomainAdded:
		c.Level = "medium"
		c.Detail = "新增子域可能是新部署的资产，也可能是影子资产。建议确认其归属与用途；" +
			"若从未在证书透明度/被动 DNS 的曾用名中出现过，更需人工核实。"
	case ChangeSubdomainRemoved:
		c.Level = "info"
		c.Detail = "子域从快照中消失（来源不再包含）。注意：证书透明度是**累积**数据，" +
			"历史子域通常会一直存在 —— 因此这里更可能是数据源覆盖变化，请结合覆盖率说明判断。"
	case ChangeIPAdded:
		c.Level = "low"
		c.Detail = "根域解析新增 IP（迁移、负载均衡或 CDN 调整）。若 IP 归属异常，可进一步核查。"
	case ChangeIPRemoved:
		c.Level = "info"
		c.Detail = "根域不再解析到该 IP。若曾为源站 IP，确认迁移是否完成、旧 IP 是否已释放。"
	case ChangePortAdded:
		c.Level = "high"
		c.Detail = "出现新的开放端口。若不在计划内需警惕：可能是服务误配置暴露，也可能是入侵后的后门。" +
			"建议确认服务内容与变更来源。"
	case ChangePortRemoved:
		c.Level = "info"
		c.Detail = "端口不再开放（服务下线或防火墙调整）。若为关键服务，确认是否宕机。"
	case ChangePortServiceChanged:
		c.Level = "medium"
		c.Detail = "同一端口的服务识别发生变化（服务替换或识别修正）。确认是否为预期变更。"
	case ChangePortIPChanged:
		c.Level = "low"
		c.Detail = "同一端口随解析 IP 变化出现/消失（CDN 节点轮换、负载均衡或迁移）。" +
			"更可能是解析变化而非暴露面变化；确认新 IP 归属是否符合预期即可。"
	case ChangeTechStatusChanged:
		c.Level = "medium"
		c.Detail = "HTTP 状态码变化。如 200→403 常意味着访问控制策略变更；" +
			"变为「探测失败」表示端点不可达（可能下线，也可能是临时故障）。"
	case ChangeTechServerChanged:
		c.Level = "medium"
		c.Detail = "Server 头变化（版本升级/降级或更换软件）。请核对新版本是否包含已知漏洞。"
	case ChangeTechFaviconChanged:
		c.Level = "low"
		c.Detail = "favicon 变化通常意味着换栈或改版。"
	case ChangeTechTitleChanged:
		c.Level = "info"
		c.Detail = "页面标题变化（改版或内容调整）。"
	case ChangeTechJARMChanged:
		c.Level = "medium"
		c.Detail = "JARM TLS 指纹变化 —— 服务端 TLS 栈的实现特征改变了（换服务器/换 TLS 库/重大升级）。" +
			"这是高价值信号：确认是否为计划内变更；若非计划内，留意后端替换或中间设备变更。"
	case ChangeTechH2Changed:
		c.Level = "low"
		c.Detail = "HTTP/2 SETTINGS 指纹变化（服务器软件升级或连接参数调整）。"
	case ChangeCoverageChanged:
		// Detail/Before/After 由调用方（coverageChange / spec 变化）填充
		c.Level = "info"
	}
	return c
}

// sortChanges 排序：级别（危险优先）→ 类型 → 目标，输出稳定
func sortChanges(cs []Change) {
	rank := map[string]int{"high": 0, "medium": 1, "low": 2, "info": 3}
	sort.SliceStable(cs, func(i, j int) bool {
		ri, oki := rank[cs[i].Level]
		rj, okj := rank[cs[j].Level]
		if !oki {
			ri = 9
		}
		if !okj {
			rj = 9
		}
		if ri != rj {
			return ri < rj
		}
		if cs[i].Kind != cs[j].Kind {
			return cs[i].Kind < cs[j].Kind
		}
		return cs[i].Target < cs[j].Target
	})
}
