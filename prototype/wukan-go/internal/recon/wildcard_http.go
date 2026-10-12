package recon

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/wukan/wukan/internal/httpprobe"
)

// ── 泛域名 HTTP 二次确认（主动探测）────────────────────────────────
//
// ⭐ 要解决的问题（技术债 #4）：
//
//	配置了泛域名解析（*.example.com → 某 IP）时，任何子域都能解析成功，
//	「能解析」不再等于「资产存活」—— 历史证书里出现过的名字会集体"存活"，
//	CT 子域列表因此可能被成片污染（假存活）。
//
// ⭐ 判定思路（对照基线，不做"单点猜测"）：
//
//	① 先探一个**随机不存在**的子域，拿到"泛域名默认站点"的响应基线
//	   （状态码 + 标题 + 正文长度 + favicon 哈希）；
//	② 再对解析成功的子域发同样的请求，与基线**成对比较**：
//	     · 响应与基线显著不同 → real（独立响应，真实站点的强证据）
//	     · 响应与基线一致     → wildcard（泛域名默认站点，不是独立资产）
//	     · 无 HTTP 响应 + 与泛域名同 IP → wildcard_no_http（疑似，弱证据）
//	     · 其余               → inconclusive（无法判定，交给人工）
//
// ⚠️ 主动探测：会向目标发 HTTP 请求，必须在 CLI 显式开启（--wildcard-http），
// 且仅当 DNS 阶段检测到泛域名时才生效。
// ⚠️ 只做澄清与降噪：所有判定都基于"与随机子域基线的对照"，
// 不抓取、不分析敏感内容。

// 泛域名二次确认的判定值（写入 SubdomainInfo.HTTPConfirm）
const (
	// ConfirmReal 响应与泛域名基线不同 —— 独立响应的强证据
	ConfirmReal = "real"
	// ConfirmWildcard 响应与泛域名基线一致 —— 泛域名默认站点，非独立资产
	ConfirmWildcard = "wildcard"
	// ConfirmWildcardNoHTTP 无 HTTP 响应且解析地址与泛域名一致 —— 疑似泛域名产物
	ConfirmWildcardNoHTTP = "wildcard_no_http"
	// ConfirmInconclusive 无法判定（无 HTTP 响应且证据不足）
	ConfirmInconclusive = "inconclusive"
)

// WildcardHTTPCheck 泛域名 HTTP 二次确认的汇总（Report.WildcardHTTP）
type WildcardHTTPCheck struct {
	// ProbeHost 基线用的随机子域名（必然不存在，用于取"默认站点"）
	ProbeHost string `json:"probe_host,omitempty"`
	// BaselineStatus 基线 HTTP 状态码（0 = 无任何 HTTP 响应）
	BaselineStatus int `json:"baseline_status,omitempty"`
	// BaselineTitle 基线页面标题
	BaselineTitle string `json:"baseline_title,omitempty"`
	// BaselineErr 基线探测失败原因
	//
	//	非空 = 基线不可用，此时"独立响应"退化为"有 HTTP 响应"（无法做同站比对），
	//	报告会明确说明这一点（不把缺失的证据当成证据）。
	BaselineErr string `json:"baseline_err,omitempty"`
	// Probed 实际确认的子域数
	Probed int `json:"probed,omitempty"`
	// Real 独立响应（真实站点）数量
	Real int `json:"real,omitempty"`
	// Wildcard 与基线一致（泛域名产物）数量
	Wildcard int `json:"wildcard,omitempty"`
	// WildcardNoHTTP 无 HTTP 响应且与泛域名同 IP（疑似泛域名产物）数量
	WildcardNoHTTP int `json:"wildcard_no_http,omitempty"`
	// Inconclusive 无法判定数量
	Inconclusive int `json:"inconclusive,omitempty"`
}

// ConfirmLabel 子域表格里显示的一行短标签（空 = 未做二次确认）
func (s *SubdomainInfo) ConfirmLabel() string {
	if s == nil {
		return ""
	}
	switch s.HTTPConfirm {
	case ConfirmReal:
		return "✓ 独立响应"
	case ConfirmWildcard:
		return "✗ 泛域名一致"
	case ConfirmWildcardNoHTTP:
		return "⚠ 疑似泛域名"
	case ConfirmInconclusive:
		return "? 无HTTP响应"
	}
	return ""
}

// selectWildcardConfirmTargets 选出要二次确认的子域
//
// 规则（与 selectSubScanTargets 对齐，量级控制是关键）：
//   - 只选解析成功的子域（Resolves && ResolveIPs 非空），跳过通配符证书条目与根域
//     （通配符证书 *.example.com 不是可访问资产；根域本身不是"泛域名产物"）
//   - 按名字排序（选择稳定，多目标并行/多次运行的判定集合一致）
//   - 限量（默认 20，由 WildcardHTTPMax 控制）
func selectWildcardConfirmTargets(rep *Report, max int) []*SubdomainInfo {
	if rep == nil || rep.CT == nil || max <= 0 {
		return nil
	}
	var subs []*SubdomainInfo
	for _, sb := range rep.CT.Subdomains {
		if sb == nil || sb.IsWildcard || !sb.Resolves || len(sb.ResolveIPs) == 0 {
			continue
		}
		if strings.EqualFold(sb.Name, rep.Target) {
			continue
		}
		subs = append(subs, sb)
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].Name < subs[j].Name })
	if len(subs) > max {
		subs = subs[:max]
	}
	return subs
}

// confirmWildcardSubdomains 执行泛域名 HTTP 二次确认
//
// 只读 rep（DNS.Wildcard / CT.Subdomains / Target），把判定写回
// SubdomainInfo.HTTPConfirm / HTTPStatus，并返回汇总。
func (r *Runner) confirmWildcardSubdomains(rep *Report) *WildcardHTTPCheck {
	chk := &WildcardHTTPCheck{}

	// 探测配置：与 tech 同档（超时/并发/降级重试一致），并复用 tech 指纹缓存 ——
	//   ⭐ 缓存键包含采集能力开关（CapabilityKey），本阶段的默认能力组合
	//   与 tech 相同，所以两边**同一 URL 只探一次**；不会互相污染。
	//   基线是随机名（每次都不同），缓存对基线自然无复用，但不冲突。
	cfg := httpprobe.DefaultConfig()
	cfg.Timeout = r.opt.TechTimeout
	cfg.Concurrency = r.opt.TechConcurrency
	cfg.RetryFallback = r.opt.TechRetryFallback
	cfg.GrabJARM = false
	cfg.Cache = r.opt.TechCache

	// ① 基线：随机子域。泛域名下它必然解析到"默认站点"，
	//    它的响应 = 泛域名给不存在的名字看的页面。
	probe := fmt.Sprintf("wukan-wc-http-%d-%s",
		time.Now().UnixNano()%1000000, strings.ReplaceAll(randomLabel(6), "-", "x"))
	chk.ProbeHost = probe + "." + rep.Target
	base := httpprobe.New(cfg).ProbeURL("https://" + chk.ProbeHost)
	if base != nil {
		chk.BaselineStatus = base.StatusCode
		chk.BaselineTitle = base.Title
		chk.BaselineErr = base.Err
	} else {
		chk.BaselineErr = "探测无结果"
	}
	baselineOK := base != nil && base.Err == "" && base.StatusCode != 0
	if !baselineOK {
		// ⭐ 不中止：基线缺失时仍可做保守判定（有响应 = 有服务；
		//   无响应 + 同泛域 IP = 疑似产物），只是能力降级，报告会说明。
		chk.BaselineErr = firstNonEmpty(chk.BaselineErr, "无 HTTP 响应")
	}

	// ② 候选子域
	subs := selectWildcardConfirmTargets(rep, r.opt.WildcardHTTPMax)
	chk.Probed = len(subs)
	if len(subs) == 0 {
		return chk
	}

	// ③ 批量探测：各子域主机名不同 → HostHeader 留空（每个请求用自己的主机名），
	//    并发由 ProbeURLs 内部按 cfg.Concurrency 控制。
	urls := make([]string, 0, len(subs))
	for _, sb := range subs {
		urls = append(urls, "https://"+sb.Name)
	}
	results := httpprobe.New(cfg).ProbeURLs(urls, nil)

	// ④ 成对判定
	wildcardIP := strings.TrimSpace(rep.DNS.Wildcard)
	for i, sb := range subs {
		var got *httpprobe.ProbeResult
		if i < len(results) {
			got = results[i]
		}
		gotOK := got != nil && got.Err == "" && got.StatusCode != 0
		same := baselineOK && gotOK && sameWildcardSite(base, got)
		ipMatch := wildcardIP != "" && containsIPFold(sb.ResolveIPs, wildcardIP)

		cls := classifyWildcardHTTP(baselineOK, same, gotOK, ipMatch)
		sb.HTTPConfirm = cls
		if got != nil && got.StatusCode != 0 {
			sb.HTTPStatus = got.StatusCode
		}
		switch cls {
		case ConfirmReal:
			chk.Real++
		case ConfirmWildcard:
			chk.Wildcard++
		case ConfirmWildcardNoHTTP:
			chk.WildcardNoHTTP++
		default:
			chk.Inconclusive++
		}
	}
	return chk
}

// classifyWildcardHTTP 纯判定函数（与网络解耦，便于单测）
//
// 输入：
//
//	baselineOK 基线可用（拿到了有效响应）
//	sameSite   与基线同站（状态码/标题/正文长度/favicon 一致）
//	gotOK      子域拿到了有效 HTTP 响应
//	ipMatch    子域解析地址与泛域名探测地址相同
func classifyWildcardHTTP(baselineOK, sameSite, gotOK, ipMatch bool) string {
	switch {
	case gotOK && baselineOK && sameSite:
		// 响应与"不存在的名字"一模一样 → 泛域名默认站点产物
		return ConfirmWildcard
	case gotOK:
		// 有响应且（基线可用时）与基线不同 → 独立响应
		return ConfirmReal
	case ipMatch && !baselineOK:
		// 无 HTTP 响应、且指向的正是泛域名地址、且泛域名地址本身不提供 HTTP
		// → 大概率是泛域名解析产物（弱证据，保守标注"疑似"）
		return ConfirmWildcardNoHTTP
	default:
		return ConfirmInconclusive
	}
}

// sameWildcardSite 判断两个探测结果是否"同一个默认站点"
//
// ⭐ 保守方向（宁可不判相同，不误杀真实资产）：
//   - 状态码必须一致
//   - 标题必须一致（去首尾空白）
//   - favicon 哈希：两边都有时必须一致；一边有一边无视为差异
//   - 正文长度允许 2% 抖动（动态时间戳/随机 token 等）
func sameWildcardSite(base, got *httpprobe.ProbeResult) bool {
	if base == nil || got == nil {
		return false
	}
	if base.Err != "" || got.Err != "" {
		return false
	}
	if base.StatusCode == 0 || got.StatusCode == 0 || base.StatusCode != got.StatusCode {
		return false
	}
	if strings.TrimSpace(base.Title) != strings.TrimSpace(got.Title) {
		return false
	}
	// favicon 哈希是确定性判据：
	//   - 两边都拿到 → 必须一致，否则不是同一站点
	//   - 一边有一边无 → 弱差异证据（默认页无 favicon 而子域有，通常不是同一页）
	//
	// ⭐ 保守方向：宁可多留一条"真实"线索，也不误杀真实资产
	//   （把真实站点误判成"泛域名产物"会让使用者把它从资产列表里删掉）。
	if (base.FaviconMurmur == 0) != (got.FaviconMurmur == 0) {
		return false
	}
	if base.FaviconMurmur != 0 && base.FaviconMurmur != got.FaviconMurmur {
		return false
	}
	return bodyLenClose(base.BodyLen, got.BodyLen)
}

// bodyLenClose 正文长度是否"接近"（2% 抖动以内）
func bodyLenClose(a, b int) bool {
	if a == b {
		return true
	}
	m := a
	if b > m {
		m = b
	}
	if m <= 0 {
		return false
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	return d*100 <= m*2
}

func containsIPFold(ips []string, target string) bool {
	for _, ip := range ips {
		if strings.EqualFold(strings.TrimSpace(ip), target) {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// wildcardHTTPEvidence 收集二次确认的证据示例（每类最多 4 条，共最多 8 条；
// 优先展示"独立响应"与"泛域名一致"这两类结论性证据）
func wildcardHTTPEvidence(rep *Report) []string {
	if rep == nil || rep.CT == nil {
		return nil
	}
	var realE, wcE, noE, incE []string
	pick := func(dst *[]string, sb *SubdomainInfo) {
		if len(*dst) >= 4 {
			return
		}
		status := "无HTTP响应"
		if sb.HTTPStatus > 0 {
			status = fmt.Sprintf("HTTP %d", sb.HTTPStatus)
		}
		*dst = append(*dst, sb.Name+"（"+status+"）")
	}
	for _, sb := range rep.CT.Subdomains {
		if sb == nil {
			continue
		}
		switch sb.HTTPConfirm {
		case ConfirmReal:
			pick(&realE, sb)
		case ConfirmWildcard:
			pick(&wcE, sb)
		case ConfirmWildcardNoHTTP:
			pick(&noE, sb)
		case ConfirmInconclusive:
			pick(&incE, sb)
		}
	}
	var out []string
	for _, x := range realE {
		out = append(out, "独立响应: "+x)
	}
	for _, x := range wcE {
		out = append(out, "泛域名一致: "+x)
	}
	for _, x := range noE {
		out = append(out, "疑似泛域名: "+x)
	}
	for _, x := range incE {
		out = append(out, "无HTTP响应: "+x)
	}
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}
