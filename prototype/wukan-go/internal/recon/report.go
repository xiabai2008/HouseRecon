package recon

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/wukan/wukan/internal/httpprobe"
	"github.com/wukan/wukan/internal/ipinfo"
	"github.com/wukan/wukan/internal/portscan"
	"github.com/wukan/wukan/internal/quic"
)

// ⭐⭐ 报告导出（P1-4）：Markdown / HTML
//
// 定位：table/json/hosts/subs 是"工作输出"，本文件产出的是**交付物** ——
// 适合直接发给同事、存档、附在工单里的完整报告：
//   - 摘要 → 发现（带判读与证据）→ 差异 → 各数据段 → 方法说明
//   - HTML 自带内联样式（单文件、无外部资源），HTML 转义由 html/template 保证
//   - 行数上限保护（子域/被动/指纹表各 100 行），避免大目标产出巨型文件

const reportTool = "屋勘 HouseRecon · wukan/0.1.0"

const reportDisclaimer = "本报告仅用于对**自己拥有或已获书面授权**的资产进行梳理。" +
	"主动探测功能（端口扫描/指纹采集/QUIC）的使用者须自行确保行为符合当地法律。"

// reportCounts 摘要计数
type reportCounts struct {
	High, Medium, Low, Info int
	Subdomains, IPs         int
	OpenPorts, TechCount    int
	DiffCount               int
}

func countReport(rep *Report) reportCounts {
	var c reportCounts
	for _, f := range rep.Findings {
		switch f.Level {
		case "high":
			c.High++
		case "medium":
			c.Medium++
		case "low":
			c.Low++
		default:
			c.Info++
		}
	}
	if rep.CT != nil {
		c.Subdomains = len(rep.CT.Subdomains)
	}
	if rep.DNS != nil {
		c.IPs = len(rep.DNS.IPs)
	}
	for _, p := range rep.Ports {
		if p.Open() {
			c.OpenPorts++
		}
	}
	c.TechCount = len(rep.Tech)
	if rep.Diff != nil {
		c.DiffCount = len(rep.Diff.Changes)
	}
	return c
}

// sortedFindings 按严重度排序（high 优先）
func sortedFindings(rep *Report) []Finding {
	order := map[string]int{"high": 0, "medium": 1, "low": 2, "info": 3}
	fs := make([]Finding, len(rep.Findings))
	copy(fs, rep.Findings)
	sort.SliceStable(fs, func(i, j int) bool {
		oi, oki := order[fs[i].Level]
		oj, okj := order[fs[j].Level]
		if !oki {
			oi = 9
		}
		if !okj {
			oj = 9
		}
		return oi < oj
	})
	return fs
}

func reportTime() string {
	return time.Now().Format("2006-01-02 15:04")
}

// ── Markdown ─────────────────────────────────────────────

// WriteMarkdown 生成 Markdown 报告
func WriteMarkdown(w io.Writer, rep *Report) error {
	if rep == nil {
		return fmt.Errorf("报告为空")
	}
	var b strings.Builder
	c := countReport(rep)

	fmt.Fprintf(&b, "# 屋勘 HouseRecon — 资产侦察报告\n\n")
	fmt.Fprintf(&b, "**目标**：`%s`  \n", rep.Target)
	fmt.Fprintf(&b, "**生成时间**：%s  \n", reportTime())
	fmt.Fprintf(&b, "**工具**：%s  \n\n", reportTool)
	fmt.Fprintf(&b, "> ⚠️ %s\n\n", reportDisclaimer)

	// 摘要
	fmt.Fprintf(&b, "## 摘要\n\n")
	fmt.Fprintf(&b, "| 项目 | 数量 |\n|---|---|\n")
	fmt.Fprintf(&b, "| 🔴 高危发现 | %d |\n", c.High)
	fmt.Fprintf(&b, "| 🟡 中危发现 | %d |\n", c.Medium)
	fmt.Fprintf(&b, "| 🔵 低危发现 | %d |\n", c.Low)
	fmt.Fprintf(&b, "| 子域 | %d |\n", c.Subdomains)
	fmt.Fprintf(&b, "| 解析 IP | %d |\n", c.IPs)
	fmt.Fprintf(&b, "| 开放端口 | %d |\n", c.OpenPorts)
	fmt.Fprintf(&b, "| HTTP 指纹 | %d |\n", c.TechCount)
	if rep.Diff != nil {
		fmt.Fprintf(&b, "| 与上次快照的差异 | %d 处 |\n", c.DiffCount)
	}
	fmt.Fprintf(&b, "\n")

	// 可行动发现
	if len(rep.Findings) > 0 {
		fmt.Fprintf(&b, "## ⭐ 可行动发现\n\n")
		for _, f := range sortedFindings(rep) {
			fmt.Fprintf(&b, "### %s [%s] %s\n\n", LevelIcon(f.Level), f.Type, f.Title)
			if f.Detail != "" {
				fmt.Fprintf(&b, "%s\n\n", mdText(f.Detail))
			}
			for _, e := range f.Evidence {
				if e != "" {
					fmt.Fprintf(&b, "- 证据：`%s`\n", mdCode(e))
				}
			}
			fmt.Fprintf(&b, "\n")
		}
	}

	// 差异
	if rep.Diff != nil && len(rep.Diff.Changes) > 0 {
		fmt.Fprintf(&b, "## 与上次快照的差异\n\n")
		fmt.Fprintf(&b, "基准 %s → 最新 %s，共 %d 处变化。\n\n",
			rep.Diff.PrevAt.Local().Format("2006-01-02 15:04"),
			rep.Diff.CurrAt.Local().Format("2006-01-02 15:04"),
			len(rep.Diff.Changes))
		for _, ch := range rep.Diff.Changes {
			line := fmt.Sprintf("- %s **[%s] %s**", LevelIcon(ch.Level), ch.Kind, mdCell(ch.Target))
			if ch.Before != "" || ch.After != "" {
				line += fmt.Sprintf("（`%s` → `%s`）", mdCode(ch.Before), mdCode(ch.After))
			}
			fmt.Fprintf(&b, "%s\n", line)
			if ch.Detail != "" {
				fmt.Fprintf(&b, "  - 判读：%s\n", mdText(ch.Detail))
			}
		}
		fmt.Fprintf(&b, "\n")
	}

	// DNS
	if rep.DNS != nil {
		fmt.Fprintf(&b, "## DNS 解析（%s）\n\n", mdCell(rep.DNS.Resolver))
		if rep.DNS.Err != "" {
			fmt.Fprintf(&b, "⚠ %s\n\n", mdText(rep.DNS.Err))
		}
		if len(rep.DNS.Records) > 0 {
			fmt.Fprintf(&b, "| 类型 | 值 |\n|---|---|\n")
			for _, rt := range sortedRecordTypes(rep.DNS.Records) {
				for _, r := range rep.DNS.Records[rt] {
					fmt.Fprintf(&b, "| %s | `%s` |\n", r.Type, mdCell(mdCode(r.Value)))
				}
			}
			fmt.Fprintf(&b, "\n")
		}
	}

	// 注册信息
	if rep.Domain != nil {
		fmt.Fprintf(&b, "## 域名注册信息\n\n")
		if rep.Domain.Err != "" {
			fmt.Fprintf(&b, "⚠ %s\n\n", mdText(rep.Domain.Err))
		} else {
			fmt.Fprintf(&b, "| 字段 | 值 |\n|---|---|\n")
			fmt.Fprintf(&b, "| 注册商 | %s |\n", mdCell(dashOr(rep.Domain.Registrar)))
			for _, k := range sortedKeys(rep.Domain.Events) {
				fmt.Fprintf(&b, "| %s | %s |\n", mdCell(k), mdCell(rep.Domain.Events[k]))
			}
			if len(rep.Domain.Nameservers) > 0 {
				fmt.Fprintf(&b, "| NS | %s |\n", mdCell(strings.Join(rep.Domain.Nameservers, ", ")))
			}
			fmt.Fprintf(&b, "| DNSSEC | %v |\n\n", rep.Domain.SecureDNS)
		}
	}

	// 证书透明度
	if rep.CT != nil && len(rep.CT.Subdomains) > 0 {
		fmt.Fprintf(&b, "## 证书透明度 · 子域（去重 %d 个）\n\n", len(rep.CT.Subdomains))
		fmt.Fprintf(&b, "| 子域 | 解析 | 首次出现 | 最后出现 | 证书数 |\n|---|---|---|---|---|\n")
		for i, sb := range rep.CT.Subdomains {
			if i >= 100 {
				fmt.Fprintf(&b, "\n…（还有 %d 个，见 JSON 输出）\n\n", len(rep.CT.Subdomains)-100)
				break
			}
			resolves := "否"
			if sb.Resolves {
				resolves = "是"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %d |\n",
				mdCell(sb.Name), resolves,
				sb.FirstSeen.Format("2006-01-02"), sb.LastSeen.Format("2006-01-02"),
				sb.CertCount)
		}
		fmt.Fprintf(&b, "\n")
	}

	// 被动 DNS + 时间线
	if rep.Passive != nil {
		if len(rep.Passive.Records) > 0 {
			fmt.Fprintf(&b, "## 被动 DNS · 历史解析\n\n")
			subs := rep.Passive.Subdomains()
			for i, host := range subs {
				if i >= 50 {
					fmt.Fprintf(&b, "\n…（还有 %d 个）\n\n", len(subs)-50)
					break
				}
				fmt.Fprintf(&b, "- `%s` → %s\n", mdCode(host), mdCell(strings.Join(rep.Passive.Records[host], ", ")))
			}
			fmt.Fprintf(&b, "\n")
		}
		if chain := timelineChain(rep.Passive.Timeline, rep.Target); len(chain) > 0 {
			fmt.Fprintf(&b, "## 被动 DNS 时间线（%s 的迁移轨迹）\n\n", rep.Target)
			fmt.Fprintf(&b, "| IP | 首次出现 | 最后出现 |\n|---|---|---|\n")
			for _, e := range chain {
				first, last := "?", "?"
				if !e.FirstSeen.IsZero() {
					first = e.FirstSeen.Format("2006-01-02")
				}
				if !e.LastSeen.IsZero() {
					last = e.LastSeen.Format("2006-01-02")
				}
				fmt.Fprintf(&b, "| `%s` | %s | %s |\n", e.IP, first, last)
			}
			fmt.Fprintf(&b, "\n")
		}
	}

	// 端口
	if len(rep.Ports) > 0 {
		fmt.Fprintf(&b, "## 端口扫描（开放端口）\n\n")
		fmt.Fprintf(&b, "| 主机 | 端口 | 服务 | 置信 | banner |\n|---|---|---|---|---|\n")
		for _, p := range rep.Ports {
			if !p.Open() {
				continue
			}
			fmt.Fprintf(&b, "| %s | %d | %s | %d | `%s` |\n",
				mdCell(p.Host), p.Port, mdCell(dashOr(p.Service)), p.Confidence,
				mdCell(mdCode(truncateS(p.Banner, 60))))
		}
		fmt.Fprintf(&b, "\n")
	}
	if rep.PortsErr != "" {
		fmt.Fprintf(&b, "## 端口扫描\n\n⚠ 未执行：%s\n\n", mdText(rep.PortsErr))
	}

	// HTTP 指纹
	if len(rep.Tech) > 0 {
		fmt.Fprintf(&b, "## HTTP 指纹与冲突检测\n\n")
		fmt.Fprintf(&b, "| URL | 状态 | Server | JARM | 技术栈 | 冲突 |\n|---|---|---|---|---|---|\n")
		for i, t := range rep.Tech {
			if t == nil {
				continue
			}
			status := fmt.Sprintf("%d", t.StatusCode)
			if t.Err != "" {
				status = "ERR"
			}
			conflict := "—"
			if i < len(rep.TechConflicts) && rep.TechConflicts[i] != nil {
				if n := len(rep.TechConflicts[i].Conflicts); n > 0 {
					conflict = fmt.Sprintf("⚠ %d", n)
				}
			}
			fmt.Fprintf(&b, "| %s | %s | %s | `%s` | %s | %s |\n",
				mdCell(truncateS(t.URL, 44)), status, mdCell(dashOr(t.Server)),
				mdCode(truncateS(t.JARM, 16)),
				mdCell(strings.Join(t.BodyKeywords, "/")), conflict)
		}
		fmt.Fprintf(&b, "\n")
		for i, cr := range rep.TechConflicts {
			if cr == nil || len(cr.Conflicts) == 0 || i >= len(rep.Tech) || rep.Tech[i] == nil {
				continue
			}
			for _, c := range cr.Conflicts {
				fmt.Fprintf(&b, "- **%s**（%s）：%s\n", mdText(c.Title), c.Type, mdText(c.Implication))
			}
		}
		fmt.Fprintf(&b, "\n")
	}

	// QUIC
	if len(rep.QUIC) > 0 {
		fmt.Fprintf(&b, "## QUIC / UDP-443 探活\n\n")
		fmt.Fprintf(&b, "| 主机 | 状态 | 实现提示 |\n|---|---|---|\n")
		for _, q := range rep.QUIC {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", q.Host, q.State.String(), mdCell(dashOr(q.StackHint)))
		}
		fmt.Fprintf(&b, "\n")
	}

	// rDNS / IP 归属
	if len(rep.IPInfo) > 0 {
		fmt.Fprintf(&b, "## IP 归属\n\n")
		fmt.Fprintf(&b, "| IP | 归属 | ASN | ISP | 标签 |\n|---|---|---|---|---|\n")
		for _, ip := range rep.IPInfo {
			if ip == nil {
				continue
			}
			fmt.Fprintf(&b, "| `%s` | %s/%s | AS%d | %s | %s |\n",
				ip.IP, mdCell(ip.CountryCode), mdCell(ip.City), ip.ASN,
				mdCell(ip.ISP), mdCell(strings.Join(ip.Flags, "/")))
		}
		fmt.Fprintf(&b, "\n")
	}

	// rDNS
	if len(rep.RDNS) > 0 {
		fmt.Fprintf(&b, "## rDNS 反查\n\n")
		fmt.Fprintf(&b, "| IP | PTR |\n|---|---|\n")
		for _, r := range rep.RDNS {
			if r == nil || len(r.Hostnames) == 0 {
				continue
			}
			fmt.Fprintf(&b, "| `%s` | %s |\n", mdCode(r.IP), mdCell(strings.Join(r.Hostnames, ", ")))
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "---\n\n")
	fmt.Fprintf(&b, "*由 %s 生成。%s*\n", reportTool, reportDisclaimer)

	_, err := io.WriteString(w, b.String())
	return err
}

// mdCell 表格单元格转义（竖线/换行会破坏表格）
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// mdCode 代码段内容转义（反引号会截断代码段；换行会破坏行内代码）
func mdCode(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// mdText 正文转义（只处理换行缩进）
func mdText(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "  \n")
}

func sortedRecordTypes(recs map[RecordType][]DNSRecord) []RecordType {
	out := make([]RecordType, 0, len(recs))
	for k := range recs {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── HTML ─────────────────────────────────────────────────

// htmlView HTML 模板的视图模型
type htmlView struct {
	Target      string
	Generated   string
	Tool        string
	Disclaimer  string
	Counts      reportCounts
	Findings    []Finding
	Diff        *SnapshotDiff
	DNS         *DNSResult
	RecordTypes []RecordType
	Domain      *DomainInfo
	DomainKeys  []string
	CT          *SubdomainResult
	Passive     *PassiveDNSResult
	PassiveSubs []string
	Timeline    []PDNSTimelineEntry
	OpenPorts   []portscan.PortResult
	PortsErr    string
	Tech        []*httpprobe.ProbeResult
	Conflicts   []*httpprobe.ConflictReport
	QUIC        []quic.Result
	IPInfo      []*ipinfo.Info
	RDNS        []*ipinfo.RDNSResult
}

const htmlReportTmpl = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>屋勘 HouseRecon — {{.Target}}</title>
<style>
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1a1a1a;line-height:1.6}
h1{border-bottom:3px solid #0a6e6e;padding-bottom:.4rem}
h2{color:#0a6e6e;border-bottom:1px solid #ddd;padding-bottom:.2rem;margin-top:2rem}
table{border-collapse:collapse;width:100%;margin:.6rem 0;font-size:.9rem}
th,td{border:1px solid #ddd;padding:.35rem .6rem;text-align:left;word-break:break-all}
th{background:#f3f7f7}
code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px;font-size:.85em}
.finding{border-left:4px solid #999;padding:.4rem .8rem;margin:.8rem 0;background:#fafafa}
.f-high{border-color:#c0392b}.f-medium{border-color:#d68910}.f-low{border-color:#2874a6}.f-info{border-color:#7f8c8d}
.chg{border-left:4px solid #d68910;padding:.3rem .8rem;margin:.4rem 0;background:#fffdf5}
.evidence{margin:.3rem 0 0 1rem;color:#555;font-size:.85rem}
.meta{color:#555;font-size:.9rem}
.note{background:#fff8e1;border:1px solid #f0e0b0;padding:.6rem .9rem;border-radius:6px;font-size:.9rem}
footer{margin-top:3rem;color:#888;font-size:.8rem;border-top:1px solid #ddd;padding-top:.6rem}
</style>
</head>
<body>
<h1>屋勘 HouseRecon — 资产侦察报告</h1>
<p class="meta"><strong>目标</strong>：<code>{{.Target}}</code><br>
<strong>生成时间</strong>：{{.Generated}}<br>
<strong>工具</strong>：{{.Tool}}</p>
<p class="note">⚠️ {{.Disclaimer}}</p>

<h2>摘要</h2>
<table>
<tr><th>项目</th><th>数量</th></tr>
<tr><td>🔴 高危发现</td><td>{{.Counts.High}}</td></tr>
<tr><td>🟡 中危发现</td><td>{{.Counts.Medium}}</td></tr>
<tr><td>🔵 低危发现</td><td>{{.Counts.Low}}</td></tr>
<tr><td>子域</td><td>{{.Counts.Subdomains}}</td></tr>
<tr><td>解析 IP</td><td>{{.Counts.IPs}}</td></tr>
<tr><td>开放端口</td><td>{{.Counts.OpenPorts}}</td></tr>
<tr><td>HTTP 指纹</td><td>{{.Counts.TechCount}}</td></tr>
{{if .Diff}}<tr><td>与上次快照的差异</td><td>{{.Counts.DiffCount}} 处</td></tr>{{end}}
</table>

{{if .Findings}}
<h2>⭐ 可行动发现</h2>
{{range .Findings}}
<div class="finding f-{{.Level}}">
<strong>{{levelIcon .Level}} [{{.Type}}] {{.Title}}</strong>
{{if .Detail}}<p>{{.Detail}}</p>{{end}}
{{range .Evidence}}<div class="evidence">· <code>{{.}}</code></div>{{end}}
</div>
{{end}}
{{end}}

{{if .Diff}}{{if .Diff.Changes}}
<h2>与上次快照的差异</h2>
<p class="meta">基准 {{fmtTime .Diff.PrevAt}} → 最新 {{fmtTime .Diff.CurrAt}}，共 {{len .Diff.Changes}} 处变化。</p>
{{range .Diff.Changes}}
<div class="chg"><strong>{{levelIcon .Level}} [{{.Kind}}] {{.Target}}</strong>{{if or .Before .After}}（<code>{{.Before}}</code> → <code>{{.After}}</code>）{{end}}
{{if .Detail}}<p>{{.Detail}}</p>{{end}}</div>
{{end}}
{{end}}{{end}}

{{if .DNS}}
<h2>DNS 解析（{{.DNS.Resolver}}）</h2>
{{if .DNS.Err}}<p>⚠ {{.DNS.Err}}</p>{{end}}
<table><tr><th>类型</th><th>值</th></tr>
{{range $rt := .RecordTypes}}{{range index $.DNS.Records $rt}}<tr><td>{{.Type}}</td><td><code>{{.Value}}</code></td></tr>{{end}}{{end}}
</table>
{{end}}

{{if .Domain}}<h2>域名注册信息</h2>
{{if .Domain.Err}}<p>⚠ {{.Domain.Err}}</p>{{else}}
<table><tr><th>字段</th><th>值</th></tr>
<tr><td>注册商</td><td>{{.Domain.Registrar}}</td></tr>
{{range $k := .DomainKeys}}<tr><td>{{$k}}</td><td>{{index $.Domain.Events $k}}</td></tr>{{end}}
{{if .Domain.Nameservers}}<tr><td>NS</td><td>{{join .Domain.Nameservers ", "}}</td></tr>{{end}}
<tr><td>DNSSEC</td><td>{{.Domain.SecureDNS}}</td></tr>
</table>{{end}}{{end}}

{{if .CT}}{{if .CT.Subdomains}}
<h2>证书透明度 · 子域（去重 {{len .CT.Subdomains}} 个）</h2>
<table><tr><th>子域</th><th>解析</th><th>首次出现</th><th>最后出现</th><th>证书数</th></tr>
{{range $i, $sb := .CT.Subdomains}}{{if lt $i 100}}<tr><td>{{$sb.Name}}</td><td>{{if $sb.Resolves}}是{{else}}否{{end}}</td><td>{{fmtDate $sb.FirstSeen}}</td><td>{{fmtDate $sb.LastSeen}}</td><td>{{$sb.CertCount}}</td></tr>{{end}}{{end}}
</table>
{{if gt (len .CT.Subdomains) 100}}<p class="meta">…（还有 {{sub (len .CT.Subdomains) 100}} 个，见 JSON 输出）</p>{{end}}
{{end}}{{end}}

{{if .Passive}}
{{if .PassiveSubs}}<h2>被动 DNS · 历史解析</h2>
{{range $i, $h := .PassiveSubs}}{{if lt $i 50}}<div><code>{{$h}}</code> → {{join (index $.Passive.Records $h) ", "}}</div>{{end}}{{end}}
{{end}}
{{if .Timeline}}<h2>被动 DNS 时间线（{{.Target}} 的迁移轨迹）</h2>
<table><tr><th>IP</th><th>首次出现</th><th>最后出现</th></tr>
{{range .Timeline}}<tr><td><code>{{.IP}}</code></td><td>{{fmtDate .FirstSeen}}</td><td>{{fmtDate .LastSeen}}</td></tr>{{end}}
</table>{{end}}
{{end}}

{{if .OpenPorts}}<h2>端口扫描（开放端口）</h2>
<table><tr><th>主机</th><th>端口</th><th>服务</th><th>置信</th><th>banner</th></tr>
{{range .OpenPorts}}<tr><td>{{.Host}}</td><td>{{.Port}}</td><td>{{.Service}}</td><td>{{.Confidence}}</td><td><code>{{.Banner}}</code></td></tr>{{end}}
</table>{{end}}
{{if .PortsErr}}<h2>端口扫描</h2><p>⚠ 未执行：{{.PortsErr}}</p>{{end}}

{{if .Tech}}<h2>HTTP 指纹与冲突检测</h2>
<table><tr><th>URL</th><th>状态</th><th>Server</th><th>JARM</th><th>技术栈</th><th>冲突</th></tr>
{{range $i, $t := .Tech}}{{if $t}}<tr><td>{{$t.URL}}</td><td>{{if $t.Err}}ERR{{else}}{{$t.StatusCode}}{{end}}</td><td>{{$t.Server}}</td><td><code>{{short $t.JARM 16}}</code></td><td>{{join $t.BodyKeywords "/"}}</td><td>{{conflictMark $.Conflicts $i}}</td></tr>{{end}}{{end}}
</table>
{{range $i, $cr := .Conflicts}}{{if $cr}}{{if $cr.Conflicts}}{{range $cr.Conflicts}}<div class="chg"><strong>{{.Title}}</strong>（{{.Type}}）<p>{{.Implication}}</p></div>{{end}}{{end}}{{end}}{{end}}
{{end}}

{{if .QUIC}}<h2>QUIC / UDP-443 探活</h2>
<table><tr><th>主机</th><th>状态</th><th>实现提示</th></tr>
{{range .QUIC}}<tr><td><code>{{.Host}}</code></td><td>{{.State}}</td><td>{{.StackHint}}</td></tr>{{end}}
</table>{{end}}

{{if .IPInfo}}<h2>IP 归属</h2>
<table><tr><th>IP</th><th>归属</th><th>ASN</th><th>ISP</th><th>标签</th></tr>
{{range .IPInfo}}{{if .}}<tr><td><code>{{.IP}}</code></td><td>{{.CountryCode}}/{{.City}}</td><td>AS{{.ASN}}</td><td>{{.ISP}}</td><td>{{join .Flags "/"}}</td></tr>{{end}}{{end}}
</table>{{end}}

{{if .RDNS}}<h2>rDNS 反查</h2>
<table><tr><th>IP</th><th>PTR</th></tr>
{{range .RDNS}}{{if .}}{{if .Hostnames}}<tr><td><code>{{.IP}}</code></td><td>{{join .Hostnames ", "}}</td></tr>{{end}}{{end}}{{end}}
</table>{{end}}

<footer>由 {{.Tool}} 生成。{{.Disclaimer}}</footer>
</body>
</html>
`

// WriteHTML 生成自包含 HTML 报告（内联样式、无外部资源）
func WriteHTML(w io.Writer, rep *Report) error {
	if rep == nil {
		return fmt.Errorf("报告为空")
	}
	view := &htmlView{
		Target:     rep.Target,
		Generated:  reportTime(),
		Tool:       reportTool,
		Disclaimer: strings.ReplaceAll(reportDisclaimer, "**", ""),
		Counts:     countReport(rep),
		Findings:   sortedFindings(rep),
		Diff:       rep.Diff,
		DNS:        rep.DNS,
		Domain:     rep.Domain,
		CT:         rep.CT,
		Passive:    rep.Passive,
		PortsErr:   rep.PortsErr,
		Tech:       rep.Tech,
		Conflicts:  rep.TechConflicts,
		QUIC:       rep.QUIC,
		IPInfo:     rep.IPInfo,
		RDNS:       rep.RDNS,
	}
	if rep.DNS != nil {
		view.RecordTypes = sortedRecordTypes(rep.DNS.Records)
	}
	if rep.Domain != nil {
		view.DomainKeys = sortedKeys(rep.Domain.Events)
	}
	if rep.Passive != nil {
		view.PassiveSubs = rep.Passive.Subdomains()
		view.Timeline = timelineChain(rep.Passive.Timeline, rep.Target)
	}
	for _, p := range rep.Ports {
		if p.Open() {
			view.OpenPorts = append(view.OpenPorts, p)
		}
	}

	funcs := template.FuncMap{
		"levelIcon": LevelIcon,
		"fmtTime": func(t time.Time) string {
			if t.IsZero() {
				return "?"
			}
			return t.Local().Format("2006-01-02 15:04")
		},
		"fmtDate": func(t time.Time) string {
			if t.IsZero() {
				return "?"
			}
			return t.Format("2006-01-02")
		},
		"join": strings.Join,
		"short": func(s string, n int) string {
			return truncateS(s, n)
		},
		"sub": func(a, b int) int { return a - b },
		"conflictMark": func(reports []*httpprobe.ConflictReport, i int) string {
			if i < len(reports) && reports[i] != nil {
				if n := len(reports[i].Conflicts); n > 0 {
					return fmt.Sprintf("⚠ %d", n)
				}
			}
			return "—"
		},
	}
	t, err := template.New("report").Funcs(funcs).Parse(htmlReportTmpl)
	if err != nil {
		return fmt.Errorf("模板错误: %w", err)
	}
	return t.Execute(w, view)
}
