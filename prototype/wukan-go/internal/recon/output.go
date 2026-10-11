package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/wukan/wukan/internal/httpprobe"
	"github.com/wukan/wukan/internal/portscan"
	"github.com/wukan/wukan/internal/quic"
)

// WriteText 输出人类可读的信息卡
func WriteText(w io.Writer, rep *Report, maxSubs int) {
	if rep == nil {
		return
	}
	rule := strings.Repeat("═", 74)

	fmt.Fprintln(w, rule)
	fmt.Fprintf(w, " 屋勘 HouseRecon — 目标信息卡: %s\n", rep.Target)
	fmt.Fprintln(w, rule)

	// ── 可行动发现（放最前面，这是最有价值的部分）──
	if len(rep.Findings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "【可行动发现】")
		// 高严重度排前面
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
		for _, f := range fs {
			fmt.Fprintf(w, "  %s [%s] %s\n", LevelIcon(f.Level), f.Type, f.Title)
			if f.Detail != "" {
				for _, line := range strings.Split(f.Detail, "\n") {
					fmt.Fprintf(w, "       %s\n", line)
				}
			}
			for i, e := range f.Evidence {
				if e == "" {
					continue
				}
				prefix := "       └ 证据: "
				if i < len(f.Evidence)-1 {
					prefix = "       ├ 证据: "
				}
				fmt.Fprintf(w, "%s%s\n", prefix, e)
			}
		}
	}

	// ── 与上次快照的差异（变化监控，--snapshot 时）──
	// ⭐ 紧跟可行动发现之后：监控场景下"变了什么"是最先要看的
	if rep.Diff != nil {
		WriteDiff(w, rep.Diff)
	}

	// ── DNS ──
	if rep.DNS != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "【DNS 解析】", rep.DNS.Resolver)
		if rep.DNS.Err != "" {
			fmt.Fprintf(w, "  ⚠ %s\n", rep.DNS.Err)
		}
		order := []RecordType{TypeA, TypeAAAA, TypeCNAME, TypeNS, TypeMX, TypeTXT, TypeSOA}
		for _, t := range order {
			recs := rep.DNS.Get(t)
			if len(recs) == 0 {
				continue
			}
			vals := make([]string, 0, len(recs))
			for _, r := range recs {
				v := r.Value
				if len(v) > 60 {
					v = v[:57] + "..."
				}
				vals = append(vals, v)
			}
			limit := 6
			line := strings.Join(vals, ", ")
			if len(vals) > limit {
				line = strings.Join(vals[:limit], ", ") +
					fmt.Sprintf(" …(共 %d 条)", len(vals))
			}
			fmt.Fprintf(w, "  %-6s %s\n", t+":", line)
		}
		if rep.DNS.Wildcard != "" {
			fmt.Fprintf(w, "  %-6s → %s  ⚠ 检测到泛域名解析\n", "*.域:", rep.DNS.Wildcard)
		}
	}

	// ── 域名注册信息 ──
	if rep.Domain != nil && rep.Domain.Err == "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "【域名注册信息】", rep.Domain.Source)
		if age, ok := rep.Domain.Age(); ok {
			fmt.Fprintf(w, "  注册时长   %s\n", humanDuration(age))
		}
		if reg, ok := rep.Domain.Events["registration"]; ok {
			fmt.Fprintf(w, "  注册时间   %s\n", formatTime(reg))
		}
		if exp, ok := rep.Domain.Events["expiration"]; ok {
			line := "  过期时间   " + formatTime(exp)
			if d, ok := rep.Domain.ExpiresIn(); ok {
				if d < 0 {
					line += fmt.Sprintf("  ⚠ 已过期 %d 天", int(-d.Hours()/24))
				} else {
					line += fmt.Sprintf("  (剩余 %d 天)", int(d.Hours()/24))
				}
			}
			fmt.Fprintln(w, line)
		}
		if l := rep.Domain.lockedStatus(); l != "" {
			fmt.Fprintf(w, "  %s\n", l)
		}
		if rep.Domain.Registrar != "" {
			fmt.Fprintf(w, "  注册商     %s\n", rep.Domain.Registrar)
		}
		if rep.Domain.Registrant != "" {
			fmt.Fprintf(w, "  注册人     %s\n", rep.Domain.Registrant)
		}
		if len(rep.Domain.Nameservers) > 0 {
			ns := rep.Domain.Nameservers
			line := strings.Join(ns, ", ")
			if len(line) > 68 {
				line = strings.Join(ns[:min(len(ns), 3)], ", ") +
					fmt.Sprintf(" …(共 %d 个)", len(ns))
			}
			fmt.Fprintf(w, "  NS         %s\n", line)
		}
		fmt.Fprintf(w, "  DNSSEC     %s\n", enabledStr(rep.Domain.SecureDNS))
	} else if rep.Domain != nil && rep.Domain.Err != "" {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "【域名注册信息】⚠ %s\n", rep.Domain.Err)
	}

	// ── 子域（证书透明度）──
	if rep.CT != nil {
		fmt.Fprintln(w)
		srcs := strings.Join(rep.CT.SourcesUsed, "+")
		if srcs == "" {
			srcs = "无可用源"
		}
		fmt.Fprintf(w, "【证书透明度 · 子域】源: %s  原始条目: %d  去重: %d\n",
			srcs, rep.CT.TotalEntries, len(rep.CT.Subdomains))

		if len(rep.CT.SourcesFailed) > 0 {
			var fl []string
			for k, v := range rep.CT.SourcesFailed {
				fl = append(fl, k+" ("+truncate(v, 40)+")")
			}
			sort.Strings(fl)
			fmt.Fprintf(w, "  ⚠ 失败源: %s\n", strings.Join(fl, "; "))
		}

		if len(rep.CT.Subdomains) > 0 {
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "  子域\t状态\t首次出现\t最后出现\t证书数\tIP")
			n := len(rep.CT.Subdomains)
			if maxSubs > 0 && n > maxSubs {
				n = maxSubs
			}
			for _, s := range rep.CT.Subdomains[:n] {
				status := "不解析"
				if s.Resolves {
					status = "✓ 存活"
					if s.IsWildcard {
						status += "(泛)"
					}
				}
				first := "—"
				if !s.FirstSeen.IsZero() {
					first = s.FirstSeen.Format("2006-01-02")
				}
				last := "—"
				if !s.LastSeen.IsZero() {
					last = s.LastSeen.Format("2006-01-02")
				}
				ips := "—"
				if len(s.ResolveIPs) > 0 {
					ips = s.ResolveIPs[0]
					if len(s.ResolveIPs) > 1 {
						ips += fmt.Sprintf("(+%d)", len(s.ResolveIPs)-1)
					}
				}
				stars := ""
				if s.CertCount > 3 {
					stars = " ★"
				}
				fmt.Fprintf(tw, "  %s%s\t%s\t%s\t%s\t%d\t%s\n",
					s.Name, stars, status, first, last, s.CertCount, ips)
			}
			tw.Flush()
			if len(rep.CT.Subdomains) > n {
				fmt.Fprintf(w, "  …(还有 %d 个，用 -n 调整显示数量或 -o json 看全部)\n",
					len(rep.CT.Subdomains)-n)
			}
			fmt.Fprintf(w, "\n  图例: ★ = 出现在 3+ 张证书（更可能是真实在用的资产）\n")
		}
	}

	// ── 被动 DNS（历史解析）──
	if rep.Passive != nil && len(rep.Passive.Records) > 0 {
		fmt.Fprintln(w)
		srcs := strings.Join(rep.Passive.SourcesUsed, "+")
		if srcs == "" {
			srcs = "无可用源"
		}
		fmt.Fprintf(w, "【被动 DNS · 历史解析】源: %s  子域 %d 个  IP 关联 %d 条\n",
			srcs, len(rep.Passive.Records), rep.Passive.TotalEntries)
		if len(rep.Passive.SourcesFailed) > 0 {
			var fl []string
			for k, v := range rep.Passive.SourcesFailed {
				fl = append(fl, k+" ("+truncate(v, 34)+")")
			}
			sort.Strings(fl)
			fmt.Fprintf(w, "  ⚠ 失败: %s\n", strings.Join(fl, "; "))
		}

		subs := rep.Passive.Subdomains()
		const limit = 12
		for i, host := range subs {
			if i >= limit {
				fmt.Fprintf(w, "  …(还有 %d 个)\n", len(subs)-limit)
				break
			}
			ips := rep.Passive.Records[host]
			line := strings.Join(ips, ", ")
			if len(line) > 66 {
				line = strings.Join(ips[:min(len(ips), 2)], ", ") +
					fmt.Sprintf(" …(共 %d)", len(ips))
			}
			// 标出与当前解析不一致的
			mark := " "
			if rep.DNS != nil && len(rep.DNS.IPs) > 0 {
				mismatch := false
				for _, ip := range ips {
					found := false
					for _, cur := range rep.DNS.IPs {
						if cur == ip {
							found = true
							break
						}
					}
					if !found {
						mismatch = true
						break
					}
				}
				if mismatch && host != rep.Target {
					mark = "⚠"
				}
			}
			fmt.Fprintf(w, "  %s %-42s %s\n", mark, truncate(host, 42), line)
		}
	}

	// ── 被动 DNS 时间线（P2-1：何时迁移、迁移到哪）──
	if rep.Passive != nil && len(rep.Passive.Timeline) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "【被动 DNS 时间线】记录 %d 条（带时间戳的历史解析）\n",
			len(rep.Passive.Timeline))
		// ⭐ 根域的迁移轨迹（最有价值的部分）
		rootChain := timelineChain(rep.Passive.Timeline, rep.Target)
		if len(rootChain) > 0 {
			fmt.Fprintf(w, "  ⭐ %s 的迁移轨迹（按首次出现排序）:\n", rep.Target)
			for _, e := range rootChain {
				first := "?"
				if !e.FirstSeen.IsZero() {
					first = e.FirstSeen.Format("2006-01-02")
				}
				last := "现在"
				if !e.LastSeen.IsZero() {
					last = e.LastSeen.Format("2006-01-02")
				}
				fmt.Fprintf(w, "     %-42s %s → %s\n", e.IP, first, last)
			}
		}
		// 其余主机名概览（完整时间线在 JSON 的 timeline 字段）
		hosts := map[string]bool{}
		for _, e := range rep.Passive.Timeline {
			hosts[e.Hostname] = true
		}
		if len(hosts) > 1 {
			fmt.Fprintf(w, "  其余 %d 个主机名的时间线见 JSON（timeline 字段）\n",
				len(hosts)-1)
		}
	}

	// ── 同源资产（IP 反查）──
	if len(rep.ReverseIP) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "【同源资产 · IP 反查】")
		for _, r := range rep.ReverseIP {
			if r == nil || len(r.Hostnames) == 0 {
				continue
			}
			// 共享基础设施噪音抑制（与分析层阈值保持一致）
			if len(r.Hostnames) > 50 {
				fmt.Fprintf(w, "  %s — %d 个虚拟主机（共享 CDN/云节点，非本域资产）⚠ 已抑制\n",
					r.IP, len(r.Hostnames))
				continue
			}
			fmt.Fprintf(w, "  %s (%d 个主机名)\n", r.IP, len(r.Hostnames))
			for i, h := range r.Hostnames {
				if i >= 6 {
					fmt.Fprintf(w, "      …(还有 %d 个)\n", len(r.Hostnames)-6)
					break
				}
				fmt.Fprintf(w, "      %s\n", h)
			}
		}
	}

	// ── IP 归属 ──
	if len(rep.IPInfo) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "【IP 归属】")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  IP\t归属\tASN\tISP/Org\t标签\t依据")
		for _, ip := range rep.IPInfo {
			if ip == nil {
				continue
			}
			if !ip.Valid {
				fmt.Fprintf(tw, "  %s\t—\t—\t—\t—\t%s\n", ip.IP, truncate(ip.Err, 24))
				continue
			}
			asn := "—"
			if ip.ASN != 0 {
				asn = "AS" + strconv.FormatUint(uint64(ip.ASN), 10)
			}
			isp := ip.ISP
			if isp == "" {
				isp = ip.Org
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
				ip.IP, ip.Location(), asn, truncate(isp, 24),
				ip.Label(), flagBasisShort(ip.FlagSources))
		}
		tw.Flush()
	}

	// ── QUIC 探活（主动探测）──
	if len(rep.QUIC) > 0 {
		fmt.Fprintln(w)
		sum := quicSum(rep.QUIC)
		fmt.Fprintf(w, "【QUIC / UDP-443 探活】⭐主动探测  确认 %d / 共 %d\n",
			sum.quic, sum.total)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  IP\t状态\tRTT\t确认\t实现归属\t版本")
		for _, q := range rep.QUIC {
			state := "无响应"
			if q.IsQUIC() {
				state = "✓ QUIC 存活"
			} else if q.State.String() == "NON_QUIC_RESP" {
				state = "非 QUIC"
			}
			rtt := "-"
			if q.RTT > 0 {
				rtt = fmt.Sprintf("%.1fms", float64(q.RTT.Microseconds())/1000)
			}
			confirm := "-"
			if q.ProbesSent > 0 {
				confirm = fmt.Sprintf("%d/%d", q.ProbesConfirmed, q.ProbesSent)
			}
			hint := q.StackHint
			if hint == "" {
				hint = "-"
			}
			vers := q.VersionText()
			if vers == "" {
				vers = "-"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
				q.Host, state, rtt, confirm, hint, vers)
		}
		tw.Flush()
		if sum.quic > 0 {
			fmt.Fprintf(w, "\n  ⭐ 这 %d 个 IP 的 UDP/443 运行 QUIC/HTTP/3。\n", sum.quic)
			fmt.Fprintln(w, "     ⚠ 传统 TCP-only 扫描器（naabu/httpx/Shodan/Censys/ZMap）看不到它们。")
		}
	}

	// ── rDNS 反查 ──
	if len(rep.RDNS) > 0 {
		fmt.Fprintln(w)
		withPTR, generic, specific := 0, 0, 0
		for _, r := range rep.RDNS {
			if r == nil {
				continue
			}
			if !r.HasPTR {
				continue
			}
			withPTR++
			c := r.Classify()
			generic += len(c.Generic)
			specific += len(c.Specific)
		}
		fmt.Fprintf(w, "【rDNS 反查】%d/%d 个 IP 配置了 PTR | 泛用名 %d | 具体域名 %d\n",
			withPTR, len(rep.RDNS), generic, specific)

		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  IP\tPTR 反查\t类型")
		for _, r := range rep.RDNS {
			if r == nil {
				continue
			}
			ptr := "（未配置）"
			kind := "-"
			if r.HasPTR {
				c := r.Classify()
				ptr = strings.Join(r.Hostnames, ", ")
				kind = "泛用主机名"
				if len(c.Specific) > 0 {
					kind = "⭐具体域名"
				}
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", r.IP, truncateStr(ptr, 52), kind)
		}
		tw.Flush()
		if generic > 0 {
			fmt.Fprintln(w, "  ⭐ 泛用名（ecs-xxx.compute.*）只说明是某台云主机，推不出上面跑了什么站点")
		}
	}

	// ── 端口扫描 ──
	if rep.PortsErr != "" {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "【端口扫描】⛔ 未执行: %s\n", rep.PortsErr)
	} else if len(rep.Ports) > 0 {
		fmt.Fprintln(w)
		ps := portscan.Summarize(rep.Ports)
		fmt.Fprintf(w, "【端口扫描】⭐主动探测  %d 个端口 | 开放 %d | 关闭 %d | 过滤 %d\n",
			ps.Total, ps.Open, ps.Closed, ps.Filtered)

		var opens []portscan.PortResult
		for _, p := range rep.Ports {
			if p.Open() {
				opens = append(opens, p)
			}
		}
		if len(opens) == 0 {
			fmt.Fprintln(w, "  （指定端口范围内无开放服务）")
		} else {
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "  IP\t端口\tRTT\t服务\t置信\tbanner")
			for _, p := range opens {
				fmt.Fprintf(tw, "  %s\t%d\t%.1fms\t%s\t%d\t%s\n",
					p.IP, p.Port, p.RTTMs(), dashIfEmptyStr(p.Service),
					p.Confidence, dashIfEmptyStr(truncateStr(p.Banner, 44)))
			}
			tw.Flush()
		}
	}

	// ── HTTP 指纹 ──
	if rep.TechErr != "" {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "【HTTP 指纹】⛔ 未执行: %s\n", rep.TechErr)
	} else if len(rep.Tech) > 0 {
		fmt.Fprintln(w)
		sum := httpprobe.Summarize(rep.TechConflicts)
		fmt.Fprintf(w, "【HTTP 指纹 · ⭐冲突检测】主动探测 %d 个 URL | 无冲突 %d | 有冲突 %d\n",
			len(rep.Tech), sum.Clean, sum.WithAny)

		// ⭐ 统计子域数量并标注
		subCount := 0
		for _, t := range rep.Tech {
			if t != nil && strings.HasPrefix(t.URL, "https://") &&
				!strings.HasPrefix(shortURLStr(t.URL), "") &&
				t.HostHeaderUsed != "" && t.HostHeaderUsed != rep.Target {
				subCount++
			}
		}
		if subCount > 0 {
			fmt.Fprintf(w, "  ⭐ 含 %d 个子域\n", subCount)
		}
		// ⭐ 降级重试透明化
		retried := 0
		for _, t := range rep.Tech {
			if t != nil && t.RetriedWith != "" {
				retried++
			}
		}
		if retried > 0 {
			fmt.Fprintf(w, "  ↻ %d 个目标经降级重试成功（跳过重定向 / http 回退）\n", retried)
		}
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  URL\t状态\tServer\tTLS\t技术栈\t冲突")
		for i, t := range rep.Tech {
			if t == nil {
				continue
			}
			status := fmt.Sprintf("%d", t.StatusCode)
			if t.Err != "" {
				status = "ERR"
			}
			conflictMark := "—"
			if i < len(rep.TechConflicts) && rep.TechConflicts[i] != nil {
				n := len(rep.TechConflicts[i].Conflicts)
				if n > 0 {
					conflictMark = fmt.Sprintf("⚠ %d", n)
				}
			}
			// ⭐ 降级重试必须如实标注（https 显示但数据来自 http 回退）
			u := truncateStr(t.URL, 34)
			if l := t.RetryLabel(); l != "" {
				u += "（" + l + "）"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
				u, status,
				dashIfEmptyStr(t.Server), dashIfEmptyStr(t.TLSVersion),
				dashIfEmptyStr(strings.Join(t.BodyKeywords, "/")), conflictMark)
		}
		tw.Flush()

		// 冲突详情
		for i, cr := range rep.TechConflicts {
			if cr == nil || len(cr.Conflicts) == 0 || i >= len(rep.Tech) {
				continue
			}
			for _, c := range cr.Conflicts {
				icon := "🔵"
				switch c.Severity {
				case "high":
					icon = "🔴"
				case "medium":
					icon = "🟡"
				}
				fmt.Fprintf(w, "\n%s [%s] %s", icon, c.Type, c.Title)
				fmt.Fprintf(w, "\n     %s", c.Detail)
				for _, src := range c.Sources {
					fmt.Fprintf(w, "\n     ├ %s（可信度 %s）: %s", src.Source, src.Trust, src.Says)
				}
				if c.Implication != "" {
					fmt.Fprintf(w, "\n     └ 判读: %s", c.Implication)
				}
			}
		}
	}

	// ── 耗时 ──
	if len(rep.Timing) > 0 {
		fmt.Fprintln(w)
		keys := make([]string, 0, len(rep.Timing))
		for k := range rep.Timing {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+rep.Timing[k])
		}
		fmt.Fprintf(w, "【耗时】%s | 总计 %s\n", strings.Join(parts, " "), rep.Total)
	}
	fmt.Fprintln(w, rule)
}

// WriteDiff 输出快照差异段
//
// ⭐ recon 报告内嵌（rep.Diff）与 `wukan diff` 命令共用同一渲染 ——
//
//	保证两个入口看到的变化格式完全一致。
func WriteDiff(w io.Writer, d *SnapshotDiff) {
	if d == nil {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "【与上次快照的差异】基准 %s（%s） → 最新 %s（%s） | 变化 %d 处\n",
		d.PrevAt.Local().Format("2006-01-02 15:04"), humanAge(time.Since(d.PrevAt)),
		d.CurrAt.Local().Format("2006-01-02 15:04"), humanAge(time.Since(d.CurrAt)),
		len(d.Changes))
	if len(d.Changes) == 0 {
		fmt.Fprintln(w, "  ✓ 与上次快照一致，无变化")
		return
	}
	for _, c := range d.Changes {
		fmt.Fprintf(w, "  %s [%s] %s", LevelIcon(c.Level), c.Kind, c.Target)
		if c.Before != "" || c.After != "" {
			fmt.Fprintf(w, "（%s → %s）", dashOr(c.Before), dashOr(c.After))
		}
		fmt.Fprintln(w)
		if c.Detail != "" {
			fmt.Fprintf(w, "       判读：%s\n", c.Detail)
		}
	}
}

// humanAge 粗粒度年龄（差异报告用）
func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "刚刚"
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d 小时前", int(d.Hours()))
	default:
		return fmt.Sprintf("%d 天前", int(d.Hours()/24))
	}
}

func flagBasisShort(sources []string) string {
	hasOrg, hasAPI := false, false
	for _, s := range sources {
		switch s {
		case "org", "self":
			hasOrg = true
		case "ip-api.com":
			hasAPI = true
		}
	}
	switch {
	case hasOrg && hasAPI:
		return "org+api"
	case hasOrg:
		return "org"
	case hasAPI:
		return "api待核"
	default:
		return "-"
	}
}

// WriteJSON 输出 JSON
func WriteJSON(w io.Writer, rep *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}

// WriteHosts 输出 hosts 文件格式（可直接 /etc/hosts）
func WriteHosts(w io.Writer, rep *Report) {
	if rep == nil {
		return
	}
	seen := map[string]bool{}
	if rep.DNS != nil {
		for _, ip := range rep.DNS.IPs {
			if !seen[ip] {
				seen[ip] = true
				fmt.Fprintf(w, "%s\t%s\n", ip, rep.Target)
			}
		}
	}
	if rep.CT != nil {
		for _, s := range rep.CT.Subdomains {
			for _, ip := range s.ResolveIPs {
				if !seen[ip] {
					seen[ip] = true
					fmt.Fprintf(w, "%s\t%s\n", ip, s.Name)
				}
			}
		}
	}
	// 被动 DNS 的历史映射（⚠ 是历史数据，导入 hosts 前需自行确认是否仍有效）
	if rep.Passive != nil {
		for _, host := range rep.Passive.Subdomains() {
			for _, ip := range rep.Passive.Records[host] {
				if !seen[ip] {
					seen[ip] = true
					fmt.Fprintf(w, "%s\t%s\n", ip, host)
				}
			}
		}
	}
}

// WriteSubdomains 输出纯子域列表
func WriteSubdomains(w io.Writer, rep *Report, onlyAlive bool) {
	if rep == nil || rep.CT == nil {
		return
	}
	seen := map[string]bool{}
	if rep.CT != nil {
		for _, s := range rep.CT.Subdomains {
			if s.IsWildcard {
				continue
			}
			if onlyAlive && !s.Resolves {
				continue
			}
			if !seen[s.Name] {
				seen[s.Name] = true
				fmt.Fprintln(w, s.Name)
			}
		}
	}
	// ⭐ 合并被动 DNS 发现的子域 —— 这部分没有证书记录，
	//    单独查 CT 是找不到的
	if !onlyAlive && rep.Passive != nil {
		for _, h := range rep.Passive.Subdomains() {
			if strings.HasPrefix(h, "*.") {
				continue
			}
			if !seen[h] {
				seen[h] = true
				fmt.Fprintln(w, h)
			}
		}
	}
}

func humanDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case days >= 3650:
		return fmt.Sprintf("%d 年 %d 天", days/365, (days%365)/1)
	case days >= 365:
		return fmt.Sprintf("%d 年 %d 天", days/365, (days % 365))
	case days >= 1:
		return fmt.Sprintf("%d 天", days)
	default:
		return fmt.Sprintf("%d 小时", int(d.Hours()))
	}
}

func formatTime(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.Format("2006-01-02")
}

func enabledStr(b bool) string {
	if b {
		return "已启用"
	}
	return "未启用"
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

type quicAgg struct {
	quic  int
	total int
}

func quicSum(rs []quic.Result) quicAgg {
	var a quicAgg
	for _, r := range rs {
		a.total++
		if r.IsQUIC() {
			a.quic++
		}
	}
	return a
}

// truncateStr 截断字符串（按 rune，避免截断多字节字符）
func truncateStr(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

// dashIfEmptyStr 空串转 "-"
func dashIfEmptyStr(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// shortURLStr 去掉 scheme 前缀
func shortURLStr(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	return u
}
