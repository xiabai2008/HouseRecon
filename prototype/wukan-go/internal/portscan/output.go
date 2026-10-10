package portscan

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// WriteTable 输出表格（只显示开放端口，符合扫描器习惯）
func WriteTable(w io.Writer, rs []PortResult, showAll bool) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	if showAll {
		fmt.Fprintln(tw, "  主机\t端口\t状态\tRTT\t服务\t置信\tbanner")
	} else {
		fmt.Fprintln(tw, "  主机\t端口\tRTT\t服务\t置信\tbanner")
	}

	for _, r := range rs {
		if !r.Open() && !showAll {
			continue
		}
		banner := dashIfEmpty(truncateStr(r.Banner, 46))
		// ⭐ 缓存行必须可辨认 —— 这不是本次实时探测的结果
		if r.Cached {
			banner += " [缓存]"
		}
		line := fmt.Sprintf("  %s\t%d\t%.1fms\t%s\t%d\t%s",
			r.Host, r.Port, r.RTTMs(), dashIfEmpty(r.Service), r.Confidence,
			banner)
		if showAll {
			line = fmt.Sprintf("  %s\t%d\t%s\t%.1fms\t%s\t%d\t%s",
				r.Host, r.Port, r.State, r.RTTMs(), dashIfEmpty(r.Service),
				r.Confidence, banner)
		}
		fmt.Fprintln(tw, line)
	}
	tw.Flush()
}

// WriteJSON 输出 JSON
func WriteJSON(w io.Writer, rs []PortResult, s Summary) error {
	out := struct {
		Summary Summary      `json:"summary"`
		Results []PortResult `json:"results"`
		Scanner string       `json:"scanner"`
	}{
		Summary: s,
		Results: rs,
		Scanner: "wukan-ports/0.1.0 (TCP connect)",
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

// WriteCSV 输出 CSV
func WriteCSV(w io.Writer, rs []PortResult) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{
		"host", "ip", "port", "state", "rtt_ms",
		"service", "confidence", "probe_method", "banner", "error", "cached",
	}); err != nil {
		return err
	}
	for _, r := range rs {
		if err := cw.Write([]string{
			r.Host, r.IP, strconv.Itoa(r.Port), string(r.State),
			strconv.FormatFloat(r.RTTMs(), 'f', 2, 64),
			r.Service, strconv.Itoa(r.Confidence), r.ProbeMethod,
			r.Banner, r.Err, strconv.FormatBool(r.Cached),
		}); err != nil {
			return err
		}
	}
	return nil
}

// WriteOpenPorts 只输出开放端口（host:port，一行一个，可喂给其他工具）
func WriteOpenPorts(w io.Writer, rs []PortResult) {
	for _, r := range rs {
		if r.Open() {
			fmt.Fprintf(w, "%s:%d\n", r.Host, r.Port)
		}
	}
}

// WriteOpenPortsOnly 只输出端口号
func WriteOpenPortsOnly(w io.Writer, rs []PortResult) {
	for _, r := range rs {
		if r.Open() {
			fmt.Fprintln(w, r.Port)
		}
	}
}

// WriteSummary 输出统计摘要
func WriteSummary(w io.Writer, s Summary, elapsed time.Duration) {
	fmt.Fprintln(w, strings.Repeat("─", 70))
	fmt.Fprintf(w, "扫描 %d 个主机 / %d 个端口 | 耗时 %.2fs\n",
		s.Hosts, s.Total, elapsed.Seconds())
	fmt.Fprintf(w, "  ✓ 开放   : %d\n", s.Open)
	fmt.Fprintf(w, "  ✗ 关闭   : %d\n", s.Closed)
	fmt.Fprintf(w, "  ? 过滤   : %d  （UDP/TCP 都无法区分 open|filtered 的固有局限）\n", s.Filtered)
	if s.Error > 0 {
		fmt.Fprintf(w, "  ! 错误   : %d\n", s.Error)
	}

	// ⭐ 关键局限说明 —— 必须让使用者知道 filtered 意味着什么
	if s.Filtered > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "ℹ 关于「过滤」状态：")
		fmt.Fprintln(w, "  连接超时无法区分「被防火墙丢掉的开放端口」与「不存在的端口」。")
		fmt.Fprintln(w, "  这是 TCP connect 扫描的固有局限 —— 要消除它必须做原始 SYN 扫描，")
		fmt.Fprintln(w, "  但那会重新引入 SYN Proxy 误报（AWS GA 等会对任何 SYN 回 SYN-ACK）。")
		fmt.Fprintln(w, "  当前实现**选择零误报**，宁可漏报也不误报。")
	}

	if s.LowConfidence > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w,
			"ℹ %d 个开放端口的置信度 < 70：\n"+
				"  这些端口开放但没抓到任何可识别的 banner。可能是：\n"+
				"   · 需要特定握手才能响应的服务（如 SMTP 先发 220 才回）\n"+
				"   · honeypot / 蜜罐\n"+
				"   · 非标准协议\n"+
				"  建议人工确认，不要直接当作真实服务。\n", s.LowConfidence)
	}
}

// ServiceBreakdown 按服务分组统计
func ServiceBreakdown(rs []PortResult) map[string][]string {
	out := map[string][]string{}
	for _, r := range rs {
		if !r.Open() {
			continue
		}
		svc := r.Service
		if svc == "" {
			svc = "unknown"
		}
		key := fmt.Sprintf("%s (%d)", svc, r.Port)
		out[key] = append(out[key], r.Host)
	}
	return out
}

// PrintServiceSummary 按服务分组打印
func PrintServiceSummary(w io.Writer, rs []PortResult) {
	groups := ServiceBreakdown(rs)
	if len(groups) == 0 {
		return
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "【按服务分组】")
	for _, k := range keys {
		hosts := groups[k]
		uniq := map[string]bool{}
		for _, h := range hosts {
			uniq[h] = true
		}
		var hl []string
		for h := range uniq {
			hl = append(hl, h)
		}
		sort.Strings(hl)
		if len(hl) > 4 {
			fmt.Fprintf(w, "  %-22s %d 个主机: %s …\n", k, len(hl),
				strings.Join(hl[:4], ", "))
		} else {
			fmt.Fprintf(w, "  %-22s %d 个主机: %s\n", k, len(hl), strings.Join(hl, ", "))
		}
	}
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

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
