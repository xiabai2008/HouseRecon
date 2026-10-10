package ipinfo

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

// ── 表格输出（给人看）────────────────────────────────────

// WriteTable 输出对齐表格
func WriteTable(w io.Writer, results []*Info, showGeo, showRdns bool) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	header := "IP\t归属\tASN\tISP/Org\t类型标签\t标签依据"
	switch {
	case showRdns:
		header = "IP\t归属\tASN\tISP/Org\tPTR 反查\t类型标签\t标签依据"
	case showGeo:
		header = "IP\t归属\t经纬度\t时区\tASN\tISP/Org\t类型标签\t标签依据"
	}
	fmt.Fprintln(tw, header)

	// 已查询的列顺序：有效 → 无效
	for _, r := range results {
		if !r.Valid {
			reason := r.Err
			if reason == "" {
				reason = "无数据"
			}
			fmt.Fprintf(tw, "%s\t—\t—\t—\t—\t%s\n", r.IP, truncate(reason, 40))
			continue
		}

		asnStr := "-"
		if r.ASN != 0 {
			asnStr = "AS" + strconv.FormatUint(uint64(r.ASN), 10)
		}
		isp := r.ISP
		if isp == "" {
			isp = r.Org
		}
		label := r.Label()
		if label == "-" {
			label = "-"
		}

		// 标签依据：说明标签是"关键字匹配"(可靠) 还是"上游标签"(可能误报)
		labelBasis := flagBasis(r.FlagSources)
		// 数据来源：哪些字段来自哪个 API
		var src string
		switch {
		case r.Cached:
			src = "cache"
		case r.SourceSecondary != "":
			src = r.SourcePrimary + "+" + r.SourceSecondary
		default:
			src = r.SourcePrimary
		}
		if labelBasis != "" {
			src += " " + labelBasis
		}

		if showRdns {
			// ⭐ PTR 列：未配置时明确写"未配置 PTR"，
			//   不留空 —— 空值会被误读成"没查"而不是"没配"
			ptr := r.ReverseHosts()
			if ptr == "" {
				ptr = "（未配置 PTR）"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				r.IP, r.Location(), asnStr,
				truncate(isp, 26), truncate(ptr, 34), label, src)
		} else if showGeo {
			geo := "-"
			if r.Latitude != 0 || r.Longitude != 0 {
				geo = fmt.Sprintf("%.4f,%.4f", r.Latitude, r.Longitude)
			}
			tz := r.Timezone
			if tz == "" {
				tz = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				r.IP, r.Location(), geo, tz, asnStr,
				truncate(isp, 26), label, src)
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
				r.IP, r.Location(), asnStr,
				truncate(isp, 30), label, src)
		}
	}
	tw.Flush()
}

// ── CSV 输出（给 Excel）──────────────────────────────────

// CSVHeaders 是 CSV 表头
var CSVHeaders = []string{
	"ip", "valid", "type", "country", "country_code", "region", "city",
	"latitude", "longitude", "timezone", "asn", "as_org", "org", "isp", "domain",
	"hosting", "proxy", "mobile", "has_ptr", "hostnames", "flags", "flag_sources", "source", "error",
}

// WriteCSV 输出 CSV
func WriteCSV(w io.Writer, results []*Info) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write(CSVHeaders); err != nil {
		return err
	}
	for _, r := range results {
		asn := ""
		if r.ASN != 0 {
			asn = "AS" + strconv.FormatUint(uint64(r.ASN), 10)
		}
		src := r.SourcePrimary
		if r.SourceSecondary != "" {
			src += "+" + r.SourceSecondary
		}
		row := []string{
			r.IP, boolStr(r.Valid), r.Type, r.Country, r.CountryCode,
			r.Region, r.City,
			trimFloat(r.Latitude), trimFloat(r.Longitude), r.Timezone,
			asn, r.ASOrg, r.Org, r.ISP, r.Domain,
			boolStr(r.Hosting), boolStr(r.Proxy), boolStr(r.Mobile),
			boolStr(r.HasPTR), strings.Join(r.Hostnames, "|"),
			strings.Join(r.Flags, "|"), strings.Join(r.FlagSources, "|"),
			src, r.Err,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// WriteCSVFile 输出 CSV 到文件
func WriteCSVFile(path string, results []*Info) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return WriteCSV(f, results)
}

// ── JSON 输出（给机器）───────────────────────────────────

// WriteJSON 输出 JSON
func WriteJSON(w io.Writer, results []*Info, stats *Stats) error {
	out := struct {
		Results []*Info `json:"results"`
		Stats   *Stats  `json:"stats,omitempty"`
	}{Results: results, Stats: stats}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

// WriteJSONFile 输出 JSON 到文件
func WriteJSONFile(path string, results []*Info, stats *Stats) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return WriteJSON(f, results, stats)
}

// ── 纯 IP 列表输出（喂给下游工具）────────────────────────

// WriteIPS 仅输出有效 IP，每行一个。用于串进 nmap / httpx 等。
func WriteIPS(w io.Writer, results []*Info) {
	for _, r := range results {
		if r.Valid {
			fmt.Fprintln(w, r.IP)
		}
	}
}

// WriteIPSFile 输出有效 IP 到文件
func WriteIPSFile(path string, results []*Info) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	WriteIPS(f, results)
	return nil
}

// ── 统计 ─────────────────────────────────────────────────

// Stats 汇总统计
type Stats struct {
	Total      int            `json:"total"`
	Valid      int            `json:"valid"`
	Invalid    int            `json:"invalid"`
	Cached     int            `json:"cached"`
	FromAPI    int            `json:"from_api"`
	FlagCounts map[string]int `json:"flag_counts,omitempty"`
	Countries  map[string]int `json:"countries,omitempty"`
	TopASN     int            `json:"top_asn_count,omitempty"`
}

// Summarize 汇总统计
func Summarize(results []*Info) *Stats {
	s := &Stats{
		Total:      len(results),
		FlagCounts: map[string]int{},
		Countries:  map[string]int{},
	}
	asnCount := map[uint]int{}
	for _, r := range results {
		if r.Valid {
			s.Valid++
			if r.Cached {
				s.Cached++
			} else {
				s.FromAPI++
			}
			for _, f := range r.Flags {
				s.FlagCounts[f]++
			}
			if r.CountryCode != "" {
				s.Countries[r.CountryCode]++
			}
			if r.ASN != 0 {
				asnCount[r.ASN]++
			}
		} else {
			s.Invalid++
		}
	}
	for _, n := range asnCount {
		if n > s.TopASN {
			s.TopASN = n
		}
	}
	if len(s.FlagCounts) == 0 {
		s.FlagCounts = nil
	}
	if len(s.Countries) == 0 {
		s.Countries = nil
	}
	return s
}

// PrintSummary 输出统计摘要
func PrintSummary(w io.Writer, s *Stats) {
	fmt.Fprintln(w, strings.Repeat("─", 70))
	fmt.Fprintf(w, "共 %d 个 IP | 有效 %d | 无效 %d | 缓存命中 %d | API 查询 %d\n",
		s.Total, s.Valid, s.Invalid, s.Cached, s.FromAPI)

	if len(s.Countries) > 0 {
		type kv struct {
			K string
			V int
		}
		var list []kv
		for k, v := range s.Countries {
			list = append(list, kv{k, v})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].V > list[j].V })
		fmt.Fprint(w, "国家分布: ")
		for i, e := range list {
			if i >= 8 {
				fmt.Fprintf(w, " …(共 %d 个国家/地区)", len(list))
				break
			}
			if i > 0 {
				fmt.Fprint(w, "  ")
			}
			fmt.Fprintf(w, "%s=%d", e.K, e.V)
		}
		fmt.Fprintln(w)
	}

	if len(s.FlagCounts) > 0 {
		type kv struct {
			K string
			V int
		}
		var list []kv
		for k, v := range s.FlagCounts {
			list = append(list, kv{k, v})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].V > list[j].V })
		fmt.Fprint(w, "类型标签: ")
		for i, e := range list {
			if i > 0 {
				fmt.Fprint(w, "  ")
			}
			fmt.Fprintf(w, "%s=%d", e.K, e.V)
		}
		fmt.Fprintln(w)
	}

	// ⭐ 关键提示：CDN / hosting 节点会干扰端口扫描结论
	if n := s.FlagCounts["proxy?"]; n > 0 {
		fmt.Fprintf(w,
			"⚠ %d 个 IP 被上游标记为 proxy —— **该标记实测存在误报**\n"+
				"  （如 114DNS 等公共 DNS 会被误判），使用前请自行核实。\n", n)
	}
	if n := s.FlagCounts["cdn"]; n > 0 {
		fmt.Fprintf(w,
			"\n⚠ %d 个 IP 被标记为 CDN 边缘节点。\n"+
				"  对这些 IP 做端口扫描得到的是 CDN 边缘的结果，不是源站的。\n"+
				"  要扫源站，需要先做 CDN 绕过（查历史 DNS / 证书 / rDNS）。\n", n)
	}
	if n := s.FlagCounts["hosting"]; n > 0 {
		fmt.Fprintf(w, "⚠ %d 个 IP 是数据中心/云主机（hosting），非住宅网络。\n", n)
	}
}

// ── 工具 ─────────────────────────────────────────────────

// flagBasis 概括标签依据的可信度
//
// ⭐ 为什么要区分：实测发现 ip-api.com 的 proxy 标记会误报
// （114.114.114.114 公共 DNS 被标为 proxy）。
// 所以"上游标签"必须显式标注，提醒使用者自行判断。
func flagBasis(sources []string) string {
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
		return "(org+api)"
	case hasOrg:
		return "(org)"
	case hasAPI:
		return "(api待核)" // ⭐ 上游标签，可能误报
	default:
		return ""
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func trimFloat(f float64) string {
	if f == 0 {
		return ""
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func truncate(s string, n int) string {
	// 注意：按 rune 截断，避免截断多字节字符
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}
