package recon

import (
	"fmt"
	"io"
	"sort"
	"time"
)

// ⭐⭐ 本地资产时间线（P2-1 的"零依赖"半边）
//
// 数据来源：**本地快照累积**（recon --snapshot 存下的历史）。
// 每次运行都是一次观测；把多次观测合并即可得出：
//   - 每个 IP / 子域 / 端口的首见与末见时间
//   - "何时迁移、迁移到哪"（IP 迁移轨迹）
//
// 与 OTX 外部时间线互补：
//   - OTX 有接入工具**之前**的历史（需要 API key）
//   - 本地时间线从第一次快照开始积累，**零外部依赖**，永远可用

// AssetSpan 一个资产在快照历史中的存续区间
type AssetSpan struct {
	Key       string    `json:"key"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Present 最新快照中是否仍存在
	Present bool `json:"present"`
	// Snapshots 在多少个快照中出现过
	Snapshots int `json:"snapshots"`
}

// LocalTimeline 本地快照聚合出的资产时间线
type LocalTimeline struct {
	Target     string      `json:"target"`
	Snapshots  int         `json:"snapshots"`
	From       time.Time   `json:"from"`
	To         time.Time   `json:"to"`
	IPs        []AssetSpan `json:"ips,omitempty"`
	Subdomains []AssetSpan `json:"subdomains,omitempty"`
	Ports      []AssetSpan `json:"ports,omitempty"`
}

// BuildLocalTimeline 从快照序列（从旧到新）聚合时间线
func BuildLocalTimeline(snaps []*Snapshot) *LocalTimeline {
	// 过滤 nil 后再判断
	valid := make([]*Snapshot, 0, len(snaps))
	for _, s := range snaps {
		if s != nil {
			valid = append(valid, s)
		}
	}
	if len(valid) == 0 {
		return nil
	}
	tl := &LocalTimeline{
		Target:    NormalizeTarget(valid[len(valid)-1].Target),
		Snapshots: len(valid),
		From:      valid[0].TakenAt,
		To:        valid[len(valid)-1].TakenAt,
	}
	ips := map[string]*AssetSpan{}
	subs := map[string]*AssetSpan{}
	ports := map[string]*AssetSpan{}

	touch := func(m map[string]*AssetSpan, key string, at time.Time, present bool) {
		s, ok := m[key]
		if !ok {
			s = &AssetSpan{Key: key, FirstSeen: at}
			m[key] = s
		}
		if at.After(s.LastSeen) {
			s.LastSeen = at
		}
		s.Present = present
		s.Snapshots++
	}

	for i, snap := range valid {
		last := i == len(valid)-1
		for _, ip := range snap.IPs {
			touch(ips, ip, snap.TakenAt, last)
		}
		for _, sub := range snap.Subdomains {
			touch(subs, sub, snap.TakenAt, last)
		}
		for _, p := range snap.OpenPorts {
			touch(ports, portKey(p.IP, p.Host, p.Port), snap.TakenAt, last)
		}
	}

	tl.IPs = spansSorted(ips)
	tl.Subdomains = spansSorted(subs)
	tl.Ports = spansSorted(ports)
	return tl
}

// spansSorted map → 按首见时间排序的切片（同时间按 Key）
func spansSorted(m map[string]*AssetSpan) []AssetSpan {
	out := make([]AssetSpan, 0, len(m))
	for _, s := range m {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.Before(out[j].FirstSeen)
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// WriteLocalTimeline 渲染本地时间线
func WriteLocalTimeline(w io.Writer, tl *LocalTimeline) {
	if tl == nil {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "【资产时间线】%s（基于 %d 个本地快照 | %s → %s）\n",
		tl.Target, tl.Snapshots,
		tl.From.Local().Format("2006-01-02"), tl.To.Local().Format("2006-01-02"))

	writeSpans := func(title string, spans []AssetSpan, limit int) {
		if len(spans) == 0 {
			return
		}
		fmt.Fprintf(w, "  %s:\n", title)
		for i, s := range spans {
			if i >= limit {
				fmt.Fprintf(w, "     …（还有 %d 个）\n", len(spans)-limit)
				break
			}
			last := "现在"
			state := "存在"
			if !s.Present {
				last = s.LastSeen.Local().Format("2006-01-02")
				state = "已消失"
			}
			fmt.Fprintf(w, "     %-42s %s → %-10s [%s]\n",
				truncateS(s.Key, 42),
				s.FirstSeen.Local().Format("2006-01-02"), last, state)
		}
	}
	writeSpans("⭐ 解析 IP（迁移轨迹，按首次出现排序）", tl.IPs, 15)
	writeSpans("子域", tl.Subdomains, 20)
	writeSpans("开放端口", tl.Ports, 20)
}
