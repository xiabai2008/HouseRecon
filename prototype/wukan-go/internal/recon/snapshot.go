package recon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ⭐⭐ 资产快照与变化监控（P1-1）
//
// 定位：单次 recon 是一次性的，**基线是复利的** ——
// 保存每次运行的资产快照，与上次对比出"新增/消失/变化"，
// 这正是"个人工具对抗商业 ASM 平台"的价值点（调研报告结论：
// "至少用两个引擎做两次查询取 diff，新出现的资产往往就是配置最粗糙的那批"）。
//
// 存储：~/.wukan/snapshots/<domain>.json，每个目标一个文件，
// 保留最近 DefaultSnapshotKeep 个快照（从旧到新）。
//
// ⭐⭐ 覆盖率（Coverage）是本模块最重要的防假阳性设计：
//
//	"不在本次快照里" ≠ "资产消失" —— 它也可能只是"本次没采这类数据"
//	（CT 源挂了、被动 DNS 限额、忘了带 --ports 参数……）。
//	快照记录**每类数据的采集是否完整**，差异引擎只对"两侧都完整"的
//	类别产出增删判定，否则输出一条 coverage_changed（不可比）说明。
//	（审查发现的 H1：没有覆盖率时，一次数据源故障会产出成片假"消失"。）

// DefaultSnapshotKeep 每个目标默认保留的快照数
const DefaultSnapshotKeep = 30

// snapshotHeartbeat 内容相同时的心跳间隔：
//
//	完全相同的快照在 24 小时内只留一条（避免高频运行刷爆历史，
//	把 keep=30 的窗口从"30 天"挤成"30 小时"）；超过 24 小时
//	即使内容相同也追加一条（"该内容在该时刻仍然成立"的心跳）。
const snapshotHeartbeat = 24 * time.Hour

// SnapshotCoverage 一次运行的采集覆盖情况
//
// ⭐ 判定口径（宁可保守，不可误报）：
//   - DNS：解析无错误（Err 为空）
//   - CT / Passive：至少有一个来源成功（SourcesUsed 非空；被动还需真的有记录）
//   - Ports：本次真的执行了端口扫描；PortsSpec 记录扫描参数
//   - Tech：本次真的执行了指纹采集（失败探测也是观测，计为已覆盖）
type SnapshotCoverage struct {
	DNS       bool   `json:"dns"`
	CT        bool   `json:"ct"`
	Passive   bool   `json:"passive"`
	Ports     bool   `json:"ports"`
	PortsSpec string `json:"ports_spec,omitempty"`
	// PortsIPs 本次实际扫描过的主机集合（排序）—— H5：diff 只对比
	// 两次都扫过的 IP，避免"子域选择集/解析 IP 漂移"产出假"新暴露端口"
	PortsIPs []string `json:"ports_ips,omitempty"`
	Tech     bool     `json:"tech"`
}

// SubdomainsOK 子域数据是否完整（CT 与被动 DNS 都必须成功 ——
// 子域列表是两者的并集，缺任何一边都可能把对方的名字误判为"消失"）
func (c SnapshotCoverage) SubdomainsOK() bool { return c.CT && c.Passive }

// Snapshot 一次 recon 运行的资产快照
//
// ⭐ 只存**用于 diff 的稳定字段**，刻意不存：
//   - 端口 banner（含动态内容：时间戳、主机名、问候语 —— 会产生假变化）
//   - 完整 findings（结论随分析逻辑演进，不适合做基线对比）
type Snapshot struct {
	Target     string           `json:"target"`
	TakenAt    time.Time        `json:"taken_at"`
	Coverage   SnapshotCoverage `json:"coverage"`
	IPs        []string         `json:"ips,omitempty"`
	Subdomains []string         `json:"subdomains,omitempty"`
	OpenPorts  []SnapshotPort   `json:"open_ports,omitempty"`
	Tech       []SnapshotTech   `json:"tech,omitempty"`
}

// SnapshotPort 快照里的一个开放端口
type SnapshotPort struct {
	Host    string `json:"host,omitempty"`
	IP      string `json:"ip,omitempty"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
}

// SnapshotTech 快照里的一个 HTTP 端点指纹
type SnapshotTech struct {
	URL string `json:"url"`
	// Status HTTP 状态码；**0 = 探测失败**
	//
	// ⭐ 失败也是一种观测："成功→失败"（下线/被墙）与"失败→成功"（恢复）
	//   都是值得报告的变化，所以失败项也要进快照。
	Status         int    `json:"status"`
	Server         string `json:"server,omitempty"`
	Title          string `json:"title,omitempty"`
	FaviconProduct string `json:"favicon_product,omitempty"`
	// JARM TLS 指纹（62 字符；未采集为空；P1-3）
	JARM string `json:"jarm,omitempty"`
	// H2Settings HTTP/2 SETTINGS 指纹（未采集为空；P1-3）
	H2Settings string `json:"h2_settings,omitempty"`
}

// BuildSnapshot 从 recon 报告提取资产快照
//
// 归一化规则（与 diff / 存储共用 NormalizeTarget，口径一致）：
//   - 目标/子域统一小写、去尾部点号
//   - 各列表去重 + 排序（快照文件稳定，便于人工查看与归档对比）
//   - 泛域名片（*.x.com）与根域本身不是"子域资产"，跳过
func BuildSnapshot(rep *Report) *Snapshot {
	if rep == nil {
		return nil
	}
	snap := &Snapshot{
		Target:  NormalizeTarget(rep.Target),
		TakenAt: time.Now().UTC(),
	}

	// ── 覆盖率（决定哪些类别可参与 diff）──
	if rep.DNS != nil && rep.DNS.Err == "" {
		snap.Coverage.DNS = true
	}
	if rep.CT != nil && len(rep.CT.SourcesUsed) > 0 {
		snap.Coverage.CT = true
	}
	if rep.Passive != nil && len(rep.Passive.SourcesUsed) > 0 && len(rep.Passive.Records) > 0 {
		snap.Coverage.Passive = true
	}
	if len(rep.Ports) > 0 {
		snap.Coverage.Ports = true
		snap.Coverage.PortsSpec = rep.PortsSpec
		// ⭐ H5：记录本次实际扫描的主机集合（diff 据此只对比共同扫过的 IP）
		ipSet := map[string]bool{}
		for _, p := range rep.Ports {
			k := strings.ToLower(strings.TrimSpace(p.IP))
			if k == "" {
				k = strings.ToLower(strings.TrimSpace(p.Host))
			}
			if k != "" {
				ipSet[k] = true
			}
		}
		for k := range ipSet {
			snap.Coverage.PortsIPs = append(snap.Coverage.PortsIPs, k)
		}
		sort.Strings(snap.Coverage.PortsIPs)
	}
	if len(rep.Tech) > 0 {
		snap.Coverage.Tech = true
	}

	// 根域解析 IP
	if rep.DNS != nil {
		seen := map[string]bool{}
		for _, ip := range rep.DNS.IPs {
			ip = strings.TrimSpace(ip)
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			snap.IPs = append(snap.IPs, ip)
		}
		sort.Strings(snap.IPs)
	}

	// 子域：CT + 被动 DNS 合并
	{
		seen := map[string]bool{}
		add := func(name string) {
			name = NormalizeTarget(name)
			if name == "" || seen[name] || strings.HasPrefix(name, "*.") {
				return
			}
			// ⭐ 根域本身不是"子域资产"（CT 会把根域也标为解析成功），
			//   它的增删应该走 IP/DNS 类差异，而不是"子域新增/消失"
			if name == snap.Target {
				return
			}
			seen[name] = true
			snap.Subdomains = append(snap.Subdomains, name)
		}
		if rep.CT != nil {
			for _, sb := range rep.CT.Subdomains {
				if sb == nil || sb.IsWildcard {
					continue
				}
				add(sb.Name)
			}
		}
		if rep.Passive != nil {
			for name := range rep.Passive.Records {
				add(name)
			}
		}
		sort.Strings(snap.Subdomains)
	}

	// 开放端口（去重 by ip:port）
	{
		seen := map[string]bool{}
		for _, p := range rep.Ports {
			if !p.Open() {
				continue
			}
			key := portKey(p.IP, p.Host, p.Port)
			if seen[key] {
				continue
			}
			seen[key] = true
			snap.OpenPorts = append(snap.OpenPorts, SnapshotPort{
				Host: p.Host, IP: p.IP, Port: p.Port, Service: p.Service,
			})
		}
		sort.Slice(snap.OpenPorts, func(i, j int) bool {
			a, b := snap.OpenPorts[i], snap.OpenPorts[j]
			return portKey(a.IP, a.Host, a.Port) < portKey(b.IP, b.Host, b.Port)
		})
	}

	// HTTP 端点指纹（含失败项，Status=0）
	{
		seen := map[string]bool{}
		for _, t := range rep.Tech {
			if t == nil {
				continue
			}
			u := strings.TrimSpace(t.URL)
			if u == "" || seen[u] {
				continue
			}
			seen[u] = true
			status := t.StatusCode
			if t.Err != "" {
				status = 0
			}
			// ⭐ H2 修复：JARM 全 0 是"探测失败"哨兵而非指纹，
			//   归一化为空（"未采集"语义）—— 与 diff 的"单侧为空不比"天然契合
			jarm := t.JARM
			if t.JARMFailed() {
				jarm = ""
			}
			snap.Tech = append(snap.Tech, SnapshotTech{
				URL: u, Status: status,
				Server: t.Server, Title: t.Title,
				FaviconProduct: t.FaviconProductName,
				JARM:           jarm,
				H2Settings:     t.H2Settings,
			})
		}
		sort.Slice(snap.Tech, func(i, j int) bool { return snap.Tech[i].URL < snap.Tech[j].URL })
	}

	return snap
}

// portKey 端口在 diff / 排序中的稳定键（IP 优先，无 IP 用主机名）
func portKey(ip, host string, port int) string {
	k := strings.ToLower(strings.TrimSpace(ip))
	if k == "" {
		k = strings.ToLower(strings.TrimSpace(host))
	}
	return k + ":" + strconv.Itoa(port)
}

// DefaultSnapshotDir 默认快照目录
func DefaultSnapshotDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "wukan-snapshots"
	}
	return filepath.Join(home, ".wukan", "snapshots")
}

// ── 存储 ─────────────────────────────────────────────────

// SnapshotStore 快照存储（每目标一个文件）
type SnapshotStore struct {
	dir  string
	keep int
}

// NewSnapshotStore 创建存储（keep <= 0 时用 DefaultSnapshotKeep）
func NewSnapshotStore(dir string, keep int) *SnapshotStore {
	if keep <= 0 {
		keep = DefaultSnapshotKeep
	}
	return &SnapshotStore{dir: dir, keep: keep}
}

// snapshotFile 快照文件结构
type snapshotFile struct {
	Target    string      `json:"target"`
	Snapshots []*Snapshot `json:"snapshots"`
}

// windowsReserved Windows 保留设备名（作为文件名会打开设备而不是文件）
var windowsReserved = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// snapshotPath 目标 → 文件路径
//
// ⭐ 三层防护：
//  1. 白名单净化：只保留 [a-z0-9.-_]，杜绝路径分隔符穿越
//  2. 净化是**有损**的（"a b.com" 与 "a_b.com" 会撞名）—— 一旦发生替换，
//     追加目标名的 FNV 哈希后缀，保证不同目标落到不同文件
//  3. Windows 保留设备名（con/nul/com1…）加前缀规避
func (s *SnapshotStore) snapshotPath(target string) string {
	name := NormalizeTarget(target)
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	safe := b.String()
	if safe != name {
		// 有损 → 加哈希后缀（同名前缀的不同目标不会互相覆盖）
		h := fnv.New32a()
		_, _ = h.Write([]byte(name))
		safe = fmt.Sprintf("%s-%08x", safe, h.Sum32())
	}
	if safe == "" {
		safe = "_"
	}
	base := safe
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	if windowsReserved[strings.ToLower(base)] {
		safe = "_" + safe
	}
	return filepath.Join(s.dir, safe+".json")
}

// readSnapshotFile 读取并解析快照文件（统一处理 BOM / 目标校验）
//
// ⭐ 目标校验：净化后不同目标可能撞同一文件名，读取时必须确认
//
//	文件里的 target 与请求目标一致 —— 否则会把别的目标的资产
//	当成自己的（静默串目标，比报错危险得多）。
func (s *SnapshotStore) readSnapshotFile(path, target string) (*snapshotFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	// ⭐ 容忍 UTF-8 BOM（Windows 记事本另存为的常见形态）
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	var f snapshotFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("快照文件损坏（未覆盖）：%s: %w", path, err)
	}
	if f.Target != "" && f.Target != target {
		return nil, fmt.Errorf("快照文件目标不匹配（文件: %s，请求: %s，路径: %s）",
			f.Target, target, path)
	}
	// 过滤手工编辑可能引入的 null 元素
	clean := f.Snapshots[:0]
	for _, sn := range f.Snapshots {
		if sn != nil {
			clean = append(clean, sn)
		}
	}
	f.Snapshots = clean
	return &f, nil
}

// SaveAndPrevious 保存快照并返回**保存前的最新快照**（首次为 nil）
//
// 返回 (prev, appended, err)：
//   - prev     保存前的最新快照（用于 diff 的对比基准；首次为 nil）
//   - appended 本次是否真的追加了新条目
//     （内容与最近快照一致且间隔 < snapshotHeartbeat 时跳过追加，
//     避免高频运行把历史窗口挤爆；返回的 prev 仍是最近一次存储的快照）
//
// ⭐ 损坏/不匹配的文件直接报错、**不覆盖** ——
//
//	否则一次解析异常就会把全部历史清空（比没有快照更糟）。
func (s *SnapshotStore) SaveAndPrevious(snap *Snapshot) (*Snapshot, bool, error) {
	if snap == nil {
		return nil, false, fmt.Errorf("快照为空")
	}
	snap.Target = NormalizeTarget(snap.Target)
	if snap.Target == "" {
		return nil, false, fmt.Errorf("快照缺少目标名")
	}

	path := s.snapshotPath(snap.Target)
	f, err := s.readSnapshotFile(path, snap.Target)
	if err != nil {
		return nil, false, err
	}
	if f == nil {
		f = &snapshotFile{Target: snap.Target}
	}

	var prev *Snapshot
	if n := len(f.Snapshots); n > 0 {
		prev = f.Snapshots[n-1]
	}

	// ⭐ 内容去重：相同内容在心跳窗口内不追加（prev 照常返回，diff 会得出"无变化"）
	appended := true
	if prev != nil && snapshotsEqual(prev, snap) &&
		snap.TakenAt.Sub(prev.TakenAt) < snapshotHeartbeat {
		appended = false
	} else {
		f.Snapshots = append(f.Snapshots, snap)
		// 保留最新 keep 个
		if len(f.Snapshots) > s.keep {
			f.Snapshots = f.Snapshots[len(f.Snapshots)-s.keep:]
		}
	}

	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return nil, false, err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, false, err
	}
	// ⭐ 原子写：先临时文件再 rename；tmp 名带 PID 防并发互踩
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return nil, false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, false, err
	}
	return prev, appended, nil
}

// snapshotsEqual 内容比较（忽略 TakenAt；顺序无关）
func snapshotsEqual(a, b *Snapshot) bool {
	if a == nil || b == nil {
		return false
	}
	if !reflect.DeepEqual(a.Coverage, b.Coverage) {
		return false
	}
	// 排序副本后深比较（手工编辑的文件顺序可能不同）
	ca, cb := *a, *b
	ca.TakenAt, cb.TakenAt = time.Time{}, time.Time{}
	ca.IPs = sortedCopy(ca.IPs)
	cb.IPs = sortedCopy(cb.IPs)
	ca.Subdomains = sortedCopy(ca.Subdomains)
	cb.Subdomains = sortedCopy(cb.Subdomains)
	ca.OpenPorts = sortedPorts(ca.OpenPorts)
	cb.OpenPorts = sortedPorts(cb.OpenPorts)
	ca.Tech = sortedTech(ca.Tech)
	cb.Tech = sortedTech(cb.Tech)
	return reflect.DeepEqual(ca, cb)
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func sortedPorts(ps []SnapshotPort) []SnapshotPort {
	out := append([]SnapshotPort(nil), ps...)
	sort.Slice(out, func(i, j int) bool {
		return portKey(out[i].IP, out[i].Host, out[i].Port) < portKey(out[j].IP, out[j].Host, out[j].Port)
	})
	return out
}

func sortedTech(ts []SnapshotTech) []SnapshotTech {
	out := append([]SnapshotTech(nil), ts...)
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// Load 读取某目标的全部快照（从旧到新；nil 元素被过滤）
func (s *SnapshotStore) Load(target string) ([]*Snapshot, error) {
	norm := NormalizeTarget(target)
	f, err := s.readSnapshotFile(s.snapshotPath(norm), norm)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, nil
	}
	return f.Snapshots, nil
}

// LatestBefore 返回时间不晚于 cutoff 的最新快照（无则 nil）—— --since 的基准选择
func (s *SnapshotStore) LatestBefore(target string, cutoff time.Time) (*Snapshot, error) {
	snaps, err := s.Load(target)
	if err != nil {
		return nil, err
	}
	var best *Snapshot
	for _, sn := range snaps {
		if sn == nil || sn.TakenAt.After(cutoff) {
			continue
		}
		if best == nil || sn.TakenAt.After(best.TakenAt) {
			best = sn
		}
	}
	return best, nil
}

// ParseSinceDuration 解析 --since 时长（支持 Nd 天 与 Go 标准时长）
func ParseSinceDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("时长为空")
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("天数格式非法: %q（应为正整数天，如 7d）", s)
		}
		// ⭐ 防溢出：time.Duration 最大约 106751 天，超出会变成负数，
		//   导致后续 since > 0 判断静默失效（审查发现的真实问题）
		if n > 106751 {
			return 0, fmt.Errorf("天数过大: %q（上限 106751 天）", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("时长格式非法: %q（支持 7d / 24h / 90m）", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("时长必须为正: %q", s)
	}
	return d, nil
}
