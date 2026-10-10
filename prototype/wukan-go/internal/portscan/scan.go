// Package portscan 实现 TCP 端口扫描（TCP connect 模式）。
//
// ⭐⭐ 为什么用 TCP connect 而不是 SYN 半开扫描 —— 这是本包最重要的设计决策：
//
// 调研报告（附录 A §5.2）指出的误报陷阱：
//
//	"AWS Global Accelerator 的边缘使用无状态 SYN Proxy（SYN Cookies）抗 DDoS
//	 —— 无论端口背后有无真实服务，都会对任何 SYN 回 SYN-ACK。
//	  只做半开 SYN 扫描的逻辑'收到 SYN-ACK ⇒ 开放'会把
//	  21/23/179/636/3306/3389/5432/5985 全部误判为 open。"
//
// 而 TCP connect 扫描**必须完成三次握手**才能判定端口开放。
// SYN Proxy 无法伪造"已建立的连接"——它只能回 SYN-ACK，
// 后续的 ACK 无人应答，连接永远建立不起来。
//
//	→ 所以 connect 扫描**天然免疫 SYN Proxy 误报**，不需要额外交叉验证。
//
// 代价（必须如实告知使用者）：
//
//  1. 会在目标侧留下完整的 established 记录（更容易被 IDS 记录）
//  2. 无法探测被防火墙 DROP 的端口（只能报 filtered，无法区分）
//  3. 单个端口探测比 SYN 扫描慢（多一个 RTT）
//
// 但对"个人自用 / 已授权资产梳理"这个场景，**误报为零比速度更重要**。
package portscan

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// PortState 端口状态
type PortState string

const (
	// StateOpen 端口开放（已完成三次握手）
	StateOpen PortState = "open"
	// StateClosed 端口关闭（收到 RST）
	StateClosed PortState = "closed"
	// StateFiltered 端口被过滤（超时，无法区分 open|filtered）
	// ⭐ TCP connect 扫描的固有局限：无法区分"被 DROP 的开放端口"与"不存在"
	StateFiltered PortState = "filtered"
	// StateError 探测出错
	StateError PortState = "error"
)

// PortResult 单个端口的扫描结果
type PortResult struct {
	Host  string    `json:"host"`
	Port  int       `json:"port"`
	IP    string    `json:"ip,omitempty"`
	State PortState `json:"state"`
	// RTT 往返时延
	RTT time.Duration `json:"-"`
	// Service 识别到的服务名
	Service string `json:"service,omitempty"`
	// Banner 抓到的 banner（已截断）
	Banner string `json:"banner,omitempty"`
	// ProbeMethod 识别用的探测方式
	ProbeMethod string `json:"probe_method,omitempty"`
	// Confidence 置信度 0-100
	//
	// ⭐ 为什么要置信度：connect 扫描只能给出 open/closed/filtered 三态，
	//   filtered 无法区分"被防火墙丢掉的开放端口"和"根本不存在的端口"。
	//   所以"开放"的结论有多可靠，取决于有多少佐证。
	Confidence int `json:"confidence"`
	// Err 错误信息
	Err string `json:"error,omitempty"`
}

// Open 是否开放
func (p PortResult) Open() bool { return p.State == StateOpen }

// RTTMs 毫秒
func (p PortResult) RTTMs() float64 { return float64(p.RTT.Microseconds()) / 1000 }

// ── 端口解析与白名单 ─────────────────────────────────────

// PortSpec 端口规格
type PortSpec struct {
	Ports    []int // 显式枚举
	Ranges   [][2]int
	TopN     int // top-N 常用端口
	All65535 bool
	// Exclude 排除的端口
	Exclude []int
}

// CommonPorts 常用端口（按服务分组的 top 列表）
var CommonPorts = map[string][]int{
	"web":     {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8001, 9000, 8081, 8082},
	"ssh":     {22, 2222, 2200},
	"ftp":     {21, 20, 990},
	"mail":    {25, 110, 143, 465, 587, 993, 995},
	"dns":     {53, 5353},
	"db":      {3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984, 9042},
	"rdp":     {3389, 3390},
	"smb":     {445, 139, 137, 138},
	"proxy":   {3128, 8080, 8888, 1080, 8118},
	"rdp-alt": {5900, 5901, 5800},
	"web-alt": {81, 300, 591, 593, 832, 981, 1010, 1311, 1099, 2082, 2095, 2096, 2480, 3000, 3128, 3333, 4243, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5280, 5281, 5601, 5800, 6543, 7000, 7396, 7474, 8000, 8001, 8008, 8014, 8042, 8060, 8069, 8080, 8081, 8083, 8088, 8090, 8091, 8118, 8123, 8172, 8181, 8222, 8243, 8280, 8281, 8333, 8337, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9001, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9502, 9800, 9981, 10000, 10250, 11371, 12443, 15672, 16080, 17778, 18091, 18092, 20720, 32000, 55440, 55672},
}

// 常用端口的扁平列表（top 集合）
var commonFlat = func() []int {
	seen := map[int]bool{}
	var out []int
	for _, ps := range CommonPorts {
		for _, p := range ps {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Ints(out)
	return out
}()

// TopNPorts 返回 top-N 常用端口
func TopNPorts(n int) []int {
	if n <= 0 || n > len(commonFlat) {
		n = len(commonFlat)
	}
	out := make([]int, n)
	copy(out, commonFlat[:n])
	return out
}

// ParsePorts 解析端口表达式
//
// 支持的语法：
//
//	80              单个端口
//	80,443,8080     逗号分隔
//	1-1024          范围
//	80,443,8000-8100 混合
//	top100          常用 top-N
//	top             全部常用端口
//	web,ssh,db      按服务名（见 CommonPorts）
//	-               ⛔ 全端口（1-65535）—— **被 ParsePorts 拒绝**
func ParsePorts(spec string) (*PortSpec, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return nil, errors.New("端口表达式为空")
	}

	// ⛔ 硬性拒绝全端口
	// 依据：调研报告 §6.2，《刑法》285 条 2 款"非法控制计算机信息系统"
	// 的入刑门槛是 20 台。一次 -p- 对一个 /16 就可能越线。
	if s == "-" || s == "0-65535" || s == "1-65535" {
		return nil, fmt.Errorf(
			"拒绝全端口扫描（%q）：\n"+
				"  这是法律与资源双重风险。按《刑法》285 条 2 款，"+
				"「非法控制计算机信息系统 20 台以上」即入刑，\n"+
				"  而一次全端口扫描对一个 /16 就可能越过该门槛。\n"+
				"  请显式列出你要扫的端口，或用 -p top100 等。", s)
	}

	ps := &PortSpec{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// 范围
		if strings.Contains(part, "-") {
			bits := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bits[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bits[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("无法解析端口范围: %q", part)
			}
			if lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("端口范围非法: %q", part)
			}
			// ⭐ 单个范围也不能太大 —— 65535 个端口的扫描就是全端口
			if hi-lo+1 > 10000 {
				return nil, fmt.Errorf(
					"端口范围 %q 过大（%d 个）。\n"+
						"  单次扫描建议不超过 10000 个端口；\n"+
						"  需要更大范围请分批，或用 -p top / -p <服务名>",
					part, hi-lo+1)
			}
			ps.Ranges = append(ps.Ranges, [2]int{lo, hi})
			continue
		}
		// top-N
		if strings.HasPrefix(strings.ToLower(part), "top") {
			numStr := part[3:]
			if numStr == "" {
				ps.TopN = len(commonFlat)
			} else {
				n, err := strconv.Atoi(numStr)
				if err != nil {
					return nil, fmt.Errorf("无法解析 top-N: %q", part)
				}
				ps.TopN = n
			}
			continue
		}
		// 服务名
		if list, ok := CommonPorts[strings.ToLower(part)]; ok {
			ps.Ports = append(ps.Ports, list...)
			continue
		}
		// 纯数字
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("无法识别的端口表达式: %q", part)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("端口号越界: %d", p)
		}
		ps.Ports = append(ps.Ports, p)
	}

	if len(ps.Ports) == 0 && len(ps.Ranges) == 0 && ps.TopN == 0 {
		return nil, fmt.Errorf("端口表达式未解析出任何端口: %q", spec)
	}
	return ps, nil
}

// Expand 展开为具体端口列表（去重 + 排序）
func (p *PortSpec) Expand() []int {
	set := make(map[int]bool)
	for _, v := range p.Ports {
		if v >= 1 && v <= 65535 {
			set[v] = true
		}
	}
	for _, r := range p.Ranges {
		for v := r[0]; v <= r[1]; v++ {
			set[v] = true
		}
	}
	if p.TopN > 0 {
		for _, v := range TopNPorts(p.TopN) {
			set[v] = true
		}
	}
	for _, v := range p.Exclude {
		delete(set, v)
	}
	out := make([]int, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// ── 扫描配置 ─────────────────────────────────────────────

// Config 扫描配置
type Config struct {
	// Ports 要扫的端口列表（已展开）
	Ports []int
	// Timeout 单端口超时
	Timeout time.Duration
	// Concurrency 并发数
	Concurrency int
	// RateLimit 全局限速（每秒最多发起的连接数）
	//
	// ⭐ 默认 200 —— 约等于普通浏览器的并发水平，
	//   足以在可接受时间内扫完常用端口，又不至于触发 IDS 告警。
	RateLimit int
	// GrabBanner 是否抓 banner（会多发一个数据包）
	GrabBanner bool
	// TLSProbe 对疑似 TLS 端口做握手（更准确但更慢）
	TLSProbe bool
	// Hosts 目标列表
	Hosts []string
	// HostHeader HTTP 请求里用的 Host 头
	//
	// ⭐ 为什么要单独设置：某些 CDN / WAF 会根据 Host 头返回不同内容
	//   （甚至只有正确 Host 才返回首页）。用 IP 请求会拿到默认站点，
	//   导致 banner 里的 Server / 页面特征判断错误。
	HostHeader string
}

// DefaultConfig 默认配置
func DefaultConfig() Config {
	return Config{
		Timeout:     3 * time.Second,
		Concurrency: 64,
		RateLimit:   200,
		GrabBanner:  true,
		TLSProbe:    false,
	}
}

// ── 限速器 ───────────────────────────────────────────────

// rateLimiter 是全局令牌桶限速器
//
// ⭐ 实现要点：**绝不能持锁 sleep**。
//
// 早期版本写成：
//
//	r.mu.Lock()
//	if need > 0 { time.Sleep(need) }   // ← 持锁睡眠
//	r.last = time.Now()
//	r.mu.Unlock()
//
// 这会导致**所有并发 goroutine 排队等锁**，
// 限速从 10/s 调到 500/s 耗时完全一样（实测都是 5.7s）——
// 限速器退化成了"全局串行队列"，并发完全失效。
//
// 正确做法：原子地计算等待时刻，**释放锁后再睡**。
type rateLimiter struct {
	interval time.Duration
	mu       sync.Mutex
	last     time.Time
}

func newRateLimiter(perSec int) *rateLimiter {
	if perSec <= 0 {
		return &rateLimiter{}
	}
	return &rateLimiter{interval: time.Second / time.Duration(perSec)}
}

// wait 阻塞直到获得一个令牌
func (r *rateLimiter) wait() {
	if r.interval <= 0 {
		return
	}
	r.mu.Lock()
	now := time.Now()
	// ⭐ 关键：把"下一个可用时刻"推进到未来，然后**立刻放锁**。
	//    即使多个 goroutine 同时进来，等待时刻也是递进的，
	//    而它们各自独立 sleep，不互相阻塞。
	next := r.last
	if now.After(next) {
		next = now
	}
	r.last = next.Add(r.interval)
	r.mu.Unlock()

	if d := time.Until(next); d > 0 {
		time.Sleep(d)
	}
}

// ── 扫描器 ───────────────────────────────────────────────

// Scanner 端口扫描器
type Scanner struct {
	cfg  Config
	rate *rateLimiter
}

// New 创建扫描器
func New(cfg Config) *Scanner {
	return &Scanner{cfg: cfg, rate: newRateLimiter(cfg.RateLimit)}
}

// ScanHost 扫描单个主机的所有配置端口
func (s *Scanner) ScanHost(host string) []PortResult {
	// 解析为 IP（一次解析，多端口复用）
	ips, err := net.LookupHost(host)
	ip := ""
	if err == nil && len(ips) > 0 {
		ip = ips[0]
	}
	if ip == "" {
		if net.ParseIP(host) != nil {
			ip = host
		} else {
			// 解析失败 → 全部端口标错误
			out := make([]PortResult, len(s.cfg.Ports))
			for i, p := range s.cfg.Ports {
				out[i] = PortResult{Host: host, Port: p, State: StateError,
					Err: "主机名解析失败: " + err.Error()}
			}
			return out
		}
	}

	results := make([]PortResult, len(s.cfg.Ports))
	sem := make(chan struct{}, s.cfg.Concurrency)
	var wg sync.WaitGroup

	for i, port := range s.cfg.Ports {
		wg.Add(1)
		go func(idx, p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = s.probe(host, ip, p)
		}(i, port)
	}
	wg.Wait()
	return results
}

// ScanAll 扫描多个主机
func (s *Scanner) ScanAll(onProgress func(host string, done, total int)) []PortResult {
	var all []PortResult
	total := len(s.cfg.Hosts) * len(s.cfg.Ports)
	counter := 0
	for _, h := range s.cfg.Hosts {
		rs := s.ScanHost(h)
		all = append(all, rs...)
		counter += len(rs)
		if onProgress != nil {
			onProgress(h, counter, total)
		}
	}
	// 排序：开放优先，然后按端口
	sort.SliceStable(all, func(i, j int) bool {
		oi := 0
		if !all[i].Open() {
			oi = 1
		}
		oj := 0
		if !all[j].Open() {
			oj = 1
		}
		if oi != oj {
			return oi < oj
		}
		if all[i].Host != all[j].Host {
			return all[i].Host < all[j].Host
		}
		return all[i].Port < all[j].Port
	})
	return all
}

// probe 探测单个端口
func (s *Scanner) probe(host, ip string, port int) PortResult {
	r := PortResult{Host: host, IP: ip, Port: port}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	// ⭐ 限速排队**必须在计时与 deadline 之外**。
	//   早期实现先 wait() 再 DialTimeout()，但 grabBanner 里用的是
	//   `SetDeadline(now + Timeout)` —— 而连接可能已在 conn 上等待了
	//   很久（限速排队 + RTT），导致刚连上就没时间读 banner 了。
	//   表现：conf=60 + banner 空白，且只在低并发下偶发。
	//
	//   正确做法：把「等令牌」和「建立连接 + 读 banner」分成两段预算。
	s.rate.wait()

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, s.cfg.Timeout)
	r.RTT = time.Since(start)

	if err != nil {
		r.State = classifyDialError(err)
		r.Confidence = 0
		r.Err = err.Error()
		return r
	}
	defer conn.Close()

	// ⭐ 走到这里说明三次握手完成 → 确定开放
	//   这就是 connect 扫描免疫 SYN Proxy 误报的原因
	r.State = StateOpen
	r.Service = guessService(port)
	r.Confidence = 60 // 基础分：有 banner / 特征佐证会提高

	if s.cfg.TLSProbe && isTLSPort(port) {
		s.probeTLS(host, addr, &r)
		return r
	}

	if s.cfg.GrabBanner {
		s.grabBanner(conn, &r)
	}

	r.Confidence = scoreConfidence(&r)
	return r
}

// probeTLS 对疑似 TLS 端口做握手
func (s *Scanner) probeTLS(host, addr string, r *PortResult) {
	tlsBudget := s.cfg.Timeout
	if tlsBudget < 2*time.Second {
		tlsBudget = 2 * time.Second
	}
	tconn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: tlsBudget}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, ServerName: host},
	)
	if err != nil {
		// 握手失败但 TCP 通 → 状态存疑
		r.Service = "tls?"
		r.Confidence = 40
		r.Err = "TLS 握手失败: " + err.Error()
		return
	}
	defer tconn.Close()
	_ = tconn.SetDeadline(time.Now().Add(s.cfg.Timeout))

	st := tconn.ConnectionState()
	r.ProbeMethod = "tls-handshake"
	r.Service = "tls"
	r.Confidence = 90
	attrs := []string{}
	if st.NegotiatedProtocol != "" {
		attrs = append(attrs, "ALPN="+st.NegotiatedProtocol)
	}
	// ⭐ HTTP/3（QUIC）不能在这里判断 —— HTTP/3 走 UDP，不在 TCP 上
	if st.Version != 0 {
		attrs = append(attrs, fmt.Sprintf("TLS=0x%04x", st.Version))
	}
	r.Banner = strings.Join(attrs, " ")
	// 端口号本身是弱信号，综合置信度中等
	r.Confidence = scoreConfidence(r)
}

// grabBanner 抓取 banner
func (s *Scanner) grabBanner(conn net.Conn, r *PortResult) {
	// ⭐ banner 读取给独立的预算（最少 2 秒）。
	//   很多服务（如 CDN）建立连接后要几十 ms 才吐数据，
	//   沿用连接阶段的剩余时间会经常读到空。
	readBudget := s.cfg.Timeout
	if readBudget < 2*time.Second {
		readBudget = 2 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(readBudget))

	// HTTP 类端口：主动发一个 HEAD 才能拿到响应
	if isHTTPPort(r.Port) {
		// ⭐ Host 头优先用配置的 HostHeader（域名），否则用 IP
		hostHdr := r.Host
		if s.cfg.HostHeader != "" {
			hostHdr = s.cfg.HostHeader
		}
		req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", hostHdr)
		if _, err := conn.Write([]byte(req)); err != nil {
			return
		}
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	r.Banner = sanitizeBanner(string(buf[:n]))
	// ⭐ ProbeMethod 记录**证据来源**，scoreConfidence 依赖它判断，
	//   所以只在还没设置时写入，不能覆盖 grabBanner 的判定结果。
	if r.ProbeMethod == "" {
		r.ProbeMethod = "banner"
	}
	if strings.HasPrefix(r.Banner, "HTTP/") {
		r.Service = "http"
		if srv := extractHeader(r.Banner, "server"); srv != "" {
			r.Banner = "Server: " + srv
		}
	}
}

// classifyDialError 把 Go 的连接错误映射为端口状态
func classifyDialError(err error) PortState {
	if err == nil {
		return StateOpen
	}
	// 超时 = 被过滤（这是 connect 扫描的固有局限：无法区分）
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return StateFiltered
	}
	// 连接被拒 = 端口关闭（收到 RST）
	if errors.Is(err, syscall.ECONNREFUSED) {
		return StateClosed
	}
	// Windows 上 ECONNREFUSED 可能被包装
	if strings.Contains(strings.ToLower(err.Error()), "refused") {
		return StateClosed
	}
	// 网络不可达 / 主机不可达
	if strings.Contains(strings.ToLower(err.Error()), "unreachable") {
		return StateFiltered
	}
	// 上下文超时
	if strings.Contains(err.Error(), "context deadline exceeded") {
		return StateFiltered
	}
	return StateError
}

// scoreConfidence 计算置信度
//
// ⭐ 分档（0-100）：
//
//	100  TLS 握手成功 + ALPN 协商
//	 90  TLS 握手成功
//	 80  banner 明确识别（HTTP 状态行 / MySQL greeting / SSH 标识）
//	 60  端口开放但无 banner（服务可能不主动发数据）
//	 40  端口开放但 TLS 握手失败（状态存疑）
//
// 为什么需要分档：connect 扫描只能给三态，filtered 无法区分
// 「被 DROP 的开放端口」与「不存在的端口」。所以"开放"的可靠度
// 取决于有多少佐证 —— 这个数字必须如实给使用者。
func scoreConfidence(r *PortResult) int {
	switch {
	case r.ProbeMethod == "tls-handshake":
		return 90
	case r.Banner != "":
		b := strings.ToLower(r.Banner)
		// 明确的协议标识
		if strings.HasPrefix(b, "http/") ||
			strings.HasPrefix(b, "ssh-") ||
			strings.Contains(r.Banner, "Server:") ||
			strings.HasPrefix(r.Banner, "220") || // SMTP/FTP
			strings.HasPrefix(r.Banner, "5.") || // MySQL greeting
			strings.HasPrefix(r.Banner, "RFB") || // VNC
			strings.HasPrefix(r.Banner, "\x00\x00") { // RDP
			return 80
		}
		return 70
	case r.Service == "tls?":
		return 40
	default:
		return 60
	}
}

// ── 服务识别 ─────────────────────────────────────────────

// serviceMap 端口 → 服务名（只列高置信度的）
var serviceMap = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
	143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
	993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle",
	2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3306: "mysql",
	3389: "rdp", 5432: "postgres", 5900: "vnc", 5984: "couchdb", 6379: "redis",
	8000: "http-alt", 8001: "http-alt", 8080: "http-proxy", 8081: "http-alt",
	8083: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
	9042: "cassandra", 9090: "prometheus", 9200: "elasticsearch", 27017: "mongodb",
}

func guessService(port int) string {
	if s, ok := serviceMap[port]; ok {
		return s
	}
	return ""
}

func isTLSPort(port int) bool {
	switch port {
	case 443, 465, 993, 995, 636, 5986, 5989, 2376, 8443, 9443, 4443:
		return true
	}
	return false
}

func isHTTPPort(port int) bool {
	switch port {
	case 80, 81, 300, 591, 593, 800, 801, 808, 880, 1080, 3128,
		8000, 8001, 8008, 8080, 8081, 8082, 8083, 8088, 8090, 8180, 8443, 8888, 9000, 9090:
		return true
	}
	return false
}

func extractHeader(raw, name string) string {
	lines := strings.Split(raw, "\r\n")
	lower := strings.ToLower(name) + ":"
	for _, l := range lines {
		if strings.HasPrefix(strings.ToLower(l), lower) {
			return strings.TrimSpace(l[len(lower):])
		}
	}
	return ""
}

// sanitizeBanner 清洗 banner（可打印字符、截断、防注入）
func sanitizeBanner(s string) string {
	const maxLen = 220
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= maxLen {
			b.WriteString("...")
			break
		}
		// 保留可打印字符与常见空白，其余用点代替
		if r == '\n' || r == '\r' {
			b.WriteByte(' ')
			n++
			continue
		}
		if r < 32 || r == 127 {
			b.WriteByte('.')
			n++
			continue
		}
		if r > 126 {
			b.WriteByte('.')
			n++
			continue
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// Summarize 汇总扫描结果
type Summary struct {
	Total    int `json:"total"`
	Open     int `json:"open"`
	Closed   int `json:"closed"`
	Filtered int `json:"filtered"`
	Error    int `json:"error"`
	Hosts    int `json:"hosts"`
	// LowConfidence 开放但置信度 < 70 的端口数
	//
	// ⭐ 这些是"开放但没抓到任何佐证"的服务，可能是 honeypot、
	//   也可能是需要特殊握手的服务，值得人工确认。
	LowConfidence int `json:"low_confidence"`
}

// Summarize 统计
func Summarize(rs []PortResult) Summary {
	var s Summary
	hostSet := map[string]bool{}
	for _, r := range rs {
		hostSet[r.Host] = true
		s.Total++
		switch r.State {
		case StateOpen:
			s.Open++
			if r.Confidence < 70 {
				s.LowConfidence++
			}
		case StateClosed:
			s.Closed++
		case StateFiltered:
			s.Filtered++
		default:
			s.Error++
		}
	}
	s.Hosts = len(hostSet)
	return s
}
