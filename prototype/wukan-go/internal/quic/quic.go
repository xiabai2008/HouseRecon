// Package quicprobe 实现 QUIC / UDP-443 探活。
//
// 原理：QUIC 长包头的 Version 字段是明文（偏移 1..4）。发送一个带保留版本号
// 的 Initial 包，服务端发现版本不支持时会回 Version Negotiation（VN）包，
// 其 Version 字段恒为 0x00000000。⭐ VN 在解密之前就发出，所以探测不需要
// 任何加密计算 —— 只需拼 20 字节明文头 + PADDING 到 1200 字节。
//
// 这一招绕开了 UDP 扫描 "无响应 = open|filtered 无法区分" 的原罪：
// 收到 VN 包是**确定性**证据。
//
// 协议依据：
//
//	RFC 9000 §14.1  Initial 最小 1200 字节（PADDING 防放大攻击）
//	RFC 9000 §17.2  长包头格式与 Version Negotiation
//	RFC 8999        保留版本号（服务器必须回 VN）
//	RFC 9369        QUIC v2
//
// ⭐ 本实现的所有偏移与判据都用真实 quic-go v0.48.2 抓包校准过。
//
//	详见 ../../doc/项目规划/QUIC探活原型验证报告.md
package quic

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ⭐ 本模块从 prototype/quic/quicprobe-go 移植而来。
// 移植时保留了三处关键教训（都是实测踩出来的，改动前请先读注释）：
//   1. VN 包在 Version 字段之后还有 DCID/SCID 字段（偏移 23），漏掉会解析出垃圾版本
//   2. 不要对 VN 包的 flags 具体值做假设（quic-go 每次都不同，是抗指纹）
//   3. QUIC 头必须逐字节 append，不能用定长 struct 拼接

// 常量：QUIC 协议字段
const (
	// 长包头首字节：Header Form(1)=1, Fixed Bit(1)=1, Long Packet Type(2)
	// Long Packet Type = 00 表示 Initial
	longHeaderInitial = 0xC0

	// 报文类型（长包头的 bit5-4）
	pktInitial   = 0x00
	pkt0RTT      = 0x01
	pktHandshake = 0x02
	pktRetry     = 0x03

	// RFC 9000 §14.1：客户端 Initial 必须 PADDING 到至少 1200 字节
	minInitialSize = 1200

	// RFC 9000 §17.2：QUIC v1 的 DCID Len 不得超过 20
	maxCIDLen = 20
)

// 保留 /  greased 版本号（RFC 8999 允许，服务端遇之必须回 VN）
var greasedVersions = []uint32{
	0x0A0A0A0A,
	0x1A2A3A4A,
	0x2A2A2A2A,
	0xFACEB00C,
}

// State 探测判定状态
type State int

const (
	// StateUnknown 未探测
	StateUnknown State = iota
	// StateQuicConfirmed ⭐ 确定：收到 VN 包，端口开且运行 QUIC
	StateQuicConfirmed
	// StateNonQUIC 有响应但不符合 QUIC 特征（端口开着，跑的是别的 UDP 服务）
	StateNonQUIC
	// StateOpenFiltered 无响应 —— UDP 的固有不确定性，无法区分 open/filtered
	StateOpenFiltered
)

func (s State) String() string {
	switch s {
	case StateQuicConfirmed:
		return "QUIC_CONFIRMED"
	case StateNonQUIC:
		return "NON_QUIC_RESP"
	case StateOpenFiltered:
		return "OPEN_FILTERED"
	default:
		return "UNKNOWN"
	}
}

// Result 单次探测结果
type Result struct {
	Host  string        `json:"host"`
	Port  int           `json:"port"`
	State State         `json:"state"`
	RTT   time.Duration `json:"-"`
	// ServerVersions 服务端通告的 QUIC 版本列表
	ServerVersions []uint32 `json:"server_versions,omitempty"`
	// StackHint 识别出的实现归属（如"腾讯自研"）
	StackHint string `json:"stack_hint,omitempty"`
	// Detail 语义准确的结论描述
	Detail string `json:"detail"`
	// RawResponse 原始响应（hex），供取证与事后核对
	RawResponse string `json:"raw_response,omitempty"`

	// ⭐ 以下为多包探测的统计信息
	//
	// 为什么要这些：实测（2026-10-04，28 个国内站点，每目标 8 轮重复）
	// 发现同一目标的判定会因 UDP 丢包而波动：
	//   www.sina.com.cn       8 轮中 7 轮确认、1 轮无响应
	//   www.toutiao.com       8/8 确认（稳定）
	//   www.xiaohongshu.com   0/8 确认（真的没 QUIC）
	// 二元的"确认/不确认"会掩盖这种不确定性，所以必须把统计量暴露出来。
	ProbesSent      int `json:"probes_sent"`      // 实际发出的探测包数
	ProbesResponded int `json:"probes_responded"` // 收到任意响应的包数
	ProbesConfirmed int `json:"probes_confirmed"` // 收到 VN 包的包数
	// Confidence 0-100 置信度评分
	Confidence int `json:"confidence"`
}

// ToJSON 转换为可序列化结构
func (r Result) ToJSON() map[string]any {
	m := map[string]any{
		"host":   r.Host,
		"port":   r.Port,
		"state":  r.State.String(),
		"detail": r.Detail,
	}
	if r.RTT > 0 {
		m["rtt_ms"] = float64(r.RTT.Microseconds()) / 1000
	}
	if len(r.ServerVersions) > 0 {
		m["server_versions"] = r.ServerVersions
	}
	if r.StackHint != "" {
		m["stack_hint"] = r.StackHint
	}
	if r.RawResponse != "" {
		m["raw_response"] = r.RawResponse
	}
	m["probes_sent"] = r.ProbesSent
	m["probes_responded"] = r.ProbesResponded
	m["probes_confirmed"] = r.ProbesConfirmed
	m["confidence"] = r.Confidence
	return m
}

// IsQUIC 是否确认运行 QUIC
func (r Result) IsQUIC() bool { return r.State == StateQuicConfirmed }

func (r Result) String() string {
	icon := "[?   ]"
	if r.State == StateQuicConfirmed {
		icon = "[QUIC]"
	} else if r.State == StateNonQUIC {
		icon = "[UDP ]"
	}
	s := fmt.Sprintf("%s %s:%d", icon, r.Host, r.Port)
	if r.RTT > 0 {
		s += fmt.Sprintf(" %.2fms", float64(r.RTT.Microseconds())/1000)
	}
	// ⭐ 显示确认统计与置信度，避免二元结论掩盖网络抖动
	if r.ProbesSent > 0 && r.IsQUIC() {
		s += fmt.Sprintf("  %d/%d确认 conf=%d",
			r.ProbesConfirmed, r.ProbesSent, r.Confidence)
	}
	if len(r.ServerVersions) > 0 {
		s += " v=" + formatVersions(r.ServerVersions)
	}
	if r.StackHint != "" {
		s += " [" + r.StackHint + "]"
	}
	return s
}

func formatVersions(vs []uint32) string {
	parts := make([]string, 0, len(vs))
	for i, v := range vs {
		if i >= 3 {
			parts = append(parts, "...")
			break
		}
		parts = append(parts, fmt.Sprintf("0x%08x", v))
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}

// knownVersions QUIC 版本号 → 实现归属
//
// ⭐ 关键：不能只认 RFC 正式版本号。实测（2026-10-04，28 个国内大站）发现：
// 腾讯通告 0x51303339（ASCII "Q039"）等自研版本号，
// 阿里通告 0xff00001d/0x1e，字节跳动通告 0x5aea5a8a。
// 不建立映射表会把国内主流栈全部报成"未知"。
var knownVersions = map[uint32]string{
	// RFC 标准
	0x00000001: "QUIC v1 (RFC 9000)",
	0x6B3343CF: "QUIC v2 (RFC 9369)",
	// 早期 draft
	0x1A2A3A0A: "draft-29",
	0xFF00001B: "draft-29 (alt)",
	0xFF00001D: "阿里自研",
	0xFF00001E: "阿里自研",
	// 腾讯自研：把 ASCII 当版本号，Q0xx 系列
	0x51303338: "腾讯自研 Q038",
	0x51303339: "腾讯自研 Q039",
	0x51303433: "腾讯自研 Q043",
	0x51303434: "腾讯自研 Q044",
	0x51303436: "腾讯自研 Q046",
	0x51303437: "腾讯自研 Q047",
	0x51303530: "腾讯自研 Q050",
	// 字节跳动
	0x5AEA5A8A: "字节自研",
	// RFC 8999 保留（用于测试降级，quic-go 自己也通告）
	0x1A2A3A4A: "reserved (RFC 8999)",
	0x0A0A0A0A: "reserved (RFC 8999)",
}

// IdentifyStack 从版本列表推断实现归属
func IdentifyStack(versions []uint32) string {
	vendors := map[string]int{}
	order := []string{}
	for _, v := range versions {
		name, ok := knownVersions[v]
		if !ok {
			continue
		}
		// 归并厂商维度
		vendor := name
		switch {
		case contains(name, "腾讯"):
			vendor = "腾讯"
		case contains(name, "阿里"):
			vendor = "阿里"
		case contains(name, "字节"):
			vendor = "字节"
		case contains(name, "QUIC v1"):
			vendor = "QUIC v1"
		case contains(name, "QUIC v2"):
			vendor = "QUIC v2"
		}
		if _, seen := vendors[vendor]; !seen {
			order = append(order, vendor)
		}
		vendors[vendor]++
	}
	sort.SliceStable(order, func(i, j int) bool { return false }) // 保持出现顺序
	out := ""
	for i, v := range order {
		if i > 0 {
			out += "+"
		}
		out += v
	}
	return out
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// buildInitialPacket 构造 QUIC Initial 探测包。
//
// ⚠️ 关键设计（两个踩过的坑）：
//
//  1. 必须逐字节 append，不能用 struct 拼接定长字段。
//     QUIC 长包头是**变长字段序列**（1字节flags + 4字节version + 1字节len +
//     N字节CID…），用定长结构体会把 layout 弄乱。
//
//  2. 必须 PADDING 到 1200 字节（RFC 9000 §14.1 反射攻击防护），
//     否则部分服务端会因长度校验直接丢弃。
//
// 只写明文头，不构造加密载荷 —— VN 在解密之前就发出。
func buildInitialPacket(version uint32, dcidLen, scidLen int) []byte {
	if dcidLen < 0 || dcidLen > maxCIDLen {
		dcidLen = 8
	}
	if scidLen < 0 || scidLen > maxCIDLen {
		scidLen = 8
	}

	pkt := make([]byte, 0, minInitialSize)
	// [0] flags
	pkt = append(pkt, longHeaderInitial)
	// [1..5] Version —— ⭐ 明文，探测的关键字段
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], version)
	pkt = append(pkt, v[:]...)
	// [5] DCID Len + DCID
	pkt = append(pkt, byte(dcidLen))
	for i := 0; i < dcidLen; i++ {
		pkt = append(pkt, byte(i))
	}
	// SCID Len + SCID
	pkt = append(pkt, byte(scidLen))
	for i := 0; i < scidLen; i++ {
		pkt = append(pkt, byte(8+i))
	}
	// Token Length (varint) = 0
	pkt = append(pkt, 0x00)
	// Length (varint) = 0
	pkt = append(pkt, 0x00)
	// PADDING 到 1200 字节
	for len(pkt) < minInitialSize {
		pkt = append(pkt, 0x00)
	}
	return pkt
}

// parseResponse 解析响应包，只读明文头部，不解密任何内容。
//
// ⭐ VN 包布局（RFC 9000 §17.2.1，已用真实 quic-go v0.48.2 抓包校准）：
//
//	[0]      1 byte   flags
//	[1..5]   4 bytes  Version = 0x00000000   ← VN 的唯一确定性标志
//	[5]      1 byte   DCID Len (n)
//	[6..6+n] n bytes  DCID
//	[6+n]    1 byte   SCID Len (m)
//	[..]     m bytes  SCID
//	之后      4 bytes × N   服务端支持的版本列表
//
// ⚠️ 早期实现漏了 DCID/SCID，直接把 CID 字节当版本读，
//
//	在真实 quic-go 上得到 0x0808090a 这类垃圾版本。
//
// ⚠️ 不要对 flags 的具体值做假设：实测 quic-go 每次探测的 flags 都不同
//
//	（0xc9/0xd2/0xea/0xff），低 4 位 reserved 被填随机值作抗指纹。
//	只能断言 HeaderForm / FixedBit 位。
func parseResponse(data []byte) (state State, versions []uint32, detail string) {
	if len(data) < 5 {
		return StateOpenFiltered, nil, fmt.Sprintf("响应过短（%d 字节），无法判定", len(data))
	}

	flags := data[0]
	headerForm := (flags >> 7) & 0x01
	fixedBit := (flags >> 6) & 0x01
	packetType := (flags >> 4) & 0x03

	// 短包头（Header Form=0）→ 1-RTT 加密包，无法判断内部
	if headerForm == 0 {
		return StateNonQUIC, nil, "短包头响应（1-RTT 加密负载），非 QUIC 握手阶段"
	}

	version := binary.BigEndian.Uint32(data[1:5])

	// ⭐ 核心判定：VN 包的 Version 恒为 0
	if version != 0 {
		if isGreased(version) {
			return StateNonQUIC, nil, fmt.Sprintf(
				"服务端回显了保留版本号 0x%08x（不合规范），非 QUIC Version Negotiation",
				version)
		}
		pk := map[byte]string{
			pktInitial: "Initial", pkt0RTT: "0-RTT",
			pktHandshake: "Handshake", pktRetry: "Retry",
		}[packetType]
		return StateNonQUIC, nil, fmt.Sprintf(
			"QUIC %s 长包头 version=0x%08x（非 VN 包）", pk, version)
	}

	// ── 以下为 Version Negotiation 包 ──
	if fixedBit != 1 {
		// RFC 允许 VN 包的 Fixed Bit 不为 1（客户端应忽略），但要记录
		detail = "Version Negotiation（Fixed Bit 异常）"
	} else {
		detail = "收到 Version Negotiation（version=0x00000000）"
	}

	off := 5
	// DCID
	if off >= len(data) {
		return StateQuicConfirmed, nil, detail + "；响应在 DCID 长度字段处截断"
	}
	dcidLen := int(data[off])
	off++
	if dcidLen > maxCIDLen {
		return StateQuicConfirmed, nil, fmt.Sprintf(
			"%s；DCID Len=%d 超过 v1 上限 20（不合规范）", detail, dcidLen)
	}
	off += dcidLen

	// SCID
	if off < len(data) {
		scidLen := int(data[off])
		off++
		if scidLen <= maxCIDLen {
			off += scidLen
		}
	}

	// 剩余部分才是版本列表
	versions = parseVersionList(data[off:])
	return StateQuicConfirmed, versions, detail
}

func isGreased(v uint32) bool {
	for _, g := range greasedVersions {
		if v == g {
			return true
		}
	}
	return false
}

// parseVersionList 解析版本列表（每 4 字节一个大端 uint32）
func parseVersionList(b []byte) []uint32 {
	if len(b) < 4 {
		return nil
	}
	n := len(b) / 4
	vs := make([]uint32, 0, n)
	for i := 0; i+4 <= len(b); i += 4 {
		vs = append(vs, binary.BigEndian.Uint32(b[i:i+4]))
	}
	return vs
}

// Target 探测目标
type Target struct {
	Host string
	Port int
}

// ParseTargetLine 解析命令行形式的目标（host / ip / host:port / URL）
func ParseTargetLine(line string, defaultPort int) (Target, bool) {
	s := trimSpace(line)
	if s == "" || s[0] == '#' {
		return Target{}, false
	}
	// 去 URL 前缀
	if len(s) > 8 && (s[:7] == "http://" || s[:8] == "https://") {
		if s[:7] == "http://" {
			s = s[7:]
		} else {
			s = s[8:]
		}
		if i := indexByte(s, '/'); i >= 0 {
			s = s[:i]
		}
	}
	// 去掉末尾的 / 和路径
	if i := indexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	// IPv6 字面量 [::1]:443
	if len(s) > 2 && s[0] == '[' {
		if i := indexByte(s, ']'); i > 0 {
			host := s[1:i]
			port := defaultPort
			if i+1 < len(s) && s[i+1] == ':' {
				if p, err := strconv.Atoi(s[i+2:]); err == nil {
					port = p
				}
			}
			return Target{Host: host, Port: port}, true
		}
	}
	// host:port
	if i := lastIndexByte(s, ':'); i > 0 {
		// 排除 IPv6 无括号形式（多个冒号）
		if indexByte(s, ':') == i {
			if p, err := strconv.Atoi(s[i+1:]); err == nil && p > 0 && p <= 65535 {
				return Target{Host: s[:i], Port: p}, true
			}
		}
	}
	return Target{Host: s, Port: defaultPort}, true
}

func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && isSpace(s[i]) {
		i++
	}
	for j > i && isSpace(s[j-1]) {
		j--
	}
	return s[i:j]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// Config 探测器配置
type Config struct {
	// Timeout 单次探测超时
	Timeout time.Duration
	// Probes 每个目标发几个探测包（轮换不同 greased version）
	Probes int
	// Concurrency 并发数
	Concurrency int
	// KeepRaw 是否保留原始响应 hex（取证用）
	KeepRaw bool
}

// DefaultConfig 返回默认配置
func DefaultConfig() Config {
	return Config{
		Timeout:     3 * time.Second,
		Probes:      2,
		Concurrency: 32,
		KeepRaw:     true,
	}
}

// Probe 探测单个目标是否运行 QUIC
func Probe(t Target, cfg Config) Result {
	r := Result{Host: t.Host, Port: t.Port, State: StateOpenFiltered}
	if cfg.Probes < 1 {
		cfg.Probes = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}

	var firstRTT time.Duration
	responses := 0
	confirmations := 0
	sent := 0
	lastDetail := "无响应（UDP open|filtered 无法区分）"

	// 收集所有确认的版本（不同探测包可能回不同 VN，取并集更稳）
	var allVersions []uint32
	seenVersions := map[uint32]bool{}
	var lastRaw []byte

	for i := 0; i < cfg.Probes; i++ {
		version := greasedVersions[i%len(greasedVersions)]
		pkt := buildInitialPacket(version, 8, 8)
		sent++

		data, rtt, err := sendProbe(t, pkt, cfg.Timeout)
		if err != nil {
			if isConnRefused(err) {
				// ICMP port unreachable —— 端口确定关闭，靠 ICMP 快速失败
				r.Detail = "ICMP port unreachable — 端口关闭"
				r.ProbesSent = sent
				r.Confidence = 100
				return r
			}
			if isTimeout(err) {
				lastDetail = fmt.Sprintf(
					"%d/%d 个探测包无响应（UDP open|filtered 无法区分）",
					sent-responses, sent)
			} else {
				lastDetail = fmt.Sprintf("网络错误：%v", err)
			}
			continue
		}

		if firstRTT == 0 {
			firstRTT = rtt
		}
		responses++

		state, versions, detail := parseResponse(data)
		if state == StateQuicConfirmed {
			confirmations++
			lastRaw = data
			for _, v := range versions {
				if !seenVersions[v] {
					seenVersions[v] = true
					allVersions = append(allVersions, v)
				}
			}
			// 记录细节但不立即返回 —— 发完全部探测包以统计置信度
			lastDetail = detail
			continue
		}
		lastDetail = detail
	}

	r.RTT = firstRTT
	r.ProbesSent = sent
	r.ProbesResponded = responses
	r.ProbesConfirmed = confirmations
	r.ServerVersions = allVersions
	r.StackHint = IdentifyStack(allVersions)
	if cfg.KeepRaw && lastRaw != nil {
		r.RawResponse = hexDump(lastRaw)
	}
	r.Confidence = scoreConfidence(sent, responses, confirmations)

	// ⭐ 判定：至少一个包收到 VN 才确认 QUIC
	switch {
	case confirmations > 0:
		r.State = StateQuicConfirmed
		r.Detail = fmt.Sprintf("收到 Version Negotiation %d/%d 次（version=0x00000000）%s",
			confirmations, sent, jitterNote(confirmations, sent))
	case responses > 0:
		r.State = StateNonQUIC
		r.Detail = lastDetail
	default:
		r.State = StateOpenFiltered
		r.Detail = lastDetail
	}
	return r
}

// jitterNote 生成抖动提示
func jitterNote(confirmed, sent int) string {
	if confirmed == sent {
		return ""
	}
	return fmt.Sprintf("；⚠ %d/%d 包无响应，存在网络抖动，建议提高 -probes 重试",
		sent-confirmed, sent)
}

// scoreConfidence 置信度评分（0-100）
//
// ⭐ 为什么需要它：实测（2026-10-04，28 个国内站点，每目标 8 轮）显示
// 同一目标的判定会因 UDP 丢包波动：
//
//	www.sina.com.cn      7/8 确认（1 轮无响应）
//	www.toutiao.com      8/8 确认
//	www.xiaohongshu.com  0/8 确认（真的没 QUIC）
//
// 二元的"确认/不确认"会掩盖这种不确定性，所以必须把统计量暴露给调用方。
func scoreConfidence(sent, responded, confirmed int) int {
	if sent == 0 {
		return 0
	}
	if confirmed > 0 {
		// 1/4 → 25, 2/4 → 50, 3/4 → 75, 4/4 → 100
		score := confirmed * 100 / sent
		if responded < sent {
			score -= 10 // 有包丢失 → 体现不确定性
		}
		if score < 10 {
			score = 10
		}
		return score
	}
	if responded > 0 {
		// 端口开着但不是 QUIC —— 结论确定，但方向与"QUIC 存活"相反
		return 15
	}
	// UDP 原罪：零证据
	return 0
}

// sendProbe 发送单个探测包并等待响应
func sendProbe(t Target, pkt []byte, timeout time.Duration) ([]byte, time.Duration, error) {
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	// ⭐ 普通 UDP socket，不需要 root，不需要 raw socket
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, 0, err
	}
	start := time.Now()
	if _, err := conn.Write(pkt); err != nil {
		return nil, 0, err
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	rtt := time.Since(start)
	if err != nil {
		return nil, rtt, err
	}
	return buf[:n], rtt, nil
}

func isTimeout(err error) bool {
	type timeouter interface{ Timeout() bool }
	if te, ok := err.(timeouter); ok && te.Timeout() {
		return true
	}
	return false
}

// isConnRefused 判断是否为"连接被拒绝"（ICMP port unreachable）
//
// ⚠️ Windows 与 Linux 的错误类型不同：
//
//	Windows: WSAECONNRESET (10054)
//	Linux:   ECONNREFUSED (111)
func isConnRefused(err error) bool {
	s := err.Error()
	return contains(s, "10054") || // WSAECONNRESET
		contains(s, "connection was forcibly closed") ||
		contains(s, "connection refused") ||
		contains(s, "ECONNREFUSED") ||
		contains(s, "拒绝") // 中文 Windows
}

func hexDump(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*3)
	for i, c := range b {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, hexDigits[c>>4], hexDigits[c&0x0f])
	}
	return string(out)
}

// ── 批量与摘要 ────────────────────────────────────────────

// Summary 汇总统计
type Summary struct {
	Total         int            `json:"total"`
	QuicConfirmed int            `json:"quic_confirmed"`
	NonQUIC       int            `json:"udp_resp"`
	OpenFiltered  int            `json:"open_or_filtered"`
	VendorCount   map[string]int `json:"vendor_breakdown,omitempty"`
}

// Scan 并发探测多个目标
func Scan(targets []Target, cfg Config) []Result {
	if len(targets) == 0 {
		return nil
	}
	workers := cfg.Concurrency
	if workers < 1 {
		workers = 1
	}
	if workers > len(targets) {
		workers = len(targets)
	}

	results := make([]Result, len(targets))
	jobs := make(chan int, len(targets))
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				results[idx] = Probe(targets[idx], cfg)
			}
		}()
	}

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(len(targets)/workers+1)*cfg.Timeout+30*time.Second)
	defer cancel()

	go func() {
		defer close(jobs)
		for i := range targets {
			select {
			case <-ctx.Done():
				return
			case jobs <- i:
			}
		}
	}()
	wg.Wait()

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].IsQUIC() != results[j].IsQUIC() {
			return results[i].IsQUIC()
		}
		if results[i].Host != results[j].Host {
			return results[i].Host < results[j].Host
		}
		return results[i].Port < results[j].Port
	})
	return results
}

// Summarize 统计结果分布
func Summarize(results []Result) Summary {
	s := Summary{Total: len(results), VendorCount: map[string]int{}}
	for _, r := range results {
		switch r.State {
		case StateQuicConfirmed:
			s.QuicConfirmed++
			if r.StackHint != "" {
				s.VendorCount[r.StackHint]++
			}
		case StateNonQUIC:
			s.NonQUIC++
		default:
			s.OpenFiltered++
		}
	}
	if len(s.VendorCount) == 0 {
		s.VendorCount = nil
	}
	return s
}

// VersionText 返回版本列表的可读文本
//
// ⭐ 保留完整版本号（含非 RFC 的国内自研栈），
// 因为"识别出这是腾讯/阿里的自研 QUIC"本身就是有价值的信息。
func (r Result) VersionText() string {
	if len(r.ServerVersions) == 0 {
		return ""
	}
	parts := make([]string, 0, len(r.ServerVersions))
	for i, v := range r.ServerVersions {
		if i >= 3 {
			parts = append(parts, fmt.Sprintf("0x%08x", r.ServerVersions[i]))
			parts = append(parts, "…")
			break
		}
		parts = append(parts, fmt.Sprintf("0x%08x", v))
	}
	return strings.Join(parts, ",")
}

// MarshalJSON 让 State 在 JSON 里输出可读字符串
//
// ⚠️ State 是 int 枚举，默认序列化会是数字（"state": 3），
//
//	对使用者毫无意义。必须实现 Marshaler。
func (s State) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON 支持从字符串读回
func (s *State) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		switch str {
		case "QUIC_CONFIRMED":
			*s = StateQuicConfirmed
		case "NON_QUIC_RESP":
			*s = StateNonQUIC
		case "OPEN_FILTERED":
			*s = StateOpenFiltered
		default:
			*s = StateUnknown
		}
		return nil
	}
	// 兼容数字
	var n int
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*s = State(n)
	return nil
}
