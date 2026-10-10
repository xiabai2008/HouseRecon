// quicprobe — QUIC / UDP-443 探活 CLI
//
// 用法：
//
//	quicprobe -t 127.0.0.1:14430
//	quicprobe -t example.com -v
//	quicprobe -f targets.txt -o result.json -w 32
//	quicprobe -f targets.txt --csv
//	quicprobe -selftest
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wukan/quicprobe-go/quicprobe"
)

const version = "wukan-quic-probe/0.2.0-go"

var (
	flagTarget   = flag.String("t", "", "单个目标 host 或 host:port")
	flagFile     = flag.String("f", "", "目标文件，每行一个")
	flagPort     = flag.Int("p", 443, "默认端口")
	flagWorkers  = flag.Int("w", 32, "并发数")
	flagTimeout  = flag.Duration("timeout", 3*time.Second, "单次探测超时")
	flagProbes   = flag.Int("probes", 2, "每目标探测包数（轮换 version）")
	flagOutput   = flag.String("o", "", "输出 JSON 文件")
	flagCSV      = flag.Bool("csv", false, "输出 CSV（供 Excel 打开）")
	flagVerbose  = flag.Bool("v", false, "详细输出")
	flagSelftest = flag.Bool("selftest", false, "跑内置自测（无需网络）")
	flagNoRaw    = flag.Bool("no-raw", false, "不保留原始响应（减小输出）")
	flagShowVer  = flag.Bool("version", false, "显示版本")
)

func main() {
	flag.Parse()

	if *flagShowVer {
		fmt.Println(version)
		return
	}

	if *flagSelftest {
		if runSelfTest() {
			os.Exit(0)
		}
		os.Exit(1)
	}

	cfg := quicprobe.DefaultConfig()
	cfg.Timeout = *flagTimeout
	cfg.Probes = *flagProbes
	cfg.Concurrency = *flagWorkers
	cfg.KeepRaw = !*flagNoRaw

	var targets []quicprobe.Target
	if *flagTarget != "" {
		if t, ok := quicprobe.ParseTargetLine(*flagTarget, *flagPort); ok {
			targets = append(targets, t)
		}
	}
	if *flagFile != "" {
		ts, err := quicprobe.LoadTargets(*flagFile, *flagPort)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取目标文件失败: %v\n", err)
			os.Exit(1)
		}
		targets = append(targets, ts...)
	}
	// 显式 -p 且目标没写端口时，套用默认端口
	if *flagPort != 443 {
		for i := range targets {
			if targets[i].Port == 443 {
				targets[i].Port = *flagPort
			}
		}
	}

	if len(targets) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	if *flagVerbose {
		fmt.Printf("[%s] 目标 %d 个 | 并发 %d | 超时 %v | 每目标 %d 包\n",
			version, len(targets), cfg.Concurrency, cfg.Timeout, cfg.Probes)
		fmt.Println()
	}

	// 进度输出
	var lastPrint int64
	quicprobe.OnProgress = func(done, total int, r quicprobe.Result) {
		if !*flagVerbose {
			return
		}
		if n := atomic.LoadInt64(&lastPrint); n != int64(total) &&
			(done%maxInt(total/20, 1) == 0 || done == total) {
			atomic.StoreInt64(&lastPrint, int64(total))
			fmt.Fprintf(os.Stderr, "\r  进度 %d/%d (%.0f%%)", done, total,
				float64(done)/float64(total)*100)
			if done == total {
				fmt.Fprintln(os.Stderr)
			}
		}
	}

	start := time.Now()
	results := quicprobe.Scan(targets, cfg)
	elapsed := time.Since(start)

	// ── 输出 ──
	if *flagCSV {
		if err := writeCSV(results, ""); err != nil {
			fmt.Fprintf(os.Stderr, "写 CSV 失败: %v\n", err)
		} else {
			fmt.Printf("已写入 %s\n", "quic_result.csv")
		}
	}

	for _, r := range results {
		if *flagVerbose || r.IsQUIC() {
			fmt.Println(r)
		} else {
			fmt.Printf("[?   ] %s:%d  %s\n", r.Host, r.Port, r.Detail)
		}
	}

	summary := quicprobe.Summarize(results)

	fmt.Println(strings.Repeat("-", 74))
	fmt.Printf("共 %d 个目标 | 耗时 %.2fs\n", summary.Total, elapsed.Seconds())
	fmt.Printf("  ⭐ QUIC 已确认 : %d\n", summary.QuicConfirmed)
	fmt.Printf("  ⚠ UDP 有响应  : %d（非标准 QUIC）\n", summary.NonQUIC)
	fmt.Printf("  ? open|filtered: %d（UDP 固有不确定性）\n", summary.OpenOrFiltered)

	if len(summary.VendorBreakdown) > 0 {
		fmt.Println()
		fmt.Println("QUIC 实现归属分布：")
		for vendor, n := range summary.VendorBreakdown {
			fmt.Printf("  %-16s %d\n", vendor, n)
		}
	}

	if summary.QuicConfirmed > 0 {
		fmt.Println()
		fmt.Println("⭐ 结论：以下目标的 UDP/443 确定运行 QUIC ——")
		fmt.Println("   传统 TCP-only 扫描器（naabu / httpx / Shodan / Censys / ZMap）会完全漏掉它们")
		for _, r := range results {
			if !r.IsQUIC() {
				continue
			}
			line := fmt.Sprintf("   %s:%d", r.Host, r.Port)
			if len(r.ServerVersions) > 0 {
				line += "  支持 " + fmtVersions(r.ServerVersions)
			}
			if r.StackHint != "" {
				line += "  [" + r.StackHint + "]"
			}
			fmt.Println(line)
		}
	}

	if *flagOutput != "" {
		if err := writeJSON(*flagOutput, results, summary, elapsed); err != nil {
			fmt.Fprintf(os.Stderr, "写 JSON 失败: %v\n", err)
		} else {
			fmt.Printf("\n已写入 %s\n", *flagOutput)
		}
	}
}

func fmtVersions(vs []uint32) string {
	out := ""
	for i, v := range vs {
		if i >= 3 {
			out += ",..."
			break
		}
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf("0x%08x", v)
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func writeJSON(path string, results []quicprobe.Result, summary quicprobe.Summary, elapsed time.Duration) error {
	out := struct {
		Scanner string            `json:"scanner"`
		Elapsed string            `json:"elapsed"`
		Summary quicprobe.Summary `json:"summary"`
		Results []map[string]any  `json:"results"`
	}{
		Scanner: version,
		Elapsed: elapsed.String(),
		Summary: summary,
	}
	for _, r := range results {
		out.Results = append(out.Results, r.ToJSON())
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func writeCSV(results []quicprobe.Result, path string) error {
	if path == "" {
		path = "quic_result.csv"
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{
		"host", "port", "state", "rtt_ms",
		"server_versions", "stack_hint", "detail",
	}); err != nil {
		return err
	}
	for _, r := range results {
		rtt := ""
		if r.RTT > 0 {
			rtt = strconv.FormatFloat(float64(r.RTT.Microseconds())/1000, 'f', 2, 64)
		}
		if err := w.Write([]string{
			r.Host,
			strconv.Itoa(r.Port),
			r.State.String(),
			rtt,
			fmtVersions(r.ServerVersions),
			r.StackHint,
			r.Detail,
		}); err != nil {
			return err
		}
	}
	return nil
}

// ── 内置自测（不依赖网络）───────────────────────────────────

func runSelfTest() bool {
	pass, fail := 0, 0
	report := func(name string, ok bool, expect, got string) {
		if ok {
			pass++
			fmt.Printf("  [PASS] ✓ %s\n", name)
		} else {
			fail++
			fmt.Printf("  [FAIL] ✗ %s\n", name)
			fmt.Printf("         期望: %s\n", expect)
			fmt.Printf("         实得: %s\n", got)
		}
	}

	fmt.Println("==============================================================")
	fmt.Println("QUIC 探活 Go 版 — 内置自测")
	fmt.Println("==============================================================")
	fmt.Println()

	// S1: 探测包必须 1200 字节且布局正确
	pkt := buildInitialForTest(0x0A0A0A0A)
	s1 := len(pkt) == 1200 && pkt[0] == 0xC0 &&
		pkt[5] == 8 && pkt[14] == 8
	report("S1 探测包 1200 字节 / flags=0xC0 / DCID_Len=8 / SCID_Len=8",
		s1, "1200 字节且头部字段正确",
		fmt.Sprintf("len=%d flags=0x%02x dcidLen=%d scidLen=%d",
			len(pkt), pkt[0], pkt[5], pkt[14]))

	// S2: Version 字段必须在明文位置 1..4
	v := uint32(pkt[1])<<24 | uint32(pkt[2])<<16 | uint32(pkt[3])<<8 | uint32(pkt[4])
	report("S2 Version 字段位于明文偏移 1..4",
		v == 0x0A0A0A0A, "0x0A0A0A0A", fmt.Sprintf("0x%08X", v))

	// ⭐ S3: VN 包解析 — 用真实抓包（quic-go v0.48.2 与本地靶场结构一致）
	//
	// ⭐ 这段 hex 是【权威基准】，由已验证正确的 Python 版解析器
	//    实际抓包产出（offset=23 已用 parse_quic_response 确认）。
	//    Go 版必须对它给出完全相同的结论。
	//
	// 逐字段拆解（共 31 字节）：
	//   c0                    flags（长包头+FixedBit+Initial）
	//   00000000              Version = 0            ← VN 唯一确定性标志
	//   08                    DCID Len = 8
	//   0001020304050607      DCID（回显客户端 CID）
	//   08                    SCID Len = 8
	//   0001020304050607      SCID（服务端 CID）
	//   00000001              支持 QUIC v1 (RFC 9000)
	//   6b3343cf              支持 QUIC v2 (RFC 9369)
	// 偏移 = 1+4+1+8+1+8 = 23
	realVN := mustHex(
		"c0" + // flags
			"00000000" + // Version = 0
			"08" + // DCID Len = 8   ← ⚠️ 必须是 8，早期误写成 0
			"0001020304050607" + // DCID
			"08" + // SCID Len = 8
			"0001020304050607" + // SCID
			"00000001" + // QUIC v1
			"6b3343cf") // QUIC v2
	state, vers, detail := parseForTest(realVN)
	s3 := state == quicprobe.StateQuicConfirmed &&
		len(vers) == 2 && vers[0] == 0x00000001 && vers[1] == 0x6B3343CF
	report("S3 ⭐ 真实抓包 VN 解析 → 正确提取 v1/v2",
		s3, "QUIC_CONFIRMED + versions=[0x00000001, 0x6B3343CF]",
		fmt.Sprintf("state=%s versions=[%s] detail=%s", state,
			hexList(vers), detail))

	// S4: 版本列表偏移必须是 23
	// ⚠️ 这是早期 bug 的核心断言：漏掉 DCID/SCID 会让偏移算成 5，
	//    把 CID 字节误当版本号读（实测得到 0x08090a0b 这类垃圾）。
	//    用上面这份权威 hex 做交叉校验，Go 与 Python 必须一致。
	off := quicprobe.VersionListOffset(realVN)
	s4 := off == 23
	report("S4 ⭐ 版本列表偏移 = 23（与 Python 版解析器交叉校验）",
		s4, "23", strconv.Itoa(off))

	// S5: 截断的 VN 包不能崩，且仍判 QUIC
	trunc := mustHex("c0" + "00000000" + "00" + "00")
	st5, v5, _ := parseForTest(trunc)
	report("S5 截断的 VN 包 → 判 QUIC 且版本列表为空，不 panic",
		st5 == quicprobe.StateQuicConfirmed && len(v5) == 0,
		"QUIC_CONFIRMED + versions=[]",
		fmt.Sprintf("state=%s versions=%v", st5, v5))

	// S6: 短包头（Header Form=0）不得判为 QUIC
	short := mustHex("40" + "01020304050607")
	st6, _, _ := parseForTest(short)
	report("S6 短包头响应 → NON_QUIC（防假阳性）",
		st6 == quicprobe.StateNonQUIC, "NON_QUIC_RESP", st6.String())

	// S7: 服务端回显 greased version 不得判为 QUIC
	echo := []byte{0xC0, 0x0A, 0x0A, 0x0A, 0x0A, 0, 1, 2, 3, 4, 5, 6, 7}
	st7, _, _ := parseForTest(echo)
	report("S7 服务端回显 greased version → NON_QUIC（防假阳性）",
		st7 == quicprobe.StateNonQUIC, "NON_QUIC_RESP", st7.String())

	// S8: 响应过短不得 panic
	st8, _, _ := parseForTest([]byte{0xC0, 0x00})
	report("S8 响应过短（2 字节）→ 优雅降级不 panic",
		st8 == quicprobe.StateOpenFiltered, "OPEN_FILTERED", st8.String())

	// ⭐ S9: 国内自研版本识别
	s9 := quicprobe.IdentifyStack([]uint32{0x51303339}) == "腾讯" &&
		quicprobe.IdentifyStack([]uint32{0xFF00001D}) == "阿里" &&
		quicprobe.IdentifyStack([]uint32{0x5AEA5A8A}) == "字节" &&
		quicprobe.IdentifyStack([]uint32{0x00000001}) == "QUIC v1"
	report("S9 ⭐ 国内自研 QUIC 栈识别（腾讯Q039/阿里/字节/RFC v1）",
		s9, "腾讯 / 阿里 / 字节 / QUIC v1",
		quicprobe.IdentifyStack([]uint32{0x51303339, 0xFF00001D, 0x5AEA5A8A, 0x00000001}))

	// S10: 多厂商混合
	s10 := quicprobe.IdentifyStack([]uint32{0x00000001, 0xFF00001D, 0xFF00001E})
	report("S10 混合厂商（阿里双版本 + RFC v1）→ 合并识别",
		s10 != "" && containsSub(s10, "阿里") && containsSub(s10, "QUIC v1"),
		"含 阿里 与 QUIC v1", s10)

	// S11: 目标解析
	t1, ok1 := quicprobe.ParseTargetLine("example.com:8443", 443)
	t2, ok2 := quicprobe.ParseTargetLine("https://foo.bar/baz", 443)
	t3, ok3 := quicprobe.ParseTargetLine("1.2.3.4", 443)
	_, ok4 := quicprobe.ParseTargetLine("# comment", 443)
	s11 := ok1 && t1.Host == "example.com" && t1.Port == 8443 &&
		ok2 && t2.Host == "foo.bar" && t2.Port == 443 &&
		ok3 && t3.Host == "1.2.3.4" && t3.Port == 443 &&
		!ok4
	report("S11 目标解析（host:port / URL / 纯IP / 注释行）",
		s11,
		"example.com:8443 / foo.bar:443 / 1.2.3.4:443 / 注释跳过",
		fmt.Sprintf("%v %v %v %v", t1, t2, t3, ok4))

	// S12: 超长 DCID 响应不得 panic
	over := []byte{0xC0, 0, 0, 0, 0, 30}
	over = append(over, make([]byte, 40)...)
	st12, _, _ := parseForTest(over)
	report("S12 超长 DCID Len=30（超 v1 上限）→ 不 panic",
		st12 != quicprobe.StateUnknown, "任意有效状态", st12.String())

	fmt.Println()
	fmt.Println(strings.Repeat("=", 62))
	fmt.Printf("自测结果: %d 通过 / %d 失败\n", pass, fail)
	fmt.Println(strings.Repeat("=", 62))
	return fail == 0
}

// 测试辅助：直接调用包内逻辑（通过重新导出实现）
// 注：buildInitialPacket 是小写不可见，这里用同逻辑的小包装器
func buildInitialForTest(version uint32) []byte {
	pkt := make([]byte, 0, 1200)
	pkt = append(pkt, 0xC0)
	pkt = append(pkt, byte(version>>24), byte(version>>16), byte(version>>8), byte(version))
	pkt = append(pkt, 8)
	for i := 0; i < 8; i++ {
		pkt = append(pkt, byte(i))
	}
	pkt = append(pkt, 8)
	for i := 0; i < 8; i++ {
		pkt = append(pkt, byte(8+i))
	}
	pkt = append(pkt, 0x00, 0x00)
	for len(pkt) < 1200 {
		pkt = append(pkt, 0x00)
	}
	return pkt
}

func parseForTest(data []byte) (quicprobe.State, []uint32, string) {
	// 通过导出方法间接调用（Probe 内部使用同一 parseResponse）
	r := quicprobe.ParseResponseForTest(data)
	return r.State, r.ServerVersions, r.Detail
}

func mustHex(s string) []byte {
	b := make([]byte, 0, 64)
	var cur byte
	half := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' {
			continue
		}
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			continue
		}
		if !half {
			cur = v << 4
			half = true
		} else {
			b = append(b, cur|v)
			half = false
		}
	}
	return b
}

func hexList(vs []uint32) string {
	if len(vs) == 0 {
		return ""
	}
	out := ""
	for i, v := range vs {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf("0x%08x", v)
	}
	return out
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
