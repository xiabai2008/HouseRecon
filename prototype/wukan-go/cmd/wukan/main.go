// wukan — 屋勘 HouseRecon CLI
//
// 现阶段仅实现 ipinfo 子命令（IP 归属批量查询）。
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/wukan/wukan/internal/httpprobe"
	"github.com/wukan/wukan/internal/ipinfo"
	"github.com/wukan/wukan/internal/portscan"
	"github.com/wukan/wukan/internal/recon"
)

const version = "wukan/0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "ipinfo", "ip":
		runIPInfo(os.Args[2:])
	case "recon":
		runRecon(os.Args[2:])
	case "ports", "portscan":
		runPorts(os.Args[2:])
	case "tech", "fingerprint", "fp":
		runTech(os.Args[2:])
	case "diff":
		runDiff(os.Args[2:])
	case "version", "-v", "--version":
		printVersion(os.Stdout)
	case "help", "-h", "--help":
		// ⭐ 帮助是**正常请求**，输出到 stdout（便于 `wukan help > doc.txt`）；
		//   而"无参数 / 未知命令"属于错误路径，走 stderr + 非零退出码。
		printUsageTo(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

// ── 启动页 ────────────────────────────────────────────────

// ANSI 颜色
//
// ⭐ 只在 TTY 下启用（见 colorOn）。输出被重定向或接入管道时自动降级为纯文本，
// 保证 `wukan help | grep xxx` 这类用法拿到的是干净输出。
// 同时遵循 NO_COLOR 约定（https://no-color.org/）。
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiCyan   = "\033[36m"
	ansiYellow = "\033[33m"
	ansiDim    = "\033[90m"
)

// isTTY 判断 writer 是否连着终端
func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// colorOn 是否启用 ANSI 颜色
func colorOn(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("WUKAN_NO_COLOR") != "" {
		return false
	}
	if os.Getenv("WUKAN_FORCE_COLOR") != "" {
		return true
	}
	return isTTY(w)
}

// bannerOn 是否输出启动页
//
// ⭐ 只在终端下输出。理由：启动页是**给人看的装饰**，
// 一旦输出被重定向（`wukan help > doc.txt`、`| grep`），
// ASCII 图案会污染可解析的内容。非 TTY 时自动省略。
// 也可用 WUKAN_NO_BANNER=1 强制关闭。
func bannerOn(w io.Writer) bool {
	if os.Getenv("WUKAN_NO_BANNER") != "" {
		return false
	}
	// ⭐ 强制显示：用于 CI 日志、录屏、或想在管道里保留启动页的场景
	if os.Getenv("WUKAN_FORCE_BANNER") != "" {
		return true
	}
	return isTTY(w)
}

// printBanner 输出 ASCII 启动页
//
// 图案取自项目命名文档（名称.txt）：
//
//	  /\
//	 /  \
//	/____\
//	| [] |  屋勘 HouseRecon
//	|____|  一屋之内，勘遍全网
//
// ⭐ 房子用 6 字符宽（`/____\` 与 `| [] |` 等宽），保证屋顶与墙体对齐。
func printBanner(w io.Writer) {
	if !bannerOn(w) {
		return
	}
	col := colorOn(w)
	paint := func(code, s string) string {
		if !col {
			return s
		}
		return code + s + ansiReset
	}
	ver := strings.TrimPrefix(version, "wukan/")

	rows := []struct{ house, text string }{
		{`  /\`, ""},
		{` /  \`, ""},
		{`/____\`, ""},
		{`| [] |`, "  " + paint(ansiBold+ansiCyan, "屋勘 HouseRecon") +
			paint(ansiDim, "  v"+ver)},
		{`|____|`, "  " + paint(ansiYellow, "一屋之内，勘遍全网")},
	}
	for _, r := range rows {
		fmt.Fprintf(w, "%s%s\n", paint(ansiCyan, r.house), r.text)
	}
	fmt.Fprintln(w)
}

// printVersion 输出版本信息（TTY 下先打启动页）
//
// ⭐ 版本号本身保持**单行**输出，因为脚本常解析它。
//
//	启动页只在 TTY 下出现（见 bannerOn），
//	所以 `wukan version | awk '{print $1}'` 依然只拿到 "wukan/0.1.0"。
func printVersion(w io.Writer) {
	printBanner(w)
	fmt.Fprintln(w, version)
}

// printUsage 输出到 stderr（用于错误路径：无参数、未知命令）
func printUsage() { printUsageTo(os.Stderr) }

// printUsageTo 输出帮助
func printUsageTo(w io.Writer) {
	printBanner(w)
	fmt.Fprint(w, `网络空间资产侦察与信息收集工具

用法:
  wukan <命令> [参数]

命令:
  recon <域名...>     目标信息卡（DNS + 注册信息 + 证书子域 + 被动DNS）
                      ⭐ 一条龙: --ports 80,443 --tech
                      ⭐ 变化监控: --snapshot（保存快照并与上次对比）
  tech <URL...>       HTTP 指纹采集 + ⭐冲突检测
  ports <主机...>     端口扫描（⚠ 主动探测，需指定端口）
  ipinfo <IP...>      IP 归属批量查询
  diff <域名...>      ⭐ 快照对比（变化监控，需先 recon --snapshot）
  version             显示版本
  help                显示本帮助

快速上手:
  wukan recon example.com
  wukan recon example.com -o recon.json
  wukan tech https://example.com
  wukan tech https://a.com https://b.com --conflicts
  wukan ports 127.0.0.1 -p 80,443
  wukan ports example.com -p top100 --rate 100
  wukan ipinfo 8.8.8.8 1.1.1.1
  wukan ipinfo -f iplist.txt -o out.csv
  wukan ipinfo -f iplist.txt --ips-only -o clean.txt | nmap -iL -

详细参数:
  wukan tech -h
  wukan ports -h
  wukan recon -h
  wukan ipinfo -h
`)
}

// ── ipinfo 子命令 ─────────────────────────────────────────

type ipinfoFlags struct {
	file       string
	output     string
	format     string
	workers    int
	rateLimit  int
	timeout    int
	noCache    bool
	noSecond   bool
	cachePath  string
	clearCache bool
	cacheStats bool
	showGeo    bool
	quiet      bool
	// ⭐ rDNS 反查（默认关闭，见 ipinfo.WithRDNS 的理由）
	withRdns bool
	// showRdns 表格显示 PTR 列
	showRdns bool
}

func runIPInfo(args []string) {
	f := parseIPInfoFlags(args)
	if f == nil {
		return
	}

	// 缓存管理子操作
	if f.clearCache || f.cacheStats {
		handleCacheOps(f)
		return
	}

	// 收集目标
	targets := collectIPTargets(args)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "错误: 未指定任何 IP。用法: wukan ipinfo <IP...> | -f <file>")
		os.Exit(2)
	}

	// 初始化缓存
	var cache *ipinfo.FileCache
	if !f.noCache {
		path := f.cachePath
		if path == "" {
			path = ipinfo.DefaultCachePath()
		}
		c, err := ipinfo.NewFileCache(path, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "警告: 载入缓存失败（%v），本次不缓存\n", err)
		} else {
			cache = c
		}
	}

	// 组装选项
	// ⭐ 限速换算：rate 表示"每秒最多 N 个请求"，
	//   而 WithRateLimit 接受的是"每个请求之间的最小间隔"。
	//   1000000/8=125000ns=125ms → 8 req/s
	interval := time.Second / time.Duration(maxInt(f.rateLimit, 1))
	opts := []ipinfo.Option{
		ipinfo.WithTimeout(time.Duration(maxInt(f.timeout, 1)) * time.Second),
		ipinfo.WithRateLimit(interval),
		ipinfo.WithSecondary(!f.noSecond),
		ipinfo.WithRDNS(f.withRdns),
	}
	if cache != nil {
		opts = append(opts, ipinfo.WithCache(cache))
	}

	client := ipinfo.New(opts...)

	if !f.quiet {
		fmt.Fprintf(os.Stderr, "[%s] 查询 %d 个 IP | 并发 %d | 限速 %d/s\n",
			version, len(targets), f.workers, f.rateLimit)
	}

	results := client.LookupMany(targets, f.workers)

	// 落盘缓存
	if cache != nil {
		if err := cache.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "警告: 保存缓存失败: %v\n", err)
		}
	}

	// 输出
	outputPath := f.output
	if err := emit(f.format, outputPath, results, f.showGeo, f.quiet, f.showRdns); err != nil {
		fmt.Fprintf(os.Stderr, "输出失败: %v\n", err)
		os.Exit(1)
	}

	// 统计摘要
	if !f.quiet && f.format != "ips" {
		ipinfo.PrintSummary(os.Stderr, ipinfo.Summarize(results))
	}
}

// emit 输出结果
//
// ⭐ 格式推断优先级：
//
//  1. 显式 --format / --csv / --json 指定的格式
//
//  2. 未显式指定时，从 -o 的**文件扩展名**推断
//
//  3. 都没给 → table
//
//     这个推断是必需的：用户写 `-o result.json` 时的直觉是"要 JSON"，
//     而不是"要一个装着表格的 .json 文件"。
func emit(format, path string, results []*ipinfo.Info, showGeo, quiet, showRdns bool) error {
	// 写到文件或 stdout
	var out *os.File
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	} else {
		out = os.Stdout
	}

	effFormat := format
	if effFormat == "" || effFormat == "table" {
		// 未显式指定格式时，从扩展名推断
		if path != "" {
			if inferred := inferFormatFromPath(path); inferred != "" {
				effFormat = inferred
			}
		}
		if effFormat == "" {
			effFormat = "table"
		}
	}

	switch strings.ToLower(effFormat) {
	case "csv":
		return ipinfo.WriteCSV(out, results)
	case "json":
		var stats *ipinfo.Stats
		if !quiet {
			stats = ipinfo.Summarize(results)
		}
		return ipinfo.WriteJSON(out, results, stats)
	case "ips", "txt":
		ipinfo.WriteIPS(out, results)
		return nil
	case "table", "text":
		ipinfo.WriteTable(out, results, showGeo, showRdns)
		return nil
	default:
		return fmt.Errorf("未知格式: %s（支持 table/csv/json/ips）", effFormat)
	}
}

// inferFormatFromPath 从文件扩展名推断输出格式
func inferFormatFromPath(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return "json"
	case ".csv":
		return "csv"
	case ".txt", ".list":
		return "ips"
	default:
		return ""
	}
}

func handleCacheOps(f *ipinfoFlags) {
	path := f.cachePath
	if path == "" {
		path = ipinfo.DefaultCachePath()
	}
	c, err := ipinfo.NewFileCache(path, true)
	if err != nil && !f.clearCache {
		fmt.Fprintf(os.Stderr, "载入缓存失败: %v\n", err)
		os.Exit(1)
	}
	if c == nil {
		c, _ = ipinfo.NewFileCache(path, false)
	}

	if f.clearCache {
		if err := c.Clear(); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "清空缓存失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("已清空缓存: %s\n", path)
		return
	}
	if f.cacheStats {
		total, valid, flagged := c.Stats()
		fmt.Printf("缓存文件: %s\n", path)
		fmt.Printf("条目总数: %d\n", total)
		fmt.Printf("有效条目: %d\n", valid)
		fmt.Printf("带标签  : %d\n", flagged)
	}
}

// ── 参数解析 ──────────────────────────────────────────────

func parseIPInfoFlags(args []string) *ipinfoFlags {
	f := &ipinfoFlags{
		format:    "table",
		workers:   8,
		rateLimit: 8,
		timeout:   15,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-h", "--help":
			printIPInfoUsage()
			os.Exit(0)
		case "-f", "--file":
			f.file = nextArg(args, &i, a)
		case "-o", "--output":
			f.output = nextArg(args, &i, a)
		case "--format":
			f.format = nextArg(args, &i, a)
		case "--csv":
			f.format = "csv"
		case "--json":
			f.format = "json"
		case "--ips-only", "--ips":
			f.format = "ips"
		case "-w", "--workers":
			f.workers = intArg(nextArg(args, &i, a), f.workers)
		case "-r", "--rate":
			f.rateLimit = intArg(nextArg(args, &i, a), f.rateLimit)
		case "--timeout":
			f.timeout = intArg(nextArg(args, &i, a), f.timeout)
		case "--no-cache":
			f.noCache = true
		case "--no-secondary":
			f.noSecond = true
		case "--cache-path":
			f.cachePath = nextArg(args, &i, a)
		case "--clear-cache":
			f.clearCache = true
		case "--cache-stats":
			f.cacheStats = true
		case "--geo":
			f.showGeo = true
		case "--rdns":
			// ⭐ 开启 rDNS（PTR）反查
			// 注意：开启后表格默认会多出 PTR 列
			f.withRdns = true
			f.showRdns = true
		case "--rdns-table":
			// 只显示 PTR 列，不实际发起反查（用于查看已缓存的 PTR）
			f.showRdns = true
		case "-q", "--quiet":
			f.quiet = true
		default:
			// 非 flag，视为 IP 目标（稍后收集）
		}
	}
	if f.workers < 1 {
		f.workers = 1
	}
	if f.workers > 64 {
		fmt.Fprintln(os.Stderr, "提示: 并发数上限 64（触发数据源限流的概率会显著上升）")
		f.workers = 64
	}
	if f.rateLimit < 1 {
		f.rateLimit = 1
	}
	return f
}

func printIPInfoUsage() {
	fmt.Fprint(os.Stderr, `wukan ipinfo — IP 归属批量查询

用法:
  wukan ipinfo <IP...>
  wukan ipinfo -f <文件>
  wukan ipinfo -f <文件> -o <输出>

参数:
  -f, --file <文件>       从文件读取（一行一个，支持 # 注释与 host:port）
  -o, --output <文件>     输出到文件（默认 stdout）
      --format <格式>     table（默认）/ csv / json / ips
      --csv               等价于 --format csv
      --json              等价于 --format json
      --ips-only          只输出有效 IP，一行一个（用于喂给下游工具）
  -w, --workers <n>       并发数（默认 8，上限 64）
  -r, --rate <n>          每秒请求上限（默认 8）
      --timeout <秒>      单次请求超时（默认 15）
  -q, --quiet             只输出结果，不打摘要
      --geo               表格增加经纬度与时区列
      --no-cache          禁用本地缓存（强制重新查询）
      --no-secondary      禁用补充源（不查 hosting/proxy/mobile）
      --cache-path <路径> 指定缓存文件（默认 ~/.wukan/ipinfo-cache.json）
      --cache-stats       查看缓存统计后退出
      --clear-cache       清空缓存后退出
  -h, --help              显示本帮助

数据源:
  主源   ipwho.is    HTTPS · 免费 10000 次/月 · 位置/ASN/ISP/经纬度
  补充源 ip-api.com  仅用于取 hosting / proxy / mobile 标识（判断 CDN 与云主机）

示例:
  wukan tech https://example.com
  wukan tech https://a.com https://b.com --conflicts
  wukan ports 127.0.0.1 -p 80,443
  wukan ports example.com -p top100 --rate 100
  wukan ipinfo 8.8.8.8 1.1.1.1 --geo
  wukan ipinfo -f iplist.txt --csv -o归属.csv
  wukan ipinfo -f iplist.txt --ips-only -o clean.txt
  wukan ipinfo -f iplist.txt --ips-only -o clean.txt | nmap -iL - -p 80,443

说明:
  · 缓存有效期 7 天（IP 归属是基础设施级信息，变更极罕见）
  · 私有/环回/保留地址会被直接标注为无效，不消耗配额
  · 批量接口不被数据源支持，故逐个查询 + 本地缓存
`)
}

// flagsWithValue 是"后面跟一个值"的 flag 列表。
// ⭐ 收集目标时必须跳过这些值，否则文件名/格式串会被当成 IP。
var flagsWithValue = []string{
	"-f", "--file",
	"-o", "--output",
	"--format",
	"-w", "--workers",
	"-r", "--rate",
	"--timeout",
	"--cache-path",
	// recon
	"-d", "--dns",
	"-n",
	"--tech-max",
	"--tech-sub-max",
	"--quic-probes",
	"--rdns-max",
	"--reverse",
	// diff
	"--since",
	// tech
	"-c", "--concurrency",
	"--timeout",
	// ports / recon --ports
	"-p", "--ports",
	"--ports-rate",
	"--ports-sub-max",
	"-c", "--concurrency",
	"-r", "--rate",
	"--timeout",
	"--format",
}

func collectIPTargets(args []string) []string {
	var targets []string
	seen := map[string]bool{}

	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		// 去重
		if seen[s] {
			return
		}
		seen[s] = true
		targets = append(targets, s)
	}

	// ⭐ 必须跳过 flag **及其值**。
	//   之前只跳过 flag 本身，导致 `-f test_ips.txt` 里的文件名
	//   被当成 IP 送去查询（实测报"不是合法的 IP 地址"）。
	//   做法：先扫一遍，标记哪些位置是 flag 的值。
	valueIdx := map[int]bool{}
	for i, a := range args {
		for _, n := range flagsWithValue {
			if a == n && i+1 < len(args) {
				valueIdx[i+1] = true
			}
		}
	}
	for i, a := range args {
		if strings.HasPrefix(a, "-") || valueIdx[i] {
			continue
		}
		// ⭐ 命令行参数同样要容错。
		//   实测：直接传 `1.2.3.4:8080` 或 `https://5.6.7.8/x` 会全部失败，
		//   而这些形式在渗透场景里很常见（从 nmap/httpx 输出里复制）。
		if ip := extractIP(a); ip != "" {
			add(ip)
			continue
		}
		add(a)
	}

	// 从文件读
	if f := findFlagValue(args, "-f", "--file"); f != "" {
		fh, err := os.Open(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 打开文件失败: %v\n", err)
			os.Exit(1)
		}
		defer fh.Close()
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// 兼容 host:port / url / 带注释 / 逗号分隔 等形式
			if ips := extractIPs(line); len(ips) > 0 {
				for _, ip := range ips {
					add(ip)
				}
			} else {
				add(line)
			}
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "警告: 读取文件出错: %v\n", err)
		}
	}

	return targets
}

var (
	ipRe    = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	ipv6Re  = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b`)
	multiRe = regexp.MustCompile(`[,\s;]+`)
)

// extractIP 从任意文本中提取 IP
//
// ⭐ 为什么要这个：渗透测试的 IP 列表几乎从不是"纯 IP 一行一个"，
// 而是 nmap 输出、httpx 输出、复制粘贴的混合形式：
//
//	1.2.3.4:8080
//	https://5.6.7.8/admin
//	52.84.180.67 (cloudfront)  ← 带注释
//	1.1.1.1, 8.8.8.8          ← 逗号分隔
//
// 直接丢给归属查询会全部失败。
//
// 返回值可能有多个（用逗号/空格分隔时），用 extractIPs。
func extractIP(s string) string {
	ips := extractIPs(s)
	if len(ips) == 0 {
		return ""
	}
	return ips[0]
}

// extractIPs 从任意文本中提取所有 IP（支持逗号/分号/空白分隔）
func extractIPs(s string) []string {
	// 先按分隔符切开，让 "1.1.1.1, 8.8.8.8" 变成两个候选
	var out []string
	seen := map[string]bool{}
	for _, seg := range multiRe.Split(s, -1) {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		var cand string
		if m := ipRe.FindString(seg); m != "" {
			cand = m
		} else if strings.Count(seg, ":") >= 2 && !strings.Contains(seg, "://") {
			// 可能是裸 IPv6（排除 host:port 形式）
			if m := ipv6Re.FindString(seg); m != "" && net.ParseIP(m) != nil {
				cand = m
			}
		}
		if cand != "" && !seen[cand] {
			seen[cand] = true
			out = append(out, cand)
		}
	}
	return out
}

func findFlagValue(args []string, names ...string) string {
	for i, a := range args {
		for _, n := range names {
			if a == n && i+1 < len(args) {
				return args[i+1]
			}
		}
	}
	return ""
}

func nextArg(args []string, i *int, flag string) string {
	if *i+1 < len(args) {
		*i++
		return args[*i]
	}
	fmt.Fprintf(os.Stderr, "错误: %s 需要一个参数\n", flag)
	os.Exit(2)
	return ""
}

func intArg(s string, def int) int {
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── recon 子命令 ──────────────────────────────────────────

type reconFlags struct {
	output     string
	format     string
	dns        string
	maxSubs    int
	noRDAP     bool
	noCT       bool
	noPassive  bool
	reverseLim int
	doQuic     bool
	quicProbes int
	// ⭐ 端口扫描（主动探测）
	scanPorts  string
	portsRate  int
	portsNoBan bool
	// ⭐ 端口结果缓存
	noPortsCache    bool
	portsCacheStats bool
	portsCacheClear bool
	// ⭐ 存活子域批量端口扫描（-1 = 未指定，用默认值）
	portsSubMax int
	// ⭐ HTTP 指纹采集（主动探测）
	doTech         bool
	techNoFav      bool
	techMax        int
	noTechSub      bool
	techSubMax     int
	noTechCache    bool
	techCacheStats bool
	techCacheClear bool
	noTechRetry    bool
	noRdns         bool
	rdnsMax        int
	noIPInfo       bool
	noVerify       bool
	parallel       bool
	allDomains     bool
	noCache        bool
	quiet          bool
	// ⭐ 资产快照（P1-1 变化监控）
	snapshot bool
}

func runRecon(args []string) {
	f := parseReconFlags(args)
	if len(args) == 0 {
		printReconUsage()
		os.Exit(2)
	}

	targets := collectDomains(args)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "错误: 未指定域名。用法: wukan recon <域名...> | -f <文件>")
		os.Exit(2)
	}

	// 组装选项
	opt := recon.DefaultOptions()

	// DNS 解析器
	resolver, ok := recon.PredefinedDoH(f.dns)
	if !ok {
		fmt.Fprintf(os.Stderr, "错误: 未知解析器 %q（可选: alidns/cloudflare/google/quad9/360/dnspod 或直接给 https:// URL）\n", f.dns)
		os.Exit(2)
	}
	opt.CT.Resolver = resolver
	opt.DNS.Timeout = 8 * time.Second

	opt.RDAP.Enabled = !f.noRDAP
	// ⭐ QUIC 探活是**主动探测**（会向目标发 UDP 包），默认关闭
	opt.QuicProbe = f.doQuic
	if f.quicProbes > 0 {
		opt.QuicProbes = f.quicProbes
	}
	// ⭐ 端口扫描是**主动探测**（会真正建立 TCP 连接），默认不开启
	opt.PortsScan = f.scanPorts != ""
	if opt.PortsScan {
		opt.PortsSpec = f.scanPorts
		if f.portsRate > 0 {
			opt.PortsRate = f.portsRate
		}
		opt.PortsGrabBanner = !f.portsNoBan
		// ⭐ 存活子域批量扫描（-1 = 未指定，保留 DefaultOptions 的默认值 10）
		if f.portsSubMax >= 0 {
			opt.PortsSubMax = f.portsSubMax
		}
	}
	// ⭐ HTTP 指纹采集是**主动探测**（发 HTTP 请求 + favicon），默认不开启
	opt.TechProbe = f.doTech
	opt.TechNoFavicon = f.techNoFav
	// ⭐ 失败目标降级重试（跳过重定向 / http 回退），默认开启
	opt.TechRetryFallback = !f.noTechRetry
	// ⭐ 子域批量探测默认开启（覆盖整个攻击面）
	opt.TechSubdomains = !f.noTechSub
	if f.techMax > 0 {
		opt.TechMaxTargets = f.techMax
	}
	if f.techSubMax > 0 {
		opt.TechSubMax = f.techSubMax
	}

	// ⭐ tech 指纹缓存（覆盖"扫→复核→写报告"循环）
	if f.techCacheClear {
		if tc, err := httpprobe.NewFileTechCache(
			httpprobe.DefaultTechCachePath(), 0, true); err == nil {
			_ = tc.Clear()
			fmt.Println("已清空 tech 指纹缓存")
			return
		}
	}
	if f.techCacheStats {
		if tc, err := httpprobe.NewFileTechCache(
			httpprobe.DefaultTechCachePath(), 0, true); err == nil {
			h, _, tot := tc.Stats()
			fmt.Printf("tech 缓存: %s\n", httpprobe.DefaultTechCachePath())
			fmt.Printf("  条目数: %d\n", tc.Len())
			if tot > 0 {
				fmt.Printf("  本次命中: %d / %d (%.0f%%)\n", h, tot,
					float64(h)/float64(tot)*100)
			} else {
				fmt.Println("  本次无查询")
			}
			rows := tc.ListEntries()
			for _, r := range rows {
				fmt.Println("   ", r)
			}
		}
		return
	}
	if !f.noTechCache {
		tc, err := httpprobe.NewFileTechCache(
			httpprobe.DefaultTechCachePath(), opt.TechCacheTTL, true)
		if err == nil {
			opt.TechCache = tc
			defer func() { _ = tc.Save() }()
		} else {
			fmt.Fprintf(os.Stderr, "提示: tech 缓存不可用（%v）\n", err)
		}
	}

	// ⭐ 端口扫描结果缓存（与 tech 同思路；TTL 6 小时，filtered/error 10 分钟）
	if f.portsCacheClear {
		if pc, err := portscan.NewFilePortCache(
			portscan.DefaultPortCachePath(), 0, true); err == nil {
			_ = pc.Clear()
			fmt.Println("已清空端口扫描缓存")
			return
		}
	}
	if f.portsCacheStats {
		if pc, err := portscan.NewFilePortCache(
			portscan.DefaultPortCachePath(), 0, true); err == nil {
			h, _, tot := pc.Stats()
			fmt.Printf("端口扫描缓存: %s\n", portscan.DefaultPortCachePath())
			fmt.Printf("  条目数: %d\n", pc.Len())
			if tot > 0 {
				fmt.Printf("  本次命中: %d / %d (%.0f%%)\n", h, tot,
					float64(h)/float64(tot)*100)
			} else {
				fmt.Println("  本次无查询")
			}
			for _, r := range pc.ListEntries() {
				fmt.Println("   ", r)
			}
		}
		return
	}
	if !f.noPortsCache {
		pc, err := portscan.NewFilePortCache(
			portscan.DefaultPortCachePath(), 0, true)
		if err == nil {
			opt.PortsCache = pc
			defer func() { _ = pc.Save() }()
		} else {
			fmt.Fprintf(os.Stderr, "提示: 端口缓存不可用（%v）\n", err)
		}
	}
	// ⭐ favicon 扩展表（~/.wukan/favicon-extra.json，可选；覆盖/扩充内置表）
	//   只在开启 --tech 时相关（冲突检测的输入）
	if f.doTech {
		if n, err := httpprobe.LoadFaviconExtra(httpprobe.DefaultFaviconExtraPath()); err != nil {
			fmt.Fprintf(os.Stderr, "提示: favicon 扩展表加载失败（%v），仅用内置表\n", err)
		} else if n > 0 && !f.quiet {
			fmt.Fprintf(os.Stderr, "已加载 favicon 扩展表: %d 条\n", n)
		}
	}

	// ⭐ rDNS 反查默认开启（纯被动 DNS 查询，不向目标发包）
	opt.RDNS = !f.noRdns
	if f.rdnsMax > 0 {
		opt.RDNSMaxIP = f.rdnsMax
	}
	opt.Passive.Enabled = !f.noPassive
	if f.reverseLim > 0 {
		opt.Passive.ReverseIPLimit = f.reverseLim
	}
	if f.noPassive {
		opt.Passive.ReverseIPLimit = 0
	}
	if f.noCT {
		opt.CT.Providers = nil
	} else {
		opt.CT.VerifyDNS = !f.noVerify
	}
	opt.DoIPInfo = !f.noIPInfo
	opt.CT.IncludeParallelDomains = f.allDomains
	opt.MaxSubdomains = f.maxSubs

	// 缓存（⭐ CT 缓存是必需的：certspotter 免费层仅 100 次/小时）
	if !f.noCache {
		ipc, err := ipinfo.NewFileCache(ipinfo.DefaultCachePath(), true)
		if err == nil {
			opt.IPInfoCache = ipc
			defer func() { _ = ipc.Save() }()
		} else {
			fmt.Fprintf(os.Stderr, "提示: IP 缓存不可用（%v），本次不缓存\n", err)
		}
		ctc, err := recon.NewFileCTCache(recon.DefaultCTCachePath(), 7*24*time.Hour, true)
		if err == nil {
			opt.CT.Cache = ctc
			opt.CT.CacheTTL = 7 * 24 * time.Hour
			defer func() { _ = ctc.Save() }()
		} else {
			fmt.Fprintf(os.Stderr, "提示: CT 缓存不可用（%v），本次不缓存\n", err)
		}
	}

	if !f.quiet {
		fmt.Fprintf(os.Stderr, "[%s] recon %d 个目标 | DNS=%s\n",
			version, len(targets), resolver.Name())
	}

	// 被动 DNS 缓存（⭐ hackertarget 免费层仅 50 次/天）
	if !f.noCache && !f.noPassive {
		pc, perr := recon.NewFilePassiveCache(recon.DefaultPassiveCachePath(), 14*24*time.Hour, true)
		if perr == nil {
			opt.Passive.Cache = pc
			defer func() { _ = pc.Save() }()
		} else {
			fmt.Fprintf(os.Stderr, "提示: 被动 DNS 缓存不可用（%v）\n", perr)
		}
	}

	runner := recon.NewRunner(opt)
	if !f.noPassive {
		runner.SetPassiveCache(opt.Passive.Cache)
	}

	// 并行处理多目标
	var results []reconJob

	if f.parallel && len(targets) > 1 {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 4)
		out := make(chan reconJob, len(targets))
		for _, d := range targets {
			wg.Add(1)
			go func(dom string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cancel()
				out <- reconJob{domain: dom, rep: runner.Run(ctx, dom)}
			}(d)
		}
		wg.Wait()
		close(out)
		for j := range out {
			results = append(results, j)
		}
		// 按输入顺序
		order := map[string]int{}
		for i, t := range targets {
			order[t] = i
		}
		sort.Slice(results, func(i, j int) bool {
			return order[results[i].domain] < order[results[j].domain]
		})
	} else {
		for _, d := range targets {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			rep := runner.Run(ctx, d)
			cancel()
			results = append(results, reconJob{domain: d, rep: rep})
		}
	}

	// ⭐ 资产快照（P1-1 变化监控）：保存本次结果并与上次对比
	if f.snapshot {
		store := recon.NewSnapshotStore(recon.DefaultSnapshotDir(), recon.DefaultSnapshotKeep)
		for _, j := range results {
			if j.rep == nil {
				continue
			}
			snap := recon.BuildSnapshot(j.rep)
			prev, appended, err := store.SaveAndPrevious(snap)
			if err != nil {
				fmt.Fprintf(os.Stderr, "警告: %s 快照保存失败（%v）\n", snap.Target, err)
				continue
			}
			// ⭐ 覆盖率警告：被动数据源失败时相关差异不可比（避免用户误读 diff）
			cov := snap.Coverage
			var missing []string
			if !cov.DNS {
				missing = append(missing, "DNS")
			}
			if !cov.CT {
				missing = append(missing, "CT")
			}
			if !cov.Passive {
				missing = append(missing, "被动DNS")
			}
			if len(missing) > 0 && !f.quiet {
				fmt.Fprintf(os.Stderr, "⚠ [%s] 本次采集覆盖不完整（%s 未成功），相关差异将标记为不可比\n",
					snap.Target, strings.Join(missing, "/"))
			}
			if prev != nil {
				diff := recon.DiffSnapshots(prev, snap)
				if diff == nil {
					fmt.Fprintf(os.Stderr, "警告: [%s] 无法对比（目标不一致？）\n", snap.Target)
				} else {
					j.rep.Diff = diff
				}
				if !f.quiet {
					when := prev.TakenAt.Local().Format("2006-01-02 15:04")
					if appended {
						fmt.Fprintf(os.Stderr, "已保存快照 [%s]（对比基准：%s）\n", snap.Target, when)
					} else {
						fmt.Fprintf(os.Stderr, "快照与上次一致 [%s]，未重复保存（对比基准：%s）\n", snap.Target, when)
					}
				}
			} else if !f.quiet {
				fmt.Fprintf(os.Stderr, "已保存快照 [%s]（首次，无对比基准）\n", snap.Target)
			}
		}
	}

	if err := emitRecon(f, results); err != nil {
		fmt.Fprintf(os.Stderr, "输出失败: %v\n", err)
		os.Exit(1)
	}
}

// reconJob 是 recon 的单个结果
type reconJob struct {
	domain string
	rep    *recon.Report
	err    error
}

func emitRecon(f *reconFlags, results []reconJob) error {
	var out io.Writer = os.Stdout
	if f.output != "" {
		fh, err := os.Create(f.output)
		if err != nil {
			return err
		}
		defer fh.Close()
		out = fh
	}

	eff := f.format
	if eff == "" || eff == "table" {
		if f.output != "" {
			if inf := inferReconFormat(f.output); inf != "" {
				eff = inf
			}
		}
		if eff == "" {
			eff = "table"
		}
	}

	switch eff {
	case "json":
		if len(results) == 1 {
			return recon.WriteJSON(out, results[0].rep)
		}
		reps := make([]*recon.Report, 0, len(results))
		for _, r := range results {
			reps = append(reps, r.rep)
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(reps)
	case "hosts":
		for _, r := range results {
			recon.WriteHosts(out, r.rep)
		}
		return nil
	case "subs", "subdomains":
		for _, r := range results {
			recon.WriteSubdomains(out, r.rep, false)
		}
		return nil
	case "table", "text":
		for i, r := range results {
			if i > 0 {
				fmt.Fprintln(out)
			}
			recon.WriteText(out, r.rep, f.maxSubs)
		}
		return nil
	default:
		return fmt.Errorf("未知格式: %s（支持 table/json/hosts/subs）", eff)
	}
}

func inferReconFormat(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "json"
	case ".hosts":
		return "hosts"
	default:
		return ""
	}
}

func parseReconFlags(args []string) *reconFlags {
	f := &reconFlags{
		format:  "table",
		dns:     "alidns",
		maxSubs: 30,
		// ⭐ -1 = 未指定（用 recon 默认值；0 是合法值，表示关闭子域扫描）
		portsSubMax: -1,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-h", "--help":
			printReconUsage()
			os.Exit(0)
		case "-o", "--output":
			f.output = nextArg(args, &i, a)
		case "--format":
			f.format = nextArg(args, &i, a)
		case "--json":
			f.format = "json"
		case "--hosts":
			f.format = "hosts"
		case "--subs", "--subdomains":
			f.format = "subs"
		case "-d", "--dns":
			f.dns = nextArg(args, &i, a)
		case "-n":
			f.maxSubs = intArg(nextArg(args, &i, a), f.maxSubs)
		case "--no-rdap":
			f.noRDAP = true
		case "--no-ct":
			f.noCT = true
		case "--quic":
			f.doQuic = true
		case "--tech":
			f.doTech = true
		case "--tech-no-favicon":
			f.techNoFav = true
		case "--tech-max":
			f.techMax = intArg(nextArg(args, &i, a), 20)
		case "--tech-sub-max":
			f.techSubMax = intArg(nextArg(args, &i, a), 15)
		case "--no-tech-sub":
			f.noTechSub = true
		case "--no-tech-cache":
			f.noTechCache = true
		case "--tech-cache-stats":
			f.techCacheStats = true
		case "--tech-cache-clear":
			f.techCacheClear = true
		case "--no-tech-retry":
			f.noTechRetry = true
		case "--no-rdns":
			f.noRdns = true
		case "--rdns-max":
			f.rdnsMax = intArg(nextArg(args, &i, a), 10)
		case "--ports":
			f.scanPorts = nextArg(args, &i, a)
		case "--ports-rate":
			f.portsRate = intArg(nextArg(args, &i, a), 100)
		case "--no-banner":
			f.portsNoBan = true
		case "--ports-sub-max":
			f.portsSubMax = intArg(nextArg(args, &i, a), 10)
		case "--no-ports-cache":
			f.noPortsCache = true
		case "--ports-cache-stats":
			f.portsCacheStats = true
		case "--ports-cache-clear":
			f.portsCacheClear = true
		case "--quic-probes":
			f.quicProbes = intArg(nextArg(args, &i, a), 2)
		case "--no-passive":
			f.noPassive = true
		case "--reverse":
			f.reverseLim = intArg(nextArg(args, &i, a), 3)
		case "--no-ipinfo":
			f.noIPInfo = true
		case "--no-verify":
			f.noVerify = true
		case "-p", "--parallel":
			f.parallel = true
		case "--all-domains":
			f.allDomains = true
		case "--no-cache":
			f.noCache = true
		case "--snapshot":
			f.snapshot = true
		case "-q", "--quiet":
			f.quiet = true
		}
	}
	return f
}

func printReconUsage() {
	fmt.Fprint(os.Stderr, `wukan recon — 目标信息卡

用法:
  wukan recon <域名...>
  wukan recon example.com
  wukan recon -f domains.txt -p
  wukan recon example.com -o recon.json

采集内容（默认全部被动，不向目标发探测包）:
  · DNS        A / AAAA / CNAME / NS / MX / TXT / SOA + 泛域名检测
  · RDAP       注册商 / 注册时间 / 过期时间 / NS / DNSSEC
  · 证书透明度  certspotter（备源 crt.sh）→ 子域 + 首次/最后出现时间
  · IP 归属    对解析出的 IP 查归属并识别 CDN/云主机
  · 被动 DNS    hackertarget 历史解析 → 子域 + 历史 IP（发现"已下线"资产）
  · rDNS 反查   IP 的 PTR → 资产自己声明的身份（发现归属异常）
                 ⭐ 默认开启（纯被动 DNS 查询）
  · IP 反查     共享主机/云节点上的同源资产
  · 可行动发现  影子资产 / 历史 IP / 同源资产 / 新注册域名 / CDN 干扰…

⭐ 需 --ports 开启（主动探测）:
  · 端口扫描     对解析出的 IP 扫指定端口 → 高风险端口/管理端口暴露

⭐ 需 --tech 开启（主动探测）:
  · HTTP 指纹    5 路独立指纹交叉校验 → 检测互相矛盾的结论
                 ⭐ 默认连带探测存活子域（覆盖整个攻击面）
                 ⭐ 报告子域技术栈差异（不同子域跑着不同的栈）

⭐ 需 --quic 开启（主动探测）:
  · QUIC 探活   UDP/443 → 找出"只开放 HTTP/3"的资产（TCP 扫描器的系统性盲区）

参数:
  -o, --output <文件>   输出到文件
      --format <格式>   table（默认）/ json / hosts / subs
      --json            等价于 --format json
      --hosts           输出 hosts 格式（可直接导入）
      --subs            只输出子域列表（一行一个）
  -d, --dns <解析器>    alidns（默认）/ cloudflare / google / quad9 / 360 / dnspod
                        也可直接传 DoH URL
  -n <数量>            表格最多显示多少个子域（默认 30）
  -p, --parallel        多目标并行处理
      --no-rdns        跳过 rDNS 反查
      --rdns-max <n>   最多对多少个 IP 反查（默认 10）
      --ports <表达式> ⭐ 开启端口扫描（主动探测，默认关）
                        例: --ports 80,443 / --ports top100 / --ports web,ssh,db
      --tech           ⭐ 开启 HTTP 指纹采集 + 冲突检测（主动探测，默认关）
      --tech-max <n>    最多探测多少个目标，含子域（默认 20）
      --tech-sub-max <n> 最多探测多少个子域（默认 15）
      --no-tech-sub     只探根域，不探子域
      --no-tech-retry   失败目标不降级重试（默认开启：跳过重定向 / http 回退）
      --no-tech-cache   不用 tech 指纹缓存（强制重新探测）
      --tech-cache-stats  查看 tech 缓存统计后退出
      --tech-cache-clear  清空 tech 缓存后退出
      --tech-no-favicon 指纹采集不抓 favicon（更快）
      --ports-rate <n>  端口扫描限速（默认 100/s）
      --ports-sub-max <n> 最多对多少个存活子域批量扫端口（默认 10，0=关闭）
      --no-banner       端口扫描不抓 banner（更快）
      --no-ports-cache  不用端口扫描缓存（强制重新扫描）
      --ports-cache-stats 查看端口扫描缓存统计后退出
      --ports-cache-clear 清空端口扫描缓存后退出
      --quic           ⭐ 开启 QUIC/UDP-443 探活（主动探测，默认关）
      --quic-probes <n>  QUIC 每目标探测包数（默认 2）
      --no-rdap        跳过注册信息查询
      --no-ct          跳过证书透明度查询
      --no-passive     跳过被动 DNS 历史解析
      --no-ipinfo      跳过 IP 归属查询
      --no-verify      跳过子域的 DNS 解析验证（更快）
      --all-domains    CT 结果包含非子域条目（如 example-int.com 这类平行域）
      --snapshot       ⭐ 保存资产快照并与上次对比（变化监控；配合 wukan diff）
      --no-cache       不使用本地缓存
  -q, --quiet          不打进度信息
  -h, --help           显示本帮助

数据源（实测 2026-10-04）:
  DNS     dns.alidns.com（默认，国内实测 0.1s 最快）
  RDAP    rdap.org → 自动跳转注册局
  CT      api.certspotter.com（实测 3.1s 稳定）/ crt.sh（常 502，自动降级）
  IP      ipwho.is（主）+ ip-api.com（补 hosting/proxy 标识）

输出示例:
  # 玩具总动员 / 影子资产
  wukan recon example.com --subs > subs.txt
  wukan recon example.com -o recon.json

  # 串进下游工具
  wukan recon example.com --ips 2>/dev/null | nmap -iL - -p 80,443
`)
}

func collectDomains(args []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			return
		}
		if seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	valueIdx := map[int]bool{}
	for i, a := range args {
		for _, n := range flagsWithValue {
			if a == n && i+1 < len(args) {
				valueIdx[i+1] = true
			}
		}
	}
	for i, a := range args {
		if strings.HasPrefix(a, "-") || valueIdx[i] {
			continue
		}
		add(a)
	}

	if f := findFlagValue(args, "-f", "--file"); f != "" {
		fh, err := os.Open(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 打开文件失败: %v\n", err)
			os.Exit(1)
		}
		defer fh.Close()
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			add(strings.TrimSpace(sc.Text()))
		}
	}
	return out
}

// ── ports 子命令 ──────────────────────────────────────────

type portsFlags struct {
	portsSpec   string
	output      string
	format      string
	timeout     int
	concurrency int
	rate        int
	noBanner    bool
	tlsProbe    bool
	withRdns    bool
	showAll     bool
	quiet       bool
	noColor     bool
	// ⭐ 端口结果缓存
	noCache    bool
	cacheStats bool
	cacheClear bool
}

func runPorts(args []string) {
	f := parsePortsFlags(args)

	// ⭐ 缓存管理子操作（不需要目标即可执行）
	if f.cacheClear {
		if pc, err := portscan.NewFilePortCache(
			portscan.DefaultPortCachePath(), 0, true); err == nil {
			_ = pc.Clear()
			fmt.Println("已清空端口扫描缓存")
			return
		}
	}
	if f.cacheStats {
		if pc, err := portscan.NewFilePortCache(
			portscan.DefaultPortCachePath(), 0, true); err == nil {
			h, _, tot := pc.Stats()
			fmt.Printf("端口扫描缓存: %s\n", portscan.DefaultPortCachePath())
			fmt.Printf("  条目数: %d\n", pc.Len())
			if tot > 0 {
				fmt.Printf("  本次命中: %d / %d (%.0f%%)\n", h, tot,
					float64(h)/float64(tot)*100)
			} else {
				fmt.Println("  本次无查询")
			}
			for _, r := range pc.ListEntries() {
				fmt.Println("   ", r)
			}
		}
		return
	}

	targets := collectHosts(args)
	if len(targets) == 0 {
		printPortsUsage()
		os.Exit(2)
	}

	// ⭐ 端口解析（ParsePorts 内部会拒绝全端口与超大范围）
	spec, err := portscan.ParsePorts(f.portsSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(2)
	}
	ports := spec.Expand()

	// ⭐ 二次确认：扫描数量超过阈值时提示
	if len(ports) > 2000 {
		fmt.Fprintf(os.Stderr,
			"⚠ 将扫描 %d 个端口 × %d 个主机 = %d 次连接\n"+
				"  这需要一些时间，并可能触发目标的 IDS 告警。\n"+
				"  确认继续？Ctrl+C 取消。\n",
			len(ports), len(targets), len(ports)*len(targets))
	}

	cfg := portscan.DefaultConfig()
	cfg.Ports = ports
	cfg.Hosts = targets
	cfg.Timeout = time.Duration(f.timeout) * time.Second
	cfg.Concurrency = f.concurrency
	cfg.RateLimit = f.rate
	cfg.GrabBanner = !f.noBanner
	cfg.TLSProbe = f.tlsProbe

	// ⭐ 端口扫描结果缓存（覆盖"扫 → 复核 → 写报告"循环；--no-cache 可绕过）
	var pCache *portscan.FilePortCache
	if !f.noCache {
		pc, err := portscan.NewFilePortCache(portscan.DefaultPortCachePath(), 0, true)
		if err == nil {
			cfg.Cache = pc
			pCache = pc
			defer func() { _ = pc.Save() }()
		} else {
			fmt.Fprintf(os.Stderr, "提示: 端口缓存不可用（%v），本次不缓存\n", err)
		}
	}

	if !f.quiet {
		fmt.Fprintf(os.Stderr,
			"[%s] ⚠ 主动探测 %d 个主机 × %d 个端口 | 并发 %d | 限速 %d/s\n",
			version, len(targets), len(ports), f.concurrency, f.rate)
	}

	sc := portscan.New(cfg)
	start := time.Now()
	var lastHost string
	results := sc.ScanAll(func(host string, done, total int) {
		if f.quiet {
			return
		}
		if host != lastHost {
			lastHost = host
			fmt.Fprintf(os.Stderr, "\r  扫描中 %s … %d/%d", host, done, total)
		}
	})
	elapsed := time.Since(start)

	summary := portscan.Summarize(results)

	if err := emitPorts(f, results, summary, elapsed); err != nil {
		fmt.Fprintf(os.Stderr, "输出失败: %v\n", err)
		os.Exit(1)
	}

	// ⭐ 缓存命中提示（让用户知道有多少结果不是本次实时探测的）
	if pCache != nil && !f.quiet && f.format != "ips" && f.format != "ports" {
		if hits, _, tot := pCache.Stats(); hits > 0 && tot > 0 {
			fmt.Fprintf(os.Stderr,
				"⭐ 缓存命中 %d/%d 个端口（结果来自本地缓存，未实际连接）\n", hits, tot)
		}
	}

	if !f.quiet && f.format != "ips" && f.format != "ports" {
		portscan.WriteSummary(os.Stderr, summary, elapsed)
		portscan.PrintServiceSummary(os.Stderr, results)
	}
}

func emitPorts(f *portsFlags, results []portscan.PortResult,
	summary portscan.Summary, elapsed time.Duration) error {

	var out io.Writer = os.Stdout
	if f.output != "" {
		fh, err := os.Create(f.output)
		if err != nil {
			return err
		}
		defer fh.Close()
		out = fh
	}

	eff := f.format
	if eff == "" || eff == "table" {
		if f.output != "" {
			if inf := inferPortsFormat(f.output); inf != "" {
				eff = inf
			}
		}
		if eff == "" {
			eff = "table"
		}
	}

	switch eff {
	case "json":
		return portscan.WriteJSON(out, results, summary)
	case "csv":
		return portscan.WriteCSV(out, results)
	case "ips", "hostport":
		portscan.WriteOpenPorts(out, results)
		return nil
	case "ports":
		portscan.WriteOpenPortsOnly(out, results)
		return nil
	case "table", "text":
		portscan.WriteTable(out, results, f.showAll)
		return nil
	default:
		return fmt.Errorf("未知格式: %s（支持 table/csv/json/ips/ports）", eff)
	}
}

func inferPortsFormat(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "json"
	case ".csv":
		return "csv"
	case ".txt":
		return "ips"
	default:
		return ""
	}
}

func parsePortsFlags(args []string) *portsFlags {
	f := &portsFlags{
		portsSpec:   "top100",
		format:      "table",
		timeout:     3,
		concurrency: 64,
		rate:        200,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-h", "--help":
			printPortsUsage()
			os.Exit(0)
		case "-p", "--ports":
			f.portsSpec = nextArg(args, &i, a)
		case "-o", "--output":
			f.output = nextArg(args, &i, a)
		case "--format":
			f.format = nextArg(args, &i, a)
		case "--json":
			f.format = "json"
		case "--csv":
			f.format = "csv"
		case "--ips-only", "--ips":
			f.format = "ips"
		case "--ports-only":
			f.format = "ports"
		case "--timeout":
			f.timeout = intArg(nextArg(args, &i, a), f.timeout)
		case "-c", "--concurrency":
			f.concurrency = intArg(nextArg(args, &i, a), f.concurrency)
		case "-r", "--rate":
			f.rate = intArg(nextArg(args, &i, a), f.rate)
		case "--no-banner":
			f.noBanner = true
		case "--tls":
			f.tlsProbe = true
		case "--rdns":
			f.withRdns = true
		case "-a", "--all":
			f.showAll = true
		case "-q", "--quiet":
			f.quiet = true
		case "--no-cache":
			f.noCache = true
		case "--cache-stats":
			f.cacheStats = true
		case "--clear-cache":
			f.cacheClear = true
		}
	}
	if f.concurrency < 1 {
		f.concurrency = 1
	}
	if f.concurrency > 512 {
		f.concurrency = 512
	}
	if f.rate < 1 {
		f.rate = 1
	}
	return f
}

func printPortsUsage() {
	fmt.Fprint(os.Stderr, `wukan ports — TCP 端口扫描（⚠ 主动探测）

用法:
  wukan ports <主机...> -p <端口>
  wukan ports 127.0.0.1 -p 18080,13306
  wukan ports example.com -p top100
  wukan ports -f hosts.txt -p web,ssh,db

⭐ 这是**主动探测**，会向目标发送连接请求。
   只对你自己拥有或已获授权的资产使用。

⭐ 为什么用 TCP connect 而不是 SYN 半开扫描：
  connect 扫描必须完成三次握手才能判定端口开放。
  SYN Proxy（AWS Global Accelerator、各类 DDoS 防护）会对
  **任何** SYN 回 SYN-ACK，导致 SYN 扫描把 3306/3389/5432 等
  全部误判为开放。connect 扫描天然免疫这种误报。

  代价：① 目标侧会留下完整 established 记录，更易被 IDS 记录
        ② 超时无法区分「被丢掉的开放端口」与「不存在的端口」

端口表达式（-p）:
  80                 单个端口
  80,443,8080        逗号分隔
  1-1024             范围（单次不超过 10000 个）
  80,443,8000-8100   混合
  top100             常用 top-100
  top                全部常用端口
  web,ssh,db         按服务名（web/ssh/ftp/mail/dns/db/rdp/smb/proxy）

  ⛔ "-"（全端口）被拒绝 —— 依据《刑法》285 条 2 款，
     「非法控制计算机信息系统 20 台以上」即入刑，一次全端口
     扫描对一个 /16 就可能越线。

参数:
  -p, --ports <表达式>   端口（默认 top100）
  -o, --output <文件>    输出文件
      --format <格式>    table（默认）/ csv / json / ips / ports
      --json / --csv     快捷格式
      --ips-only         只输出 host:port（可喂给其他工具）
      --ports-only       只输出端口号
  -c, --concurrency <n>  并发（默认 64，上限 512）
  -r, --rate <n>         每秒连接上限（默认 200）
      --timeout <秒>     单端口超时（默认 3）
      --no-banner        不抓 banner（更快）
      --tls              对疑似 TLS 端口做握手（更准但更慢）
  -a, --all              显示全部端口（含 closed/filtered）
  -q, --quiet            只输出结果

⭐ 结果缓存（默认开启）:
  端口结果缓存在 ~/.wukan/ports-cache.json，TTL 6 小时；
  filtered/error 属**不确定结论**，只用 10 分钟短 TTL（防止抖动被固化）。
  缓存命中时不会发起任何连接，结果行会标注 [缓存]。
      --no-cache         不用缓存（强制重新扫描）
      --cache-stats      查看缓存统计后退出
      --clear-cache      清空缓存后退出

  -h, --help             显示本帮助

置信度:
  100  TLS 握手成功 + ALPN
   90  TLS 握手成功
   80  banner 明确识别（HTTP/SSH/MySQL…）
   70  抓到 banner 但无法归类
   60  端口开放但无 banner
   40  开放但 TLS 握手失败（存疑）

示例:
  # 本地靶场
  wukan ports 127.0.0.1 -p 18080,18443,13306

  # 常用端口，只看开放的
  wukan ports example.com -p top100

  # 串进下游工具
  wukan ports example.com -p top100 --ips-only -o open.txt
  nmap -iL open.txt -sV

  # 看全部状态分布
  wukan ports example.com -p top100 --all
`)
}

func collectHosts(args []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			return
		}
		// 去 URL 前缀与路径
		s = strings.TrimPrefix(s, "https://")
		s = strings.TrimPrefix(s, "http://")
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[:i]
		}
		// 剥掉 :port
		if i := strings.LastIndexByte(s, ':'); i > 0 {
			if _, err := strconv.Atoi(s[i+1:]); err == nil {
				s = s[:i]
			}
		}
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	valueIdx := map[int]bool{}
	for i, a := range args {
		for _, n := range flagsWithValue {
			if a == n && i+1 < len(args) {
				valueIdx[i+1] = true
			}
		}
	}
	for i, a := range args {
		if strings.HasPrefix(a, "-") || valueIdx[i] {
			continue
		}
		add(a)
	}

	if f := findFlagValue(args, "-f", "--file"); f != "" {
		fh, err := os.Open(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 打开文件失败: %v\n", err)
			os.Exit(1)
		}
		defer fh.Close()
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			add(strings.TrimSpace(sc.Text()))
		}
	}
	return out
}

// ── tech 子命令 ───────────────────────────────────────────

type techFlags struct {
	output        string
	format        string
	timeout       int
	concurrency   int
	noFollow      bool
	noFavicon     bool
	noRetry       bool
	onlyConflicts bool
	quiet         bool
}

func runTech(args []string) {
	f := parseTechFlags(args)
	urls := collectURLs(args)
	if len(urls) == 0 {
		printTechUsage()
		os.Exit(2)
	}

	// ⭐ favicon 扩展表（~/.wukan/favicon-extra.json，可选；覆盖/扩充内置表）
	if n, err := httpprobe.LoadFaviconExtra(httpprobe.DefaultFaviconExtraPath()); err != nil {
		fmt.Fprintf(os.Stderr, "提示: favicon 扩展表加载失败（%v），仅用内置表\n", err)
	} else if n > 0 && !f.quiet {
		fmt.Fprintf(os.Stderr, "已加载 favicon 扩展表: %d 条\n", n)
	}

	cfg := httpprobe.DefaultConfig()
	cfg.Timeout = time.Duration(f.timeout) * time.Second
	cfg.Concurrency = f.concurrency
	cfg.FollowRedirect = !f.noFollow
	cfg.GrabFavicon = !f.noFavicon
	// ⭐ 失败目标降级重试（跳过重定向 / http 回退），默认开启
	cfg.RetryFallback = !f.noRetry

	if !f.quiet {
		fmt.Fprintf(os.Stderr, "[%s] ⚠ 主动探测 %d 个 URL | 并发 %d | 超时 %ds\n",
			version, len(urls), cfg.Concurrency, f.timeout)
	}

	prober := httpprobe.New(cfg)
	results := prober.ProbeURLs(urls, nil)

	// ⭐ 核心：交叉校验多个独立指纹来源，检测矛盾
	reports := httpprobe.DetectAll(results)
	summary := httpprobe.Summarize(reports)

	if err := emitTech(f, results, reports, summary); err != nil {
		fmt.Fprintf(os.Stderr, "输出失败: %v\n", err)
		os.Exit(1)
	}

	if !f.quiet && f.format == "table" {
		techSummary(os.Stderr, results, reports, summary)
	}
}

func emitTech(f *techFlags, results []*httpprobe.ProbeResult,
	reports []*httpprobe.ConflictReport, summary httpprobe.Summary) error {

	var out io.Writer = os.Stdout
	if f.output != "" {
		fh, err := os.Create(f.output)
		if err != nil {
			return err
		}
		defer fh.Close()
		out = fh
	}

	eff := f.format
	if eff == "" || eff == "table" {
		if f.output != "" {
			if inf := inferTechFormat(f.output); inf != "" {
				eff = inf
			}
		}
		if eff == "" {
			eff = "table"
		}
	}

	switch eff {
	case "json":
		return writeTechJSON(out, results, reports, summary)
	case "csv":
		return writeTechCSV(out, results)
	case "table", "text":
		writeTechTable(out, results, reports, f.onlyConflicts)
		return nil
	default:
		return fmt.Errorf("未知格式: %s（支持 table/csv/json）", eff)
	}
}

func inferTechFormat(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "json"
	case ".csv":
		return "csv"
	default:
		return ""
	}
}

func writeTechTable(w io.Writer, results []*httpprobe.ProbeResult,
	reports []*httpprobe.ConflictReport, onlyConflicts bool) {

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  URL\t状态\tServer\t技术栈\t标题")
	for i, r := range results {
		if r == nil {
			continue
		}
		if onlyConflicts && (reports[i] == nil || len(reports[i].Conflicts) == 0) {
			continue
		}
		status := fmt.Sprintf("%d", r.StatusCode)
		if r.Err != "" {
			status = "ERR"
		}
		// ⭐ 降级重试必须如实标注（https 显示但数据来自 http 回退）
		u := truncateStr2(r.URL, 40)
		if l := r.RetryLabel(); l != "" {
			u += "（" + l + "）"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
			u, status,
			dashIfEmpty2(r.Server), dashIfEmpty2(strings.Join(r.BodyKeywords, "/")),
			truncateStr2(dashIfEmpty2(r.Title), 26))
	}
	tw.Flush()

	// ⭐ 冲突详情
	for i, rep := range reports {
		if rep == nil || len(rep.Conflicts) == 0 {
			continue
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  【%s】", results[i].URL)
		for _, c := range rep.Conflicts {
			icon := "🔵"
			switch c.Severity {
			case "high":
				icon = "🔴"
			case "medium":
				icon = "🟡"
			case "info":
				icon = "ℹ️"
			}
			fmt.Fprintf(w, "\n%s  %s", icon, c.Title)
			fmt.Fprintf(w, "\n     %s", c.Detail)
			for _, s := range c.Sources {
				fmt.Fprintf(w, "\n     ├ %s（可信度 %s）: %s", s.Source, s.Trust, s.Says)
			}
			if c.Implication != "" {
				fmt.Fprintf(w, "\n     └ 判读: %s", c.Implication)
			}
		}
	}
}

func writeTechJSON(w io.Writer, results []*httpprobe.ProbeResult,
	reports []*httpprobe.ConflictReport, summary httpprobe.Summary) error {
	out := struct {
		Summary   httpprobe.Summary           `json:"summary"`
		Results   []*httpprobe.ProbeResult    `json:"results"`
		Conflicts []*httpprobe.ConflictReport `json:"conflicts"`
		Scanner   string                      `json:"scanner"`
	}{
		Summary:   summary,
		Results:   results,
		Conflicts: reports,
		Scanner:   "wukan-tech/0.1.0",
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

func writeTechCSV(w io.Writer, results []*httpprobe.ProbeResult) error {
	cw := newCSVWriter(w)
	defer cw.Flush()
	if err := cw.Write([]string{
		"url", "ip", "port", "status_code", "server", "powered_by",
		"tls_version", "alpn", "cert_issuer", "title", "body_tech",
		"favicon_murmur", "favicon_len", "title_len", "rtt_ms", "error",
	}); err != nil {
		return err
	}
	for _, r := range results {
		if r == nil {
			continue
		}
		if err := cw.Write([]string{
			r.URL, r.IP, strconv.Itoa(r.Port), strconv.Itoa(r.StatusCode),
			r.Server, r.PoweredBy, r.TLSVersion, r.ALPN, r.CertIssuer,
			r.Title, strings.Join(r.BodyKeywords, "|"),
			strconv.FormatInt(r.FaviconMurmur, 10), strconv.Itoa(r.FaviconLen),
			strconv.Itoa(len(r.Title)),
			strconv.FormatFloat(float64(r.RTT.Microseconds())/1000, 'f', 2, 64),
			r.Err,
		}); err != nil {
			return err
		}
	}
	return nil
}

func techSummary(w io.Writer, results []*httpprobe.ProbeResult,
	reports []*httpprobe.ConflictReport, summary httpprobe.Summary) {
	fmt.Fprintln(w, strings_Repeat("─", 70))
	fmt.Fprintf(w, "探测 %d 个 URL | 无冲突 %d | 有冲突 %d\n",
		summary.Total, summary.Clean, summary.WithAny)

	// ⭐ 降级重试透明化：有多少结果是"首次失败、重试成功"的
	retried := 0
	for _, r := range results {
		if r != nil && r.RetriedWith != "" {
			retried++
		}
	}
	if retried > 0 {
		fmt.Fprintf(w, "  ↻ %d 个目标经降级重试成功（跳过重定向 / http 回退）\n", retried)
	}

	if len(summary.BySev) > 0 {
		parts := []string{}
		for _, sev := range []string{"high", "medium", "low", "info"} {
			if n, ok := summary.BySev[sev]; ok && n > 0 {
				icon := map[string]string{"high": "🔴", "medium": "🟡", "low": "🔵", "info": "ℹ️"}[sev]
				parts = append(parts, fmt.Sprintf("%s %s=%d", icon, sev, n))
			}
		}
		fmt.Fprintf(w, "  %s\n", strings.Join(parts, "  "))
	}
	if len(summary.ByType) > 0 {
		parts := []string{}
		for t, n := range summary.ByType {
			parts = append(parts, fmt.Sprintf("%s=%d", t, n))
		}
		sort.Strings(parts)
		fmt.Fprintf(w, "  冲突类型: %s\n", strings.Join(parts, "  "))
	}

	if summary.Clean == summary.Total && summary.Total > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "ℹ 所有目标的各路指纹相互一致，无矛盾。")
	}
}

func parseTechFlags(args []string) *techFlags {
	f := &techFlags{format: "table", timeout: 8, concurrency: 16}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-h", "--help":
			printTechUsage()
			os.Exit(0)
		case "-o", "--output":
			f.output = nextArg(args, &i, a)
		case "--format":
			f.format = nextArg(args, &i, a)
		case "--json":
			f.format = "json"
		case "--csv":
			f.format = "csv"
		case "--conflicts", "--only-conflicts":
			f.onlyConflicts = true
		case "-c", "--concurrency":
			f.concurrency = intArg(nextArg(args, &i, a), f.concurrency)
		case "--timeout":
			f.timeout = intArg(nextArg(args, &i, a), f.timeout)
		case "--no-follow":
			f.noFollow = true
		case "--no-favicon":
			f.noFavicon = true
		case "--no-retry":
			f.noRetry = true
		case "-q", "--quiet":
			f.quiet = true
		}
	}
	return f
}

func collectURLs(args []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			return
		}
		// 无 scheme 的补 http://
		if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
			s = "http://" + s
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}

	valueIdx := map[int]bool{}
	for i, a := range args {
		for _, n := range flagsWithValue {
			if a == n && i+1 < len(args) {
				valueIdx[i+1] = true
			}
		}
	}
	for i, a := range args {
		if strings.HasPrefix(a, "-") || valueIdx[i] {
			continue
		}
		add(a)
	}

	if f := findFlagValue(args, "-f", "--file"); f != "" {
		fh, err := os.Open(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 打开文件失败: %v\n", err)
			os.Exit(1)
		}
		defer fh.Close()
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			add(strings.TrimSpace(sc.Text()))
		}
	}
	return out
}

func printTechUsage() {
	fmt.Fprint(os.Stderr, `wukan tech — HTTP 指纹采集 + ⭐冲突检测

用法:
  wukan tech <URL...>
  wukan tech https://example.com
  wukan tech https://a.com https://b.com --conflicts
  wukan tech -f urls.txt -o result.json

⭐ 这是**主动探测**（会发送 HTTP 请求）。只对已授权资产使用。

⭐⭐ 本命令与 httpx 等工具的根本区别：
   现有工具只做「把多个来源的指纹拼在一起输出」，
   **没有任何工具校验这些来源之间是否自相矛盾**。

   wukan tech 采集 5 路相互独立的指纹并交叉校验：
     ① HTTP 响应头（Server / X-Powered-By / Set-Cookie / CDN 特征头）
     ② TLS 层（版本 / 加密套件 / ALPN / 证书 SAN）
     ③ favicon 哈希（MurmurHash3，与 Shodan 兼容）
     ④ 正文特征（标题 / CMS 关键词）
     ⑤ 各来源之间的一致性

   冲突本身往往指向真实问题：
     · CDN 声称存在，但 X-Powered-By 泄露了源站框架
     · 证书 SAN 不覆盖访问的主机名（配错证书或中间代理重签）
     · Server 头声称的版本与 TLS 特征矛盾（头被伪造）
     · 会话 Cookie 缺 Secure / HttpOnly
     · TLS 版本过旧

参数:
  -o, --output <文件>    输出文件（扩展名自动定格式）
      --json / --csv     输出格式
      --conflicts        只显示有冲突的目标
  -c, --concurrency <n>  并发（默认 16）
      --timeout <秒>     超时（默认 8）
      --no-follow        不跟随重定向
      --no-favicon       不抓 favicon（更快）
      --no-retry         失败目标不降级重试（默认开启：跳过重定向 / http 回退）
  -q, --quiet           只输出结果
  -h, --help            显示本帮助

favicon 哈希说明:
  按 Shodan 兼容方式计算：MurmurHash3 x86_32 + Base64
  + RFC 2045 每 76 字符换行 + 有符号 int32。
  调研报告指出中文教程普遍漏掉换行步骤，导致 hash 永远对不上 Shodan。
  本实现有 15 项标准向量交叉验证。

favicon 扩展表（可选）:
  内置表 23 条（全部实测）。可通过 ~/.wukan/favicon-extra.json
  覆盖/扩充，无需重编译：
    {"entries": [
      {"hash": 116323821, "name": "SonarQube", "category": "代码质量"}
    ]}
  hash 可写整数或整数字符串；同名 hash 外部优先；category 可省略。
  ⚠️ 数据须实测后填入 —— 填错的哈希只会静默失效，不会报错。

示例:
  wukan tech https://example.com
  wukan tech example.com --conflicts
  wukan tech -f urls.txt -o result.json
`)
}

func truncateStr2(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

func dashIfEmpty2(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func strings_Repeat(s string, n int) string {
	return strings.Repeat(s, n)
}

func newCSVWriter(w io.Writer) *csv.Writer { return csv.NewWriter(w) }

// ── diff 子命令（快照对比 / 变化监控）─────────────────────

type diffFlags struct {
	since time.Duration
	// sinceRaw 用户输入的原始时长串（错误提示里保持可读，而不是 "168h0m0s"）
	sinceRaw string
	format   string
	output   string
}

func runDiff(args []string) {
	f := parseDiffFlags(args)
	targets := collectDomains(args)
	if len(targets) == 0 {
		printDiffUsage()
		os.Exit(2)
	}

	store := recon.NewSnapshotStore(recon.DefaultSnapshotDir(), recon.DefaultSnapshotKeep)
	now := time.Now()

	var out io.Writer = os.Stdout
	if f.output != "" {
		fh, err := os.Create(f.output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "输出失败: %v\n", err)
			os.Exit(1)
		}
		defer fh.Close()
		out = fh
	}

	eff := f.format
	if eff == "" && f.output != "" && strings.EqualFold(filepath.Ext(f.output), ".json") {
		eff = "json"
	}

	var diffs []*recon.SnapshotDiff
	failed := 0
	for _, target := range targets {
		d, err := diffOne(store, target, f.since, f.sinceRaw, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: %s: %v\n", target, err)
			failed++
			continue
		}
		diffs = append(diffs, d)
	}

	if eff == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		var encErr error
		if len(diffs) == 1 {
			encErr = enc.Encode(diffs[0])
		} else {
			encErr = enc.Encode(diffs)
		}
		if encErr != nil {
			fmt.Fprintf(os.Stderr, "输出失败: %v\n", encErr)
			os.Exit(1)
		}
	} else {
		for i, d := range diffs {
			if i > 0 {
				fmt.Fprintln(out)
			}
			recon.WriteDiff(out, d)
		}
	}

	// 失败（无快照 / 文件损坏 / 目标不匹配）必须反映到退出码 —— 供监控脚本判断
	if failed > 0 {
		os.Exit(1)
	}
}

// diffOne 计算单目标的快照差异
//
// 默认对比"最近两次快照"；--since 时对比"不晚于 N 前的最新快照 → 最新"。
func diffOne(store *recon.SnapshotStore, target string, since time.Duration, sinceRaw string, now time.Time) (*recon.SnapshotDiff, error) {
	snaps, err := store.Load(target)
	if err != nil {
		return nil, err
	}
	if len(snaps) == 0 {
		return nil, fmt.Errorf("没有快照记录（先运行: wukan recon %s --snapshot）",
			recon.NormalizeTarget(target))
	}
	curr := snaps[len(snaps)-1]

	var prev *recon.Snapshot
	if since > 0 {
		prev, err = store.LatestBefore(target, now.Add(-since))
		if err != nil {
			return nil, err
		}
		if prev == nil {
			return nil, fmt.Errorf("没有早于 %s 的快照（最早快照：%s）",
				sinceRaw, snaps[0].TakenAt.Local().Format("2006-01-02 15:04"))
		}
		if prev.TakenAt.Equal(curr.TakenAt) {
			return nil, fmt.Errorf("没有更早的快照可对比（--since %s 超过了快照历史跨度）", sinceRaw)
		}
	} else {
		if len(snaps) < 2 {
			return nil, fmt.Errorf("只有一个快照（%s），无对比基准",
				curr.TakenAt.Local().Format("2006-01-02 15:04"))
		}
		prev = snaps[len(snaps)-2]
	}

	d := recon.DiffSnapshots(prev, curr)
	if d == nil {
		return nil, fmt.Errorf("快照对比失败（目标不一致？）")
	}
	return d, nil
}

func parseDiffFlags(args []string) *diffFlags {
	f := &diffFlags{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		// ⭐ 支持 --since=7d 等号写法（否则会被当作未知参数静默忽略，
		//   语义悄悄退回"最近两次"，是危险的静默行为）
		if strings.HasPrefix(a, "--since=") {
			v := strings.TrimPrefix(a, "--since=")
			d, err := recon.ParseSinceDuration(v)
			if err != nil {
				fmt.Fprintf(os.Stderr, "错误: --since %v\n", err)
				os.Exit(2)
			}
			f.since, f.sinceRaw = d, v
			continue
		}
		switch a {
		case "-h", "--help":
			printDiffUsage()
			os.Exit(0)
		case "--since":
			v := nextArg(args, &i, a)
			d, err := recon.ParseSinceDuration(v)
			if err != nil {
				fmt.Fprintf(os.Stderr, "错误: --since %v\n", err)
				os.Exit(2)
			}
			f.since, f.sinceRaw = d, v
		case "--json":
			f.format = "json"
		case "-o", "--output":
			f.output = nextArg(args, &i, a)
		}
	}
	return f
}

func printDiffUsage() {
	fmt.Fprint(os.Stderr, `wukan diff — 快照对比（变化监控）

用法:
  wukan diff <域名...>                 对比最近两次快照
  wukan diff example.com --since 7d    对比 7 天前 → 最新
  wukan diff example.com --json        输出 JSON
  wukan diff a.com b.com               多目标

⭐ 需要先有快照：recon --snapshot 会在每次运行后保存快照
   （~/.wukan/snapshots/，每目标保留最近 30 个）。

对比内容:
  · 子域 新增/消失          · 解析 IP 新增/消失
  · 端口 新增开放/不再开放/服务变化
  · HTTP 指纹 状态码 / Server / favicon / 标题变化

  每条变化都带判读（这意味着什么、该做什么）。

参数:
      --since <时长>   对比基准的时间跨度（如 7d / 24h / 90m；默认"最近两次"）
      --json          输出 JSON
  -o, --output <文件>  输出到文件（.json 扩展名自动用 JSON）
  -h, --help           显示本帮助

示例:
  # 每日监控：跑 recon 存快照，之后随时看变化
  wukan recon example.com --snapshot
  wukan diff example.com
  wukan diff example.com --since 7d
`)
}
