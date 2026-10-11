// favicon-collect — favicon 哈希表规模化采集工具（P2-3）
//
// 用途：批量下载产品的 favicon → 计算 Shodan 兼容哈希 → 生成
// **~/.wukan/favicon-extra.json 兼容**的扩展表 + 供人工核对的溯源清单。
//
// ⭐ 为什么必须人工核对（项目的血泪教训）：
//
//	填错的哈希不会崩溃，只会让识别**静默失效**（永远匹配不上，没有报错）。
//	本工具负责"下载 + 计算 + 记录来源（URL/md5/日期）"，但**内容正确性
//	必须人工核对**（对比产品官网图标、检查 md5）后才能投入使用。
//
// 用法：
//
//	go run ./cmd/favicon-collect -f seeds.txt -o favicon-extra.json
//	go run ./cmd/favicon-collect -f seeds.txt --check          # 只核对已有表
//
// seeds.txt 格式（每行，`#` 开头为注释）：
//
//	产品名 | 域名或URL | 类别（可选）
//	SonarQube | sonarsource.com | 代码质量
//	Grafana   | https://grafana.com/favicon.ico | 运维监控
package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/wukan/wukan/internal/httpprobe"
)

const maxFaviconSize = 512 * 1024

type seed struct {
	Name     string
	Source   string // 原始输入（域名或 URL）
	URL      string // 实际请求的 URL
	Category string
}

type result struct {
	Name     string `json:"name"`
	Category string `json:"category,omitempty"`
	Hash     int64  `json:"hash"`
	MD5      string `json:"md5"`
	Size     int    `json:"size"`
	Source   string `json:"source"`
	Fetched  string `json:"fetched"`
}

// extraFile favicon-extra.json 的输出结构（与 P0-2 加载格式一致）
type extraFile struct {
	Entries []extraEntry `json:"entries"`
}

type extraEntry struct {
	Hash     int64  `json:"hash"`
	Name     string `json:"name"`
	Category string `json:"category,omitempty"`
}

func main() {
	seedFile := flag.String("f", "", "种子文件（产品名 | 域名或URL | 类别）")
	outFile := flag.String("o", "favicon-extra.json", "输出扩展表路径")
	timeout := flag.Int("timeout", 15, "单个下载超时（秒）")
	force := flag.Bool("force", false, "存在失败条目时仍写正式输出（默认写 .partial.json，防止不完整的表覆盖已核对的表）")
	flag.Parse()

	if *seedFile == "" {
		fmt.Fprintln(os.Stderr, "用法: favicon-collect -f seeds.txt -o favicon-extra.json")
		os.Exit(2)
	}
	seeds, err := parseSeeds(*seedFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取种子失败: %v\n", err)
		os.Exit(1)
	}
	if len(seeds) == 0 {
		fmt.Fprintln(os.Stderr, "种子文件为空")
		os.Exit(1)
	}

	client := &http.Client{Timeout: time.Duration(*timeout) * time.Second}
	now := time.Now().Format("2006-01-02")
	var results []result
	var failed []string
	seenHash := map[int64]string{} // hash → name（碰撞检测）

	fmt.Fprintf(os.Stderr, "采集 %d 个产品的 favicon…\n", len(seeds))
	for _, s := range seeds {
		r, err := collectOne(client, s, now)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s (%s): %v", s.Name, s.URL, err))
			fmt.Fprintf(os.Stderr, "  ✗ %-24s %v\n", s.Name, err)
			continue
		}
		// ⭐ 哈希碰撞：默认**不写入**（保留第一个）—— 让"人工取舍"真正发生，
		//   而不是两条都进文件后由加载器静默二选一
		if prev, ok := seenHash[r.Hash]; ok {
			fmt.Fprintf(os.Stderr, "  ⚠ %-24s 哈希与 %s 相同（%d）—— 图标碰撞，已跳过（保留 %s）\n",
				r.Name, prev, r.Hash, prev)
			continue
		}
		seenHash[r.Hash] = r.Name
		results = append(results, *r)
		fmt.Fprintf(os.Stderr, "  ✓ %-24s hash=%-12d md5=%s size=%d\n",
			r.Name, r.Hash, r.MD5[:8], r.Size)
	}

	// 输出扩展表（P0-2 兼容格式）
	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	ef := extraFile{}
	for _, r := range results {
		ef.Entries = append(ef.Entries, extraEntry{Hash: r.Hash, Name: r.Name, Category: r.Category})
	}
	b, err := json.MarshalIndent(ef, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "序列化失败: %v\n", err)
		os.Exit(1)
	}
	// ⭐ M4 修复：
	//   ① 有失败条目时默认写 .partial.json（不完整的表不能静默覆盖已核对的表）
	//   ② 原子写（tmp + rename），中断不会留半截文件
	outPath := *outFile
	if len(failed) > 0 && !*force {
		outPath = strings.TrimSuffix(*outFile, ".json") + ".partial.json"
	}
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写入失败: %v\n", err)
		os.Exit(1)
	}
	if err := os.Rename(tmp, outPath); err != nil {
		fmt.Fprintf(os.Stderr, "写入失败: %v\n", err)
		os.Exit(1)
	}
	if outPath != *outFile {
		fmt.Fprintf(os.Stderr, "⚠ 存在 %d 个失败条目，输出写到 %s（加 --force 可强制写 %s）\n",
			len(failed), outPath, *outFile)
	}

	// 溯源清单（供人工核对：来源 URL + md5 + 日期）
	fmt.Printf("\n===== 人工核对清单（务必核对后再启用）=====\n")
	fmt.Printf("输出: %s（%d 条）\n\n", outPath, len(ef.Entries))
	fmt.Printf("%-24s %-14s %-34s %-10s %s\n", "产品", "hash", "md5", "size", "来源")
	for _, r := range results {
		fmt.Printf("%-24s %-14d %-34s %-10d %s\n", r.Name, r.Hash, r.MD5, r.Size, r.Source)
	}
	if len(failed) > 0 {
		fmt.Printf("\n失败 %d 个：\n", len(failed))
		for _, f := range failed {
			fmt.Printf("  ✗ %s\n", f)
		}
	}
	fmt.Printf("\n⭐ 下一步：\n")
	fmt.Printf("  1. 人工核对上表（对照产品官网图标 / md5 / 来源 URL）\n")
	fmt.Printf("  2. 核对无误后复制到 ~/.wukan/favicon-extra.json 即生效（无需重编译）\n")
}

// parseSeeds 解析种子文件（产品名 | 域名或URL | 类别）
func parseSeeds(path string) ([]seed, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []seed
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("行格式错误（需要 产品名 | 域名或URL [| 类别]）: %q", line)
		}
		s := seed{Name: parts[0], Source: parts[1]}
		if len(parts) > 2 {
			s.Category = parts[2]
		}
		// 域名 → /favicon.ico；完整 URL 原样
		if strings.HasPrefix(s.Source, "http://") || strings.HasPrefix(s.Source, "https://") {
			s.URL = s.Source
		} else {
			s.URL = "https://" + strings.TrimSuffix(s.Source, "/") + "/favicon.ico"
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

// collectOne 下载单个 favicon 并计算哈希/md5
func collectOne(client *http.Client, s seed, fetched string) (*result, error) {
	req, err := http.NewRequest(http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "+
			"(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("返回 %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFaviconSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("空内容")
	}
	if len(data) > maxFaviconSize {
		return nil, fmt.Errorf("超过 %dKB 上限（可能不是图标）", maxFaviconSize/1024)
	}
	sum := md5.Sum(data)
	return &result{
		Name:     s.Name,
		Category: s.Category,
		Hash:     httpprobe.ShodanFaviconHash(data),
		MD5:      hex.EncodeToString(sum[:]),
		Size:     len(data),
		Source:   s.URL,
		Fetched:  fetched,
	}, nil
}
