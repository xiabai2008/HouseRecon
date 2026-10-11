package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wukan/wukan/internal/httpprobe"
)

// ⭐ 种子解析：注释/空行/两列/三列/URL 形式
func TestParseSeeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seeds.txt")
	content := "# 注释行\n\n" +
		"Grafana | grafana.com | 运维监控\n" +
		"SonarQube | https://sonarsource.com/favicon.ico | 代码质量\n" +
		"Redis | redis.io\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	seeds, err := parseSeeds(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(seeds) != 3 {
		t.Fatalf("应解析 3 条，实际 %d", len(seeds))
	}
	// 域名 → 补 /favicon.ico
	if seeds[0].Name != "Grafana" || seeds[0].URL != "https://grafana.com/favicon.ico" ||
		seeds[0].Category != "运维监控" {
		t.Errorf("域名形式解析错误：%+v", seeds[0])
	}
	// 完整 URL 原样保留
	if seeds[1].URL != "https://sonarsource.com/favicon.ico" {
		t.Errorf("URL 形式应原样保留：%+v", seeds[1])
	}
	// 两列（无类别）
	if seeds[2].Category != "" || seeds[2].URL != "https://redis.io/favicon.ico" {
		t.Errorf("两列形式解析错误：%+v", seeds[2])
	}

	// 坏行 → 报错（不能静默跳过）
	bad := filepath.Join(dir, "bad.txt")
	_ = os.WriteFile(bad, []byte("只有名字没有来源\n"), 0o644)
	if _, err := parseSeeds(bad); err == nil {
		t.Error("格式错误的行应报错")
	}
}

// ⭐ 下载 + 哈希计算：与 ShodanFaviconHash 一致 + md5 正确
func TestCollectOne(t *testing.T) {
	iconBytes := []byte("fake-favicon-bytes-\x00\x01\x02-1234567890")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/favicon.ico" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write(iconBytes)
	}))
	defer srv.Close()

	s := seed{Name: "TestApp", Source: srv.URL, URL: srv.URL + "/favicon.ico", Category: "测试"}
	client := &http.Client{Timeout: 5 * time.Second}
	r, err := collectOne(client, s, "2026-10-12")
	if err != nil {
		t.Fatal(err)
	}
	if r.Hash != httpprobe.ShodanFaviconHash(iconBytes) {
		t.Errorf("哈希应与 ShodanFaviconHash 一致：%d vs %d",
			r.Hash, httpprobe.ShodanFaviconHash(iconBytes))
	}
	sum := md5.Sum(iconBytes)
	if r.MD5 != hex.EncodeToString(sum[:]) {
		t.Errorf("md5 错误：%s", r.MD5)
	}
	if r.Size != len(iconBytes) {
		t.Errorf("size 错误：%d", r.Size)
	}
	if r.Source == "" || r.Fetched != "2026-10-12" {
		t.Errorf("溯源字段缺失：%+v", r)
	}
}

// 404 / 空内容 → 明确错误（不产出垃圾条目）
func TestCollectOne_Failures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/empty.ico":
			_, _ = w.Write(nil)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	if _, err := collectOne(client, seed{Name: "x", URL: srv.URL + "/nope.ico"}, "d"); err == nil {
		t.Error("404 应报错")
	}
	if _, err := collectOne(client, seed{Name: "x", URL: srv.URL + "/empty.ico"}, "d"); err == nil {
		t.Error("空内容应报错")
	}
}

// ⭐⭐ 输出必须能被 wukan 的扩展表加载器（P0-2）直接吃下
func TestOutputLoadableByWukan(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "favicon-extra.json")
	ef := extraFile{Entries: []extraEntry{
		{Hash: 20261012, Name: "FaviconCollectTest", Category: "测试"},
	}}
	b, _ := json.MarshalIndent(ef, "", "  ")
	if err := os.WriteFile(outPath, b, 0o644); err != nil {
		t.Fatal(err)
	}

	// 清空外部表并在测试后还原
	t.Cleanup(func() { _, _ = httpprobe.LoadFaviconExtra(filepath.Join(dir, "none.json")) })
	n, err := httpprobe.LoadFaviconExtra(outPath)
	if err != nil {
		t.Fatalf("wukan 扩展表加载器应能读取本工具输出: %v", err)
	}
	if n != 1 {
		t.Errorf("应加载 1 条，实际 %d", n)
	}
	if got := (&httpprobe.ProbeResult{FaviconMurmur: 20261012}).FaviconProduct(); got != "FaviconCollectTest" {
		t.Errorf("外部条目应生效，实际 %q", got)
	}
}

// 种子文件语法检查：真实 seeds.txt 必须全部合法（防止提交坏种子）
func TestRealSeedsFileValid(t *testing.T) {
	seeds, err := parseSeeds("seeds.txt")
	if err != nil {
		t.Fatalf("seeds.txt 应全部合法: %v", err)
	}
	if len(seeds) < 40 {
		t.Errorf("seeds.txt 条目过少（%d）—— 应覆盖内置复测 + 新增长尾", len(seeds))
	}
	// 内置复测的 23 条必须都在（用于验证工具链）
	known := []string{"Grafana", "Jenkins", "GitHub", "GitLab", "Gitea", "Apache",
		"Cloudflare", "DEV Community", "Docker", "MongoDB", "Mozilla", "Node.js",
		"PHP", "Packagist", "PostgreSQL", "PyPI", "Python", "React", "Redis",
		"RubyGems", "Traefik", "WordPress", "nginx"}
	names := map[string]bool{}
	for _, s := range seeds {
		names[s.Name] = true
	}
	for _, k := range known {
		if !names[k] {
			t.Errorf("seeds.txt 缺少内置复测条目: %s", k)
		}
	}
	// URL 形式必须合法
	for _, s := range seeds {
		if !strings.HasPrefix(s.URL, "https://") {
			t.Errorf("%s 的 URL 异常: %s", s.Name, s.URL)
		}
	}
}
