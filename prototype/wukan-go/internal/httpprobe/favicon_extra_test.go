package httpprobe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetFaviconExtra 每个测试结束后清空外部表，避免污染其他测试
func resetFaviconExtra(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { faviconExtra.Store(nil) })
}

func writeFaviconExtra(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "favicon-extra.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ⭐ 扩充 + 覆盖：外部表能新增条目，也能覆盖内置条目（外部优先）
func TestLoadFaviconExtra_ExtendAndOverride(t *testing.T) {
	resetFaviconExtra(t)
	path := writeFaviconExtra(t, `{
	  "entries": [
	    {"hash": 20261010, "name": "SonarQube", "category": "代码质量"},
	    {"hash": "20261011", "name": "字符串哈希产品"},
	    {"hash": 1928290, "name": "Jenkins 改", "category": ""}
	  ]
	}`)

	n, err := LoadFaviconExtra(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("应加载 3 条，实际 %d", n)
	}

	// 扩充：新 hash 命中
	p := &ProbeResult{FaviconMurmur: 20261010}
	name, cat, ok := p.ProductInfo()
	if !ok || name != "SonarQube" || cat != "代码质量" {
		t.Errorf("外部新条目应命中：name=%q cat=%q ok=%v", name, cat, ok)
	}

	// ⭐ hash 写字符串也必须能解析
	if got := (&ProbeResult{FaviconMurmur: 20261011}).FaviconProduct(); got != "字符串哈希产品" {
		t.Errorf("字符串形式的 hash 应能解析，实际 %q", got)
	}

	// ⭐ 覆盖：内置 Jenkins(1928290) 被外部改名（外部优先）
	if got := (&ProbeResult{FaviconMurmur: 1928290}).FaviconProduct(); got != "Jenkins 改" {
		t.Errorf("外部条目应覆盖内置条目，实际 %q", got)
	}
	// category 省略且推断不出 → 空串（而不是报错）
	if _, cat, ok := (&ProbeResult{FaviconMurmur: 1928290}).ProductInfo(); !ok || cat != "" {
		t.Errorf("未提供 category 且无法推断时应为空串，实际 %q ok=%v", cat, ok)
	}

	// 内置未受影响的条目仍正常
	if name, cat, ok := (&ProbeResult{FaviconMurmur: 2111119328}).ProductInfo(); !ok ||
		name != "Redis" || cat != "数据库" {
		t.Errorf("未覆盖的内置条目应不受影响：name=%q cat=%q ok=%v", name, cat, ok)
	}
}

// ⭐ 文件不存在 = 清空外部表（以文件为准），保留内置表
func TestLoadFaviconExtra_MissingFileClears(t *testing.T) {
	resetFaviconExtra(t)
	path := writeFaviconExtra(t, `{"entries": [{"hash": 1928290, "name": "临时改名"}]}`)
	if _, err := LoadFaviconExtra(path); err != nil {
		t.Fatal(err)
	}
	if got := (&ProbeResult{FaviconMurmur: 1928290}).FaviconProduct(); got != "临时改名" {
		t.Fatalf("前置条件失败：%q", got)
	}

	// 加载一个不存在的路径 → 不算错误，外部表被清空
	missing := filepath.Join(t.TempDir(), "not-exist.json")
	n, err := LoadFaviconExtra(missing)
	if err != nil {
		t.Fatalf("文件不存在不应报错: %v", err)
	}
	if n != 0 {
		t.Errorf("文件不存在应返回 0 条，实际 %d", n)
	}
	// 覆盖消失 → 回落到内置
	if got := (&ProbeResult{FaviconMurmur: 1928290}).FaviconProduct(); got != "Jenkins" {
		t.Errorf("清空后应回落到内置表 Jenkins，实际 %q", got)
	}
}

// ⭐ 坏文件不能把已加载的好数据清掉（变更前后表保持一致）
func TestLoadFaviconExtra_InvalidJSONKeepsOld(t *testing.T) {
	resetFaviconExtra(t)
	good := writeFaviconExtra(t, `{"entries": [{"hash": 20261010, "name": "旧数据"}]}`)
	if _, err := LoadFaviconExtra(good); err != nil {
		t.Fatal(err)
	}

	bad := writeFaviconExtra(t, `{ this is not json`)
	if _, err := LoadFaviconExtra(bad); err == nil {
		t.Fatal("坏 JSON 应返回错误")
	}
	if got := (&ProbeResult{FaviconMurmur: 20261010}).FaviconProduct(); got != "旧数据" {
		t.Errorf("加载失败后应保留旧表，实际 %q", got)
	}
}

// ⭐ 空 name / hash=0 视为错误 —— 填错的条目不能静默失效
func TestLoadFaviconExtra_RejectsBadEntries(t *testing.T) {
	resetFaviconExtra(t)

	// 空 name
	p1 := writeFaviconExtra(t, `{"entries": [{"hash": 20261010, "name": "  "}]}`)
	if _, err := LoadFaviconExtra(p1); err == nil {
		t.Error("空 name 的条目应报错（不能静默失效）")
	} else if !strings.Contains(err.Error(), "第 1 条") {
		t.Errorf("错误信息应指明条目序号，实际: %v", err)
	}

	// hash = 0（漏写 hash 字段的典型表现）
	p2 := writeFaviconExtra(t, `{"entries": [{"name": "没有哈希"}]}`)
	if _, err := LoadFaviconExtra(p2); err == nil {
		t.Error("hash=0 的条目应报错")
	}

	// 坏条目不能让上一次的外部表被清掉
	good := writeFaviconExtra(t, `{"entries": [{"hash": 20261010, "name": "好数据"}]}`)
	if _, err := LoadFaviconExtra(good); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFaviconExtra(p2); err == nil {
		t.Fatal("前置条件失败")
	}
	if got := (&ProbeResult{FaviconMurmur: 20261010}).FaviconProduct(); got != "好数据" {
		t.Errorf("校验失败后应保留旧表，实际 %q", got)
	}
}

// ⭐ 外部条目必须与内置条目走同一套冲突判定（favicon_vs_server）
//
// 用外部哈希映射到 "Redis"，Server 头是 IIS → 应报冲突，
// 证明外部条目不是"只显示不校验"。
func TestLoadFaviconExtra_ConflictDetection(t *testing.T) {
	resetFaviconExtra(t)
	path := writeFaviconExtra(t, `{
	  "entries": [
	    {"hash": 333333333, "name": "Redis", "category": "数据库"}
	  ]
	}`)
	if _, err := LoadFaviconExtra(path); err != nil {
		t.Fatal(err)
	}

	p := &ProbeResult{
		URL:             "https://x.example.com",
		FaviconMurmur:   333333333, // 外部条目 → Redis
		Server:          "Microsoft-IIS/10.0",
		CFHeaders:       map[string]string{},
		CDNHeaders:      map[string]string{},
		SecurityHdrs:    map[string]string{},
		CertSANs:        []string{"*.example.com"},
		CertMatchesHost: true,
	}
	rep := DetectConflicts(p)
	found := false
	for _, c := range rep.Conflicts {
		if c.Type == ConflictFaviconVsServer {
			found = true
		}
	}
	if !found {
		t.Error("外部条目（Redis）与 Server=IIS 应报 favicon_vs_server 冲突")
	}

	// 指纹面板也应记录外部条目（含类别）
	if got := rep.Fingerprints["favicon-product"]; got != "Redis（数据库）" {
		t.Errorf("指纹面板应记录外部条目与类别，实际 %q", got)
	}
}

// ⭐ 容忍 UTF-8 BOM（Windows 记事本保存的 UTF-8 会带 BOM）
func TestLoadFaviconExtra_ToleratesBOM(t *testing.T) {
	resetFaviconExtra(t)
	p := filepath.Join(t.TempDir(), "favicon-extra.json")
	content := "\xef\xbb\xbf" + `{"entries": [{"hash": 20261010, "name": "带BOM"}]}`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := LoadFaviconExtra(p)
	if err != nil {
		t.Fatalf("带 BOM 的文件应能加载: %v", err)
	}
	if n != 1 {
		t.Fatalf("应加载 1 条，实际 %d", n)
	}
	if got := (&ProbeResult{FaviconMurmur: 20261010}).FaviconProduct(); got != "带BOM" {
		t.Errorf("BOM 文件内容应生效，实际 %q", got)
	}
}

// ⭐ 默认路径必须落在 ~/.wukan/ 下（与其它缓存一致）
func TestDefaultFaviconExtraPath(t *testing.T) {
	got := DefaultFaviconExtraPath()
	if !strings.Contains(got, ".wukan") || !strings.Contains(got, "favicon-extra.json") {
		t.Errorf("默认路径应在 ~/.wukan/ 下，实际 %q", got)
	}
}

// 兼容性回归：无外部表时，内置行为必须与之前完全一致
func TestLookupFaviconProduct_BuiltinFallback(t *testing.T) {
	resetFaviconExtra(t)
	// 未加载外部表 → 全部走内置
	if got := (&ProbeResult{FaviconMurmur: 1928290}).FaviconProduct(); got != "Jenkins" {
		t.Errorf("无外部表时应命中内置 Jenkins，实际 %q", got)
	}
	// 查不到的 hash
	if _, ok := lookupFaviconProduct(999999999); ok {
		t.Error("未知 hash 不应命中")
	}
	// hash=0 的特判
	if got := (&ProbeResult{FaviconMurmur: 0}).FaviconProduct(); got != "" {
		t.Errorf("hash=0 应返回空串，实际 %q", got)
	}
}
