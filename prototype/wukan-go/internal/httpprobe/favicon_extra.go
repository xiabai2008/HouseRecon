package httpprobe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
)

// ⭐⭐ favicon 扩展表（外部加载）
//
// 动机：内置表 23 条是实测产物，但**每次扩充都要改代码 + 重编译**。
// 本机制允许通过 ~/.wukan/favicon-extra.json 覆盖/扩充内置表：
//
//	{
//	  "entries": [
//	    {"hash": 116323821, "name": "SonarQube", "category": "代码质量"},
//	    {"hash": "-1261306053", "name": "某产品", "category": "自定义"}
//	  ]
//	}
//
// ⭐ 规则：
//  1. hash 可写整数或整数字符串（有些工具导出的 JSON 把大整数写成字符串）
//  2. 同一 hash 与内置表冲突时，**外部条目优先** —— 便于用户修正内置误判
//  3. category 可省略；省略时用 categoryOf(name) 推断，推断不出则为空
//  4. name 为空、hash 为 0 的条目视为**错误**（宁可报错，不可静默失效）
//
// ⭐⚠️ 与内置表同样的两条纪律（内置表的教训，外部表同样适用）：
//
//	① 数据必须**实测**后填入。填错的哈希不会崩溃，只会静默失效
//	   （永远匹配不上，没有任何报错）—— 这是最难发现的一类 bug。
//	② favicon 命中只是**线索**，不是结论。图标只有几百字节，
//	   不同应用共用同一图标必然碰撞（实测 grafana.com 与 grafana.net
//	   图标 md5 完全相同）。
//
// 兼容性说明：外部条目与内置条目走**同一套**冲突判定
// （favicon_vs_server 的互斥判定基于产品名，见 faviconCompatibleWith），
// 行为一致；未收录的陌生产品名默认判定为兼容（不引入假阳性）。

// FaviconExtraEntry 扩展表条目
type FaviconExtraEntry struct {
	Hash     jsonInt64 `json:"hash"`
	Name     string    `json:"name"`
	Category string    `json:"category,omitempty"`
}

// jsonInt64 兼容"数字"与"字符串"两种 JSON 写法
type jsonInt64 int64

func (n *jsonInt64) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	s = strings.Trim(s, `"`)
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("hash 需为整数（或整数字符串），无法解析 %s", string(b))
	}
	*n = jsonInt64(v)
	return nil
}

// faviconExtraFile 扩展表文件结构
type faviconExtraFile struct {
	Entries []FaviconExtraEntry `json:"entries"`
}

// faviconExtra 外部条目（nil = 未加载或为空）
//
// ⭐ 用 atomic.Pointer 而非普通全局变量：探测阶段有多个 goroutine
//
//	并发查表（ProductInfo 等），而加载发生在此之前；atomic 保证
//	无论时序如何都没有数据竞争，也便于测试随时替换。
var faviconExtra atomic.Pointer[map[int64]faviconProduct]

// DefaultFaviconExtraPath 返回默认扩展表路径
func DefaultFaviconExtraPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "wukan-favicon-extra.json"
	}
	return filepath.Join(home, ".wukan", "favicon-extra.json")
}

// LoadFaviconExtra 加载外部 favicon 扩展表，返回加载的条目数。
//
// 语义：
//   - 文件不存在 → 清空外部表（以文件为准），返回 (0, nil) —— 不算错误
//   - 解析/校验失败 → 返回错误，且**不修改**当前已加载的表
//     （避免一个坏文件把上一次的好数据清掉）
//   - 成功 → 替换外部表（外部条目在查表时优先于内置表）
func LoadFaviconExtra(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			faviconExtra.Store(nil)
			return 0, nil
		}
		return 0, err
	}
	var f faviconExtraFile
	// ⭐ 容忍 UTF-8 BOM：Windows 记事本等处保存的 UTF-8 文件会带 BOM，
	//   而 Go 的 json.Unmarshal 不认 BOM —— 不剥掉会直接报
	//   "invalid character 'ï'" 这种难以理解错误。
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	if err := json.Unmarshal(b, &f); err != nil {
		return 0, fmt.Errorf("%s: JSON 解析失败: %w", path, err)
	}
	m := make(map[int64]faviconProduct, len(f.Entries))
	for i, e := range f.Entries {
		name := strings.TrimSpace(e.Name)
		if name == "" {
			return 0, fmt.Errorf("%s: 第 %d 条条目 name 为空", path, i+1)
		}
		hash := int64(e.Hash)
		if hash == 0 {
			return 0, fmt.Errorf(
				"%s: 第 %d 条条目（%s）hash 为 0（0 表示无 favicon，不能作为条目键）",
				path, i+1, name)
		}
		cat := strings.TrimSpace(e.Category)
		if cat == "" {
			cat = categoryOf(name)
		}
		m[hash] = faviconProduct{name: name, cat: cat}
	}
	faviconExtra.Store(&m)
	return len(m), nil
}

// lookupFaviconProduct 查表：**外部优先，内置兜底**
//
// 外部优先的理由：内置表是实测产物但难免有误判/碰撞，
// 用户通过外部表修正时应以用户的为准（覆盖语义）。
func lookupFaviconProduct(hash int64) (faviconProduct, bool) {
	if m := faviconExtra.Load(); m != nil {
		if fp, ok := (*m)[hash]; ok {
			return fp, true
		}
	}
	fp, ok := faviconHashTable[hash]
	return fp, ok
}
