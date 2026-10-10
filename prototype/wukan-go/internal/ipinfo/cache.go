package ipinfo

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CacheTTL 默认缓存有效期。
//
// ⭐ 为什么是 7 天：
//   - IP 归属（国家/城市/ISP/ASN）是**基础设施级信息**，变更极罕见
//   - 一次缓存能覆盖渗透测试的"扫 → 复核 → 写报告"完整循环
//   - 30 天太长：IP 可能被回收转卖，归属会变
const CacheTTL = 7 * 24 * time.Hour

// FileCache 是基于 JSON 文件的缓存实现。
//
// 设计要点：
//   - 单文件、人类可读、便于手工检查与清理
//   - 内存索引 + 追加写盘（写盘去重，避免文件无限膨胀）
//   - 进程内并发安全
type FileCache struct {
	path string

	mu    sync.RWMutex
	items map[string]*cacheEntry
	dirty bool
}

type cacheEntry struct {
	Info     *Info `json:"info"`
	CachedAt int64 `json:"cached_at"` // Unix 秒
}

// NewFileCache 创建文件缓存。load 为 true 时尝试载入已有缓存。
func NewFileCache(path string, load bool) (*FileCache, error) {
	c := &FileCache{
		path:  path,
		items: make(map[string]*cacheEntry),
	}
	if load {
		if err := c.load(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// DefaultCachePath 返回默认缓存路径：~/.wukan/ipinfo-cache.json
func DefaultCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "wukan-ipinfo-cache.json"
	}
	return filepath.Join(home, ".wukan", "ipinfo-cache.json")
}

func (c *FileCache) load() error {
	f, err := os.Open(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 首次运行，无缓存，正常
		}
		return err
	}
	defer f.Close()

	// 逐行解析，容忍末行截断（进程被杀时可能写一半）
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	loaded, skipped := 0, 0

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var e cacheEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			skipped++
			continue
		}
		if e.Info == nil || e.Info.IP == "" {
			skipped++
			continue
		}
		age := time.Since(time.Unix(e.CachedAt, 0))
		if age > CacheTTL {
			continue // 过期
		}
		c.items[e.Info.IP] = &e
		loaded++
	}
	_ = skipped
	return nil
}

func (c *FileCache) save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	// 先写临时文件再改名，避免中途崩溃留下半截文件
	tmp := c.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)

	c.mu.RLock()
	for _, e := range c.items {
		if age := time.Since(time.Unix(e.CachedAt, 0)); age > CacheTTL {
			continue
		}
		_ = enc.Encode(e)
	}
	c.mu.RUnlock()

	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, c.path)
}

// Get 查询缓存
func (c *FileCache) Get(ip string) (*Info, bool) {
	c.mu.RLock()
	e, ok := c.items[ip]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Since(time.Unix(e.CachedAt, 0)) > CacheTTL {
		return nil, false
	}
	return e.Info, true
}

// Put 写入缓存
func (c *FileCache) Put(ip string, info *Info) {
	c.mu.Lock()
	c.items[ip] = &cacheEntry{
		Info:     info,
		CachedAt: time.Now().Unix(),
	}
	c.dirty = true
	c.mu.Unlock()
}

// Len 缓存条目数
func (c *FileCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// Save 落盘（去重重写，不会无限膨胀）
func (c *FileCache) Save() error { return c.save() }

// Stats 缓存统计
func (c *FileCache) Stats() (total int, valid int, withFlags int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, e := range c.items {
		total++
		if e.Info.Valid {
			valid++
		}
		if len(e.Info.Flags) > 0 {
			withFlags++
		}
	}
	return
}

// Clear 清空缓存
func (c *FileCache) Clear() error {
	c.mu.Lock()
	c.items = make(map[string]*cacheEntry)
	c.mu.Unlock()
	return os.Remove(c.path)
}

// String 实现，供调试
func (c *FileCache) String() string {
	total, valid, flagged := c.Stats()
	return fmt.Sprintf("FileCache{%s} 共 %d 条（有效 %d，带标签 %d）",
		c.path, total, valid, flagged)
}
