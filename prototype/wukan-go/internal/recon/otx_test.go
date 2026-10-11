package recon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ⭐ OTX 时间线解析：格式容错（带/不带时区）+ 去重 + 排序 + 跳过空值
func TestOTX_PassiveDNSParse(t *testing.T) {
	t.Setenv(EnvOTXKey, "test-key")
	body := `{
	  "passive_dns": [
	    {"hostname": "WWW.Example.com", "address": "5.6.7.8", "first": "2020-01-02T03:04:05", "last": "2021-01-01T00:00:00"},
	    {"hostname": "example.com", "address": "1.2.3.4", "first": "2015-06-01T00:00:00Z", "last": "2020-01-02T00:00:00Z"},
	    {"hostname": "example.com", "address": "1.2.3.4", "first": "2015-06-01T00:00:00Z", "last": "2020-01-02T00:00:00Z"},
	    {"hostname": "", "address": "9.9.9.9", "first": "", "last": ""},
	    {"hostname": "example.com", "address": "", "first": "", "last": ""}
	  ]
	}`
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-OTX-API-KEY")
		if !strings.Contains(r.URL.Path, "/api/v1/indicators/domain/example.com/passive_dns") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := NewOTX(3 * time.Second)
	c.baseURL = srv.URL
	entries, err := c.PassiveDNS(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	// ⭐ key 必须出现在请求头里
	if gotHeader != "test-key" {
		t.Errorf("请求应携带 X-OTX-API-KEY 头，实际 %q", gotHeader)
	}
	if len(entries) != 2 {
		t.Fatalf("应解析 2 条（去重、跳过空值），实际 %d：%+v", len(entries), entries)
	}
	// 排序：hostname 字典序 → example.com 在前
	if entries[0].Hostname != "example.com" || entries[0].IP != "1.2.3.4" {
		t.Errorf("第一条应为 example.com/1.2.3.4，实际 %+v", entries[0])
	}
	if entries[0].FirstSeen.Year() != 2015 {
		t.Errorf("RFC3339 时间应解析成功，实际 %v", entries[0].FirstSeen)
	}
	// 无时区格式 "2020-01-02T03:04:05" 也要能解析
	if entries[1].FirstSeen.Year() != 2020 || entries[1].LastSeen.Year() != 2021 {
		t.Errorf("无时区时间应解析成功，实际 %+v", entries[1])
	}
	// 主机名应归一化小写
	if entries[1].Hostname != "www.example.com" {
		t.Errorf("主机名应小写，实际 %q", entries[1].Hostname)
	}
}

// ⭐ 未配置 key → 快速失败 + 可行动提示（不浪费请求）
func TestOTX_NoKeyFailsFast(t *testing.T) {
	t.Setenv(EnvOTXKey, "")
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()
	c := NewOTX(2 * time.Second)
	c.baseURL = srv.URL
	_, err := c.PassiveDNS(context.Background(), "x.com")
	if err == nil || !strings.Contains(err.Error(), EnvOTXKey) {
		t.Errorf("无 key 时应报含 %q 的提示，实际 %v", EnvOTXKey, err)
	}
	if called {
		t.Error("无 key 时不应发出请求")
	}
}

// ⭐ key 无效时 OTX 返回 200 + 提示体 —— 必须识别，不能静默当成"无历史"
func TestOTX_AnonymousBodyDetected(t *testing.T) {
	t.Setenv(EnvOTXKey, "bad-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"detail": "Anonymous access to this endpoint is limited. Please authenticate."}`))
	}))
	defer srv.Close()
	c := NewOTX(2 * time.Second)
	c.baseURL = srv.URL
	_, err := c.PassiveDNS(context.Background(), "x.com")
	if err == nil || !strings.Contains(err.Error(), "key") {
		t.Errorf("提示体应被识别为认证失败，实际 %v", err)
	}
}

// 429 / 5xx / 坏 JSON → 明确错误（不静默）
func TestOTX_Errors(t *testing.T) {
	t.Setenv(EnvOTXKey, "test-key")
	cases := []struct {
		code    int
		body    string
		wantSub string
	}{
		{http.StatusTooManyRequests, "", "限流"},
		{http.StatusInternalServerError, "", "返回 500"},
		{http.StatusOK, "not json", "解析失败"},
	}
	for _, cse := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(cse.code)
			_, _ = w.Write([]byte(cse.body))
		}))
		c := NewOTX(2 * time.Second)
		c.baseURL = srv.URL
		_, err := c.PassiveDNS(context.Background(), "x.com")
		if err == nil || !strings.Contains(err.Error(), cse.wantSub) {
			t.Errorf("code=%d 应报含 %q 的错误，实际 %v", cse.code, cse.wantSub, err)
		}
		srv.Close()
	}
}

// ⭐ 时间线缓存：roundtrip + 与 Records 互不污染 + 旧格式兼容
func TestPassiveCache_Timeline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	c, _ := NewFilePassiveCache(path, 14*24*time.Hour, false)

	entries := []PDNSTimelineEntry{
		{Hostname: "example.com", IP: "1.2.3.4", FirstSeen: time.Now().Add(-100 * 24 * time.Hour)},
	}
	c.PutTimeline("timeline:example.com", entries)
	c.PutPassive("hostsearch:example.com", map[string][]string{"a.example.com": {"1.2.3.4"}})
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}

	c2, _ := NewFilePassiveCache(path, 14*24*time.Hour, true)
	got, ok := c2.GetTimeline("timeline:example.com")
	if !ok || len(got) != 1 || got[0].IP != "1.2.3.4" {
		t.Errorf("时间线应能读回，实际 ok=%v %+v", ok, got)
	}
	// 时间线条目不能被 GetPassive 命中（Records 为空）
	if _, ok := c2.GetPassive("timeline:example.com"); ok {
		t.Error("时间线条目不应被 GetPassive 命中")
	}
	// Records 应完好
	if recs, ok := c2.GetPassive("hostsearch:example.com"); !ok || len(recs) != 1 {
		t.Error("Records 缓存应完好")
	}
	// 未知键 → false
	if _, ok := c2.GetTimeline("timeline:not-exist.com"); ok {
		t.Error("未知键不应命中")
	}
}

// ⭐ 旧格式缓存文件（无 timeline 字段）必须能加载（向后兼容）
func TestPassiveCache_OldFormatCompat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.json")
	// cached_at 用近期时间（否则会被 TTL 判过期，测不到 schema 兼容性）
	old := `{"hostsearch:example.com":{"records":{"a.example.com":["1.2.3.4"]},"cached_at":` +
		fmt.Sprintf("%d", time.Now().Add(-time.Hour).Unix()) + `}}`
	if err := os.WriteFile(path, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := NewFilePassiveCache(path, 14*24*time.Hour, true)
	if err != nil {
		t.Fatalf("旧格式应能加载: %v", err)
	}
	if recs, ok := c.GetPassive("hostsearch:example.com"); !ok || len(recs) != 1 {
		t.Error("旧格式的 Records 应可用")
	}
}
