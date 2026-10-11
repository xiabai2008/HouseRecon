package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestHT 创建指向本地测试服务器的 hackertarget 客户端
func newTestHT(t *testing.T, handler http.HandlerFunc) *HackerTargetClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := NewHackerTarget(3 * time.Second)
	c.baseURL = srv.URL
	return c
}

const htQuotaBody = "API count exceeded - Increase your API limits https://hackertarget.com/api/"

// ⭐ key 从环境变量读取，且要裁掉前后空白
func TestHackerTarget_EnvKey(t *testing.T) {
	t.Setenv(EnvHackerTargetKey, "  sekret-key  ")
	c := NewHackerTarget(time.Second)
	if !c.HasKey() {
		t.Error("设置环境变量后 HasKey 应为 true")
	}
	if c.apiKey != "sekret-key" {
		t.Errorf("key 前后空白应被裁掉，实际 %q", c.apiKey)
	}

	t.Setenv(EnvHackerTargetKey, "")
	if NewHackerTarget(time.Second).HasKey() {
		t.Error("空值不应视为已配置 key")
	}
}

// ⭐⭐ key 必须真的出现在请求里（服务端断言收到 apikey 参数）
func TestHackerTarget_KeySentInRequest(t *testing.T) {
	t.Setenv(EnvHackerTargetKey, "sekret")
	var gotQuery string
	c := newTestHT(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("sub.example.com,1.2.3.4\nwww.example.com,5.6.7.8\n"))
	})

	recs, err := c.HostSearch(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "apikey=sekret") {
		t.Errorf("请求应携带 apikey 参数，实际 query=%q", gotQuery)
	}
	if !strings.Contains(gotQuery, "q=example.com") {
		t.Errorf("请求应携带 q 参数，实际 query=%q", gotQuery)
	}
	if len(recs) != 2 {
		t.Errorf("应解析出 2 个主机，实际 %d", len(recs))
	}
}

// 未配置 key 时不带 apikey 参数（行为与旧版完全一致）
func TestHackerTarget_NoKeyNoParam(t *testing.T) {
	t.Setenv(EnvHackerTargetKey, "")
	var gotQuery string
	c := newTestHT(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("a.example.com,1.2.3.4\n"))
	})
	if _, err := c.HostSearch(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gotQuery, "apikey") {
		t.Errorf("未配置 key 不应携带 apikey 参数，实际 query=%q", gotQuery)
	}
}

// ⭐⭐ 配额耗尽的提示必须"可行动"：
//
//	没 key → 告诉用户设置哪个环境变量；
//	有 key → 提示检查 key/套餐（而不是重复说"限流了"）。
func TestHackerTarget_QuotaMessage(t *testing.T) {
	ctx := context.Background()

	// 无 key
	t.Setenv(EnvHackerTargetKey, "")
	c := newTestHT(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(htQuotaBody))
	})
	_, err := c.HostSearch(ctx, "x.com")
	if err == nil {
		t.Fatal("配额耗尽应报错")
	}
	if !strings.Contains(err.Error(), EnvHackerTargetKey) {
		t.Errorf("无 key 时错误信息应提示设置 %s，实际: %v", EnvHackerTargetKey, err)
	}

	// 有 key（服务端仍返回配额消息 → 提示应改为"检查 key"）
	t.Setenv(EnvHackerTargetKey, "k123")
	c2 := newTestHT(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(htQuotaBody))
	})
	_, err2 := c2.HostSearch(ctx, "x.com")
	if err2 == nil {
		t.Fatal("配额耗尽应报错")
	}
	if !strings.Contains(err2.Error(), "检查 key") {
		t.Errorf("有 key 时错误信息应提示检查 key，实际: %v", err2)
	}
}

// ⭐⭐ DNSLookup / ReverseIPLookup 遇到配额耗尽必须显式报错 ——
//
// 此前只查 "error" 字样（配额消息不含该词），会静默返回空结果，
// 表现为"该域没有 DNS 记录"，污染交叉验证结论。
func TestHackerTarget_QuotaNotSilent(t *testing.T) {
	t.Setenv(EnvHackerTargetKey, "")
	ctx := context.Background()

	c := newTestHT(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(htQuotaBody))
	})
	if _, err := c.DNSLookup(ctx, "x.com"); err == nil {
		t.Error("dnslookup 配额耗尽应报错，不能静默返回空结果")
	}
	if _, err := c.ReverseIPLookup(ctx, "1.2.3.4"); err == nil {
		t.Error("reverseiplookup 配额耗尽应报错，不能静默返回空结果")
	}
}

// HTTP 429 也要给可行动提示
func TestHackerTarget_429Hint(t *testing.T) {
	t.Setenv(EnvHackerTargetKey, "")
	c := newTestHT(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err := c.HostSearch(context.Background(), "x.com")
	if err == nil {
		t.Fatal("429 应报错")
	}
	if !strings.Contains(err.Error(), EnvHackerTargetKey) {
		t.Errorf("429 错误信息应提示设置环境变量，实际: %v", err)
	}
}

// apiURL：q 正常转义、key 特殊字符转义、无 key 无参数
func TestHackerTarget_APIURL(t *testing.T) {
	t.Setenv(EnvHackerTargetKey, "k ey&x")
	c := NewHackerTarget(time.Second)
	u := c.apiURL("hostsearch", "example.com")
	if !strings.Contains(u, "q=example.com") {
		t.Errorf("普通域名不应被过度转义，实际 %q", u)
	}
	if !strings.Contains(u, "apikey=k+ey%26x") {
		t.Errorf("key 中的特殊字符应被转义，实际 %q", u)
	}

	t.Setenv(EnvHackerTargetKey, "")
	c2 := NewHackerTarget(time.Second)
	if strings.Contains(c2.apiURL("dnslookup", "a.com"), "apikey") {
		t.Error("无 key 时不应有 apikey 参数")
	}
}

// 正常成功路径不受 key 逻辑影响（回归）
func TestHackerTarget_DNSLookupSuccess(t *testing.T) {
	t.Setenv(EnvHackerTargetKey, "sekret")
	var gotQuery string
	c := newTestHT(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("A: 1.2.3.4\nNS: ns1.example.com\n"))
	})
	recs, err := c.DNSLookup(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs["A"]) != 1 || recs["A"][0] != "1.2.3.4" {
		t.Errorf("A 记录解析错误: %+v", recs)
	}
	if !strings.Contains(gotQuery, "apikey=sekret") {
		t.Errorf("dnslookup 也应携带 key，实际 query=%q", gotQuery)
	}
}
