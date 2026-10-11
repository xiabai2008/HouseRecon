package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// EnvOTXKey 环境变量名：OTX API key（免费注册后获取）
//
// ⭐ 实测（2026-10-11）：OTX 的 passive_dns 已限制匿名访问
//
//	（"Anonymous access to this endpoint is limited. Please authenticate."），
//	必须携带 key 才能查询。免费注册即可获得 key。
const EnvOTXKey = "WUKAN_OTX_KEY"

// OTXClient AlienVault OTX 被动 DNS 客户端（带时间戳的历史解析）
//
// ⭐ 为什么需要它（P2-1）：
//
//	hackertarget 只给"当前快照"，看不出"**何时迁移、迁移到哪**"。
//	OTX 的 passive_dns 接口每条记录带 first/last 时间戳 ——
//	这正是把"快照"升级成"时间线"所需的最小数据源。
//
// ⚠️ 需要 API key（环境变量 WUKAN_OTX_KEY，免费注册）。
//
//	未配置 key 时**快速失败**并给出可行动的提示（不浪费一次请求）。
type OTXClient struct {
	client  *http.Client
	baseURL string
	apiKey  string
}

// NewOTX 创建 OTX 客户端（自动读取 WUKAN_OTX_KEY）
func NewOTX(timeout time.Duration) *OTXClient {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &OTXClient{
		client:  &http.Client{Timeout: timeout},
		baseURL: "https://otx.alienvault.com",
		apiKey:  strings.TrimSpace(os.Getenv(EnvOTXKey)),
	}
}

// HasKey 是否配置了 API key
func (c *OTXClient) HasKey() bool { return c.apiKey != "" }

// otxResponse OTX passive_dns 响应结构
type otxResponse struct {
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
		Address  string `json:"address"`
		First    string `json:"first"`
		Last     string `json:"last"`
	} `json:"passive_dns"`
}

// PassiveDNS 查询域名的历史解析时间线
func (c *OTXClient) PassiveDNS(ctx context.Context, domain string) ([]PDNSTimelineEntry, error) {
	// ⭐ 未配置 key 快速失败：OTX 已限制匿名访问，直接请求只会拿到
	//   一条晦涩的提示，不如明确告诉用户怎么解决。
	if c.apiKey == "" {
		return nil, fmt.Errorf("需要 API key（OTX 已限制匿名访问）：设置环境变量 %s（免费注册）", EnvOTXKey)
	}
	url := fmt.Sprintf("%s/api/v1/indicators/domain/%s/passive_dns",
		c.baseURL, domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wukan-recon/0.1 (+asset-recon)")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-OTX-API-KEY", c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("限流（OTX）")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("返回 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	// ⭐ key 无效时 OTX 仍返回 200 + 提示体，必须识别出来（否则会被
	//   当成"该域没有历史记录"静默吞掉）
	if strings.Contains(string(body), "Anonymous access") ||
		strings.Contains(string(body), "Please authenticate") {
		return nil, fmt.Errorf("key 无效或未生效（OTX 要求认证）：检查 %s", EnvOTXKey)
	}
	var out otxResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("解析失败: %w", err)
	}

	var entries []PDNSTimelineEntry
	seen := map[string]bool{}
	for _, r := range out.PassiveDNS {
		host := strings.ToLower(strings.TrimSpace(r.Hostname))
		ip := strings.TrimSpace(r.Address)
		if host == "" || ip == "" {
			continue
		}
		key := host + "|" + ip
		if seen[key] {
			continue
		}
		seen[key] = true
		entries = append(entries, PDNSTimelineEntry{
			Hostname:  host,
			IP:        ip,
			FirstSeen: parseOTXTime(r.First),
			LastSeen:  parseOTXTime(r.Last),
			Source:    "otx",
		})
	}
	// 稳定排序：主机名 → 首次出现（渲染与 diff 友好）
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Hostname != entries[j].Hostname {
			return entries[i].Hostname < entries[j].Hostname
		}
		if !entries[i].FirstSeen.Equal(entries[j].FirstSeen) {
			return entries[i].FirstSeen.Before(entries[j].FirstSeen)
		}
		return entries[i].IP < entries[j].IP
	})
	return entries, nil
}

// parseOTXTime OTX 时间格式容错（可能带/不带时区）
func parseOTXTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
