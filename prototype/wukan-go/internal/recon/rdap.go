package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DomainInfo 域名注册信息（来自 RDAP）
type DomainInfo struct {
	Domain string `json:"domain"`
	// Registrar 注册商
	Registrar string `json:"registrar,omitempty"`
	// RegistrarIANAID 注册商 IANA ID
	RegistrarIANAID string `json:"registrar_iana_id,omitempty"`
	// Status 域名状态（client transfer prohibited 等）
	Status []string `json:"status,omitempty"`
	// Events 关键事件（registration / expiration / last changed）
	Events map[string]string `json:"events,omitempty"`
	// Nameservers NS 列表
	Nameservers []string `json:"nameservers,omitempty"`
	// SecureDNS 是否启用 DNSSEC
	SecureDNS bool `json:"secure_dns,omitempty"`
	// Registrant/Admin/Tech 联系人（RDAP 常常脱敏为红acted）
	Registrant string `json:"registrant,omitempty"`
	// Source 数据来源
	Source string `json:"source,omitempty"`
	// Err 错误
	Err string `json:"error,omitempty"`
}

// Age 域名年龄
func (d *DomainInfo) Age() (time.Duration, bool) {
	if d == nil || d.Events == nil {
		return 0, false
	}
	s, ok := d.Events["registration"]
	if !ok {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, false
	}
	return time.Since(t), true
}

// ExpiresIn 距过期时间
func (d *DomainInfo) ExpiresIn() (time.Duration, bool) {
	if d == nil || d.Events == nil {
		return 0, false
	}
	s, ok := d.Events["expiration"]
	if !ok {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, false
	}
	return time.Until(t), true
}

// IsExpiringSoon 域名是否即将过期（默认 90 天）
func (d *DomainInfo) IsExpiringSoon(within time.Duration) bool {
	dur, ok := d.ExpiresIn()
	return ok && dur < within
}

// IsNew 域名是否很新（默认 180 天）—— 新注册域名在攻击中更常见
func (d *DomainInfo) IsNew(within time.Duration) bool {
	age, ok := d.Age()
	return ok && age < within
}

// lockedStatus 是注册局锁（禁止转移）状态
func (d *DomainInfo) lockedStatus() string {
	for _, s := range d.Status {
		if strings.Contains(s, "transfer prohibited") ||
			strings.Contains(s, "delete prohibited") {
			return "🔒 " + s
		}
	}
	return ""
}

// ── RDAP 查询 ─────────────────────────────────────────────

// RDAPClient 是 RDAP 域名注册信息客户端
type RDAPClient struct {
	client    *http.Client
	bootstrap string
}

// NewRDAPClient 创建客户端
func NewRDAPClient(timeout time.Duration) *RDAPClient {
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	return &RDAPClient{
		client: &http.Client{Timeout: timeout},
		// rdap.org 会按 TLD 自动跳转到对应注册局的 RDAP 服务
		bootstrap: "https://rdap.org/domain/",
	}
}

// rdapResponse 是 RDAP 域名的最小字段集（RFC 9083）
type rdapResponse struct {
	LDHName string   `json:"ldhName"`
	Handle  string   `json:"handle"`
	Status  []string `json:"status"`
	Events  []struct {
		EventAction string `json:"eventAction"`
		EventDate   string `json:"eventDate"`
	} `json:"events"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	Entities []struct {
		Roles     []string `json:"roles"`
		PublicIDs []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"publicIds"`
		VCardArray any `json:"vcardArray"`
	} `json:"entities"`
	SecureDNS *struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS"`
	Notices []struct {
		Title string `json:"title"`
	} `json:"notices"`
}

// Lookup 查询域名注册信息
func (c *RDAPClient) Lookup(ctx context.Context, domain string) (*DomainInfo, error) {
	url := c.bootstrap + strings.ToLower(domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "wukan-recon/0.1")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RDAP 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &DomainInfo{Domain: domain, Source: "rdap.org",
			Err: "域名未注册或 RDAP 无记录"}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RDAP 返回 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var r rdapResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("解析 RDAP 响应失败: %w", err)
	}

	info := &DomainInfo{
		Domain:      domain,
		Status:      r.Status,
		Nameservers: make([]string, 0, len(r.Nameservers)),
		Events:      map[string]string{},
		Source:      "rdap.org",
	}
	if info.Domain == "" {
		info.Domain = strings.ToLower(r.LDHName)
	}
	for _, ns := range r.Nameservers {
		if ns.LDHName != "" {
			info.Nameservers = append(info.Nameservers, strings.ToLower(ns.LDHName))
		}
	}
	for _, e := range r.Events {
		if e.EventDate != "" {
			info.Events[e.EventAction] = e.EventDate
		}
	}
	if r.SecureDNS != nil {
		info.SecureDNS = r.SecureDNS.DelegationSigned
	}

	// 从 entities 提取注册商 IANA ID 与联系人
	for _, ent := range r.Entities {
		var ianaID string
		for _, pid := range ent.PublicIDs {
			if strings.EqualFold(pid.Type, "IANA Registrar ID") {
				ianaID = pid.Value
			}
		}
		isRegistrar := false
		for _, role := range ent.Roles {
			if role == "registrar" {
				isRegistrar = true
			}
		}
		if isRegistrar && ianaID != "" && info.RegistrarIANAID == "" {
			info.RegistrarIANAID = ianaID
			// 从 notices 里找注册商名，或用 IANA ID 兜底
			info.Registrar = "IANA#" + ianaID
		}
		for _, role := range ent.Roles {
			if role == "registrant" {
				// vCard 通常被注册局脱敏为 "REDACTED FOR PRIVACY"
				info.Registrant = extractVCardName(ent.VCardArray)
			}
		}
	}

	sort.Strings(info.Nameservers)
	return info, nil
}

// extractVCardName 从 vcardArray 中提取姓名
//
// ⭐ 绝大多数注册局会脱敏，返回 "REDACTED FOR PRIVACY" 之类。
// 这种情况应如实报告，不能编造。
func extractVCardName(vc any) string {
	arr, ok := vc.([]any)
	if !ok || len(arr) < 2 {
		return ""
	}
	props, ok := arr[1].([]any)
	if !ok {
		return ""
	}
	var parts []string
	for _, p := range props {
		pm, ok := p.([]any)
		if !ok || len(pm) < 4 {
			continue
		}
		name, _ := pm[0].(string)
		val, _ := pm[3].(string)
		switch name {
		case "fn":
			// fn 是完整名字，优先
			if val != "" {
				return val
			}
		case "org":
			if val != "" {
				return val
			}
		}
	}
	return strings.Join(parts, " ")
}

// RDAPOptions RDAP 查询选项
type RDAPOptions struct {
	Timeout time.Duration
	Enabled bool
}

// LookupDomain 查询域名注册信息（带容错）
func LookupDomain(ctx context.Context, domain string, opt RDAPOptions) *DomainInfo {
	if !opt.Enabled {
		return &DomainInfo{Domain: domain, Source: "disabled", Err: "已跳过（-no-rdap）"}
	}
	c := NewRDAPClient(opt.Timeout)
	info, err := c.Lookup(ctx, domain)
	if err != nil {
		return &DomainInfo{Domain: domain, Source: "rdap.org", Err: err.Error()}
	}
	return info
}
