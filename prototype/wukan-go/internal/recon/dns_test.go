package recon

import (
	"errors"
	"testing"
)

// ⭐ 良性"无记录"（doh.go 返回中文）必须被识别 ——
// E2E 实测发现：只匹配英文模式会让正常域名的 DNS.Err 变脏
// （报告出现"⚠ CNAME: 无记录"噪音，快照覆盖率也被误判为"未覆盖"）
func TestIsNoRecord(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{errors.New("无记录"), true},
		{errors.New("no answer"), true},
		{errors.New("no records"), true},
		{errors.New("no such record"), true},
		{errors.New("NXDOMAIN: example.com 不存在"), false},
		{errors.New("查询超时"), false},
		{nil, false},
	}
	for _, c := range cases {
		if got := isNoRecord(c.err); got != c.want {
			t.Errorf("isNoRecord(%v) = %v，期望 %v", c.err, got, c.want)
		}
	}
}

// ⭐ DNS 硬失败判定（快照覆盖率用）：良性段不算失败，未知段按失败处理（保守）
func TestDNSHardFailed(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"CNAME: 无记录", false},
		{"MX: 系统解析器不支持 MX 类型查询（请用 -dns alidns 走 DoH）", false},
		{"NXDOMAIN", true},
		{"A: dial tcp: i/o timeout", true},
		{"CNAME: 无记录; MX: i/o timeout", true},
		{"未知错误", true},
	}
	for _, c := range cases {
		if got := dnsHardFailed(c.in); got != c.want {
			t.Errorf("dnsHardFailed(%q) = %v，期望 %v", c.in, got, c.want)
		}
	}
}

// 冒烟：NXDOMAIN 判定不受本次修改影响
func TestIsNXDomain_StillWorks(t *testing.T) {
	for _, s := range []string{"NXDOMAIN: x 不存在", "no such host", "does not exist"} {
		if !isNXDomain(errors.New(s)) {
			t.Errorf("isNXDomain(%q) 应为 true", s)
		}
	}
	if isNXDomain(errors.New("无记录")) {
		t.Error("'无记录' 不是 NXDOMAIN")
	}
}
