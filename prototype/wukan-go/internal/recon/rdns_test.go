package recon

import (
	"strings"
	"testing"

	"github.com/wukan/wukan/internal/ipinfo"
)

// helper 快速构造 Report
func mkRep(target string, rdns ...*ipinfo.RDNSResult) *Report {
	return &Report{Target: target, RDNS: rdns}
}

// ⭐⭐ 核心：PTR 指向本域 → 正常，不报归属异常
func TestRDNSFinding_OwnDomainNoAlarm(t *testing.T) {
	rep := mkRep("example.com",
		&ipinfo.RDNSResult{
			IP:        "1.2.3.4",
			Hostnames: []string{"static.cdn.example.com", "www.example.com"},
			HasPTR:    true,
		})
	findings := Analyze(rep)
	for _, f := range findings {
		if f.Type == "rdns_identity_mismatch" {
			t.Errorf("⭐ PTR 指向本域子域不应报归属异常：%s", f.Title)
		}
	}
}

// ⭐⭐ 核心：PTR 指向**别人的域** → 必须报高危归属异常
//
// 这是 rDNS 在 recon 里独有的发现：其他来源都发现不了。
// 正向 DNS 只能告诉你「域名指到哪」，rDNS 告诉你「IP 的主人自称是谁」
// —— 两者矛盾就是资产被转售/挪用的直接证据。
func TestRDNSFinding_ForeignDomainAlarm(t *testing.T) {
	rep := mkRep("example.com",
		&ipinfo.RDNSResult{
			IP:        "1.2.3.4",
			Hostnames: []string{"cdn.someone-else.com"},
			HasPTR:    true,
		})
	findings := Analyze(rep)
	found := false
	for _, f := range findings {
		if f.Type == "rdns_identity_mismatch" {
			found = true
			if f.Level != "high" {
				t.Errorf("归属异常应为 high 级别，实际 %q", f.Level)
			}
			// ⭐ 必须给出可行动的判读（Detail 末段）
			if f.Detail == "" {
				t.Error("⭐ 必须给出判读（用户要知道该做什么）")
			}
			if len(f.Evidence) == 0 {
				t.Error("必须给出证据（具体哪个 IP 指向了哪个域）")
			}
		}
	}
	if !found {
		t.Error("⭐ PTR 指向外部域名必须报 rdns_identity_mismatch")
	}
}

// ⭐ 根域自身也算属于本域
func TestRDNSFinding_RootDomainIsOwn(t *testing.T) {
	rep := mkRep("example.com",
		&ipinfo.RDNSResult{
			IP:        "1.2.3.4",
			Hostnames: []string{"example.com"},
			HasPTR:    true,
		})
	for _, f := range Analyze(rep) {
		if f.Type == "rdns_identity_mismatch" {
			t.Errorf("根域 PTR 不应报异常：%s", f.Title)
		}
	}
}

// ⭐ 泛用主机名**不该**触发归属异常
//
// ecs-1-2-3-4.compute.hwclouds-dns.com 是云厂商的默认 PTR，
// 它是**所有**华为云主机的共同形态，不指向任何具体域。
// 若拿它跟目标域比较，会对所有云主机疯狂误报。
func TestRDNSFinding_GenericNoAlarm(t *testing.T) {
	rep := mkRep("example.com",
		&ipinfo.RDNSResult{
			IP:        "1.2.3.4",
			Hostnames: []string{"ecs-1-2-3-4.compute.hwclouds-dns.com"},
			HasPTR:    true,
		})
	for _, f := range Analyze(rep) {
		if f.Type == "rdns_identity_mismatch" {
			t.Errorf("⭐ 泛用云主机名不应触发归属异常（会对所有云主机误报）：%s", f.Title)
		}
	}
}

// ⭐ 大小写不敏感：PTR 返回 GITHUB.COM 也应认作本域
func TestRDNSFinding_CaseInsensitive(t *testing.T) {
	rep := mkRep("github.com",
		&ipinfo.RDNSResult{
			IP:        "140.82.113.4",
			Hostnames: []string{"GITHUB.COM", "Api.GitHub.com"},
			HasPTR:    true,
		})
	for _, f := range Analyze(rep) {
		if f.Type == "rdns_identity_mismatch" {
			t.Errorf("大小写差异不应被当成外部域名：%s", f.Title)
		}
	}
}

// ⭐ 无 PTR 是常态，应给「无法确认归属」的提示而不是异常告警
func TestRDNSFinding_NoPTRIsInfo(t *testing.T) {
	rep := mkRep("example.com",
		&ipinfo.RDNSResult{IP: "1.2.3.4", HasPTR: false, Err: ""},
		&ipinfo.RDNSResult{IP: "5.6.7.8", HasPTR: false, Err: ""},
	)
	findings := Analyze(rep)
	hasNone := false
	for _, f := range findings {
		if f.Type == "rdns_none" {
			hasNone = true
			if f.Level == "high" || f.Level == "medium" {
				t.Errorf("⭐ 无 PTR 是常态（实测 1/3 公网 IP 无 PTR），不应报中高危：%q", f.Level)
			}
		}
	}
	if !hasNone {
		t.Error("全部无 PTR 时应提示「无法通过 rDNS 确认归属」")
	}
}

// ⭐ 混合情况：有 PTR 的报身份信息，无 PTR 的不报
func TestRDNSFinding_Mixed(t *testing.T) {
	rep := mkRep("example.com",
		&ipinfo.RDNSResult{
			IP:        "1.2.3.4",
			Hostnames: []string{"static.cdn.example.com"},
			HasPTR:    true,
		},
		&ipinfo.RDNSResult{IP: "5.6.7.8", HasPTR: false},
	)
	types := map[string]bool{}
	for _, f := range Analyze(rep) {
		types[f.Type] = true
	}
	if !types["rdns_identity"] {
		t.Error("有 PTR 时应报 rdns_identity")
	}
	if types["rdns_none"] {
		t.Error("⭐ 部分有 PTR 时不应报「全部无 PTR」")
	}
	if types["rdns_identity_mismatch"] {
		t.Error("本域子域不应触发归属异常")
	}
}

// ⭐ rDNS 与 reverseiplookup 语义不同，不能互相替代
//
// rDNS         → IP 持有者**自己声明**的身份（权威 DNS，无配额）
// reverseiplookup → 第三方数据库里**实际托管**的所有域名（50次/天配额）
func TestRDNSVsReverseIP_SemanticsDiffer(t *testing.T) {
	// rDNS 指向别人的域 → 归属异常
	rep := mkRep("example.com",
		&ipinfo.RDNSResult{
			IP:        "1.2.3.4",
			Hostnames: []string{"other-tenant.net"},
			HasPTR:    true,
		})
	foundMismatch := false
	for _, f := range Analyze(rep) {
		if f.Type == "rdns_identity_mismatch" {
			foundMismatch = true
		}
	}
	if !foundMismatch {
		t.Error("rDNS 的归属判定应独立于 reverseiplookup 生效")
	}

	// reverseiplookup 的 shared_infra 与 rDNS 的 mismatch 是两件事
	r := &ipinfo.RDNSResult{
		IP:        "1.2.3.4",
		Hostnames: []string{"other-tenant.net"},
		HasPTR:    true,
	}
	if c := r.Classify(); len(c.Specific) != 1 {
		t.Errorf("other-tenant.net 应被判为具体域名，实际 %+v", c)
	}
	if !strings.Contains(r.Hostnames[0], "other-tenant") {
		t.Error("Hostnames 保留原始值")
	}
}
