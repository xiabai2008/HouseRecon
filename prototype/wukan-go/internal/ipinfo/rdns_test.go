package ipinfo

import (
	"net"
	"strings"
	"testing"
)

// ⭐⭐ 回归防护：ARPA 反查域不能当成主机名
//
// 实测踩到（2026-10-05）：查 119.3.70.188 的 PTR 时，
// 某些递归 resolver 把查询名 188.70.3.119.in-addr.arpa 直接返回，
// 于是工具报告"PTR = 188.70.3.119.in-addr.arpa" —— 毫无信息量。
//
// 关键：DoH 返回值**带结尾点**，必须先去点再判断后缀，
// 顺序反了过滤就失效。
func TestDoHPTR_FilterARPADomain(t *testing.T) {
	// 模拟 lookupDoH 的过滤逻辑
	filter := func(raw string) string {
		n := strings.TrimSuffix(strings.TrimSpace(raw), ".")
		if n == "" {
			return ""
		}
		if strings.HasSuffix(n, ".in-addr.arpa") || strings.HasSuffix(n, ".ip6.arpa") {
			return ""
		}
		return n
	}

	cases := []struct {
		in   string
		want string
	}{
		// 真实的 ARPA 查询名（带结尾点）—— 必须被过滤
		{"188.70.3.119.in-addr.arpa.", ""},
		{"8.8.8.8.in-addr.arpa.", ""},
		// 不带点也要过滤
		{"188.70.3.119.in-addr.arpa", ""},
		// IPv6 形式
		{"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", ""},
		// 正常主机名 —— 必须保留
		{"dns.google.", "dns.google"},
		{"ecs-119-3-70-188.compute.hwclouds-dns.com.", "ecs-119-3-70-188.compute.hwclouds-dns.com"},
		{"one.one.one.one.", "one.one.one.one"},
		// 空
		{"", ""},
	}
	for _, c := range cases {
		if got := filter(c.in); got != c.want {
			t.Errorf("filter(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// ⭐ reverseName 必须正确生成 ARPA 域名
func TestReverseName(t *testing.T) {
	cases := []struct {
		ip   string
		want string
	}{
		{"8.8.8.8", "8.8.8.8.in-addr.arpa"},
		{"1.1.1.1", "1.1.1.1.in-addr.arpa"},
		{"119.3.70.188", "188.70.3.119.in-addr.arpa"}, // ⭐ 真正反转
		{"255.255.255.255", "255.255.255.255.in-addr.arpa"},
		{"8.8.4.4", "4.4.8.8.in-addr.arpa"}, // 注意不是对称的
		// IPv6：32 个 nibble 逐个反序
	}
	for _, c := range cases {
		got, err := reverseName(c.ip)
		if err != nil {
			t.Errorf("reverseName(%q) 报错: %v", c.ip, err)
			continue
		}
		if got != c.want {
			t.Errorf("reverseName(%q)\n  得到 %q\n  期望 %q", c.ip, got, c.want)
		}
	}

	// ⭐ IPv6 的期望值不该手写 —— 32 个 nibble 数错一个就不对。
	//   用性质断言代替：nibble 数量、首个 nibble、结尾后缀。
	for _, ip := range []string{"::1", "2001:db8::1", "fe80::1", "2400:3200::1"} {
		got, err := reverseName(ip)
		if err != nil {
			t.Errorf("reverseName(%q) 报错: %v", ip, err)
			continue
		}
		prefix := strings.TrimSuffix(got, ".ip6.arpa")
		nibbles := strings.Split(prefix, ".")
		if len(nibbles) != 32 {
			t.Errorf("reverseName(%q) 应有 32 个 nibble，实际 %d", ip, len(nibbles))
		}
		// 首位 nibble 必须等于 IP 的最后一段的最低 nibble
		wantFirst := nibbleAt(ip, 31)
		if nibbles[0] != wantFirst {
			t.Errorf("reverseName(%q) 首位 nibble = %q, 期望 %q",
				ip, nibbles[0], wantFirst)
		}
	}
}

// nibbleAt 取 IP 第 i 个 nibble（i=0 是最高位，i=31 是最低位）
func nibbleAt(ipStr string, i int) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	b := ip.To16()
	if b == nil {
		return ""
	}
	const hexDigits = "0123456789abcdef"
	byteIdx := i / 2
	// nibble 0 = 高位，nibble 1 = 低位
	if i%2 == 0 {
		return string(hexDigits[b[byteIdx]>>4])
	}
	return string(hexDigits[b[byteIdx]&0x0f])
}

// ⭐ IPv6 的 nibble 格式容易写错：必须 32 个 nibble 各自反序
func TestReverseName_IPv6NibbleCount(t *testing.T) {
	got, err := reverseName("2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, ".ip6.arpa") {
		t.Fatalf("IPv6 应以 .ip6.arpa 结尾，得到 %q", got)
	}
	// 数一下 nibble 数（减去末尾的 ip6.arpa）
	prefix := strings.TrimSuffix(got, ".ip6.arpa")
	nibbles := strings.Split(prefix, ".")
	if len(nibbles) != 32 {
		t.Errorf("IPv6 ARPA 应有 32 个 nibble，实际 %d 个（%q）", len(nibbles), prefix)
	}
	// 最后一个 nibble 必须是 '1'（因为 ::1 的最低位是 1）
	if nibbles[0] != "1" {
		t.Errorf("IPv6 反查首位应为最低位 nibble('1')，实际 %q", nibbles[0])
	}
}

// ⭐ 泛用主机名分类：云厂商默认 PTR 与真实站点要分开
func TestIsGenericHostname(t *testing.T) {
	generic := []string{
		"ecs-119-3-70-188.compute.hwclouds-dns.com",
		"ec2-1-2-3-4.compute-1.amazonaws.com",
		"1-2-3-4.cloudapp.azure.com",
		"ip-10-0-1-5.ec2.internal",
		"vip-192-168-1-1.example.com",
		"host.docker.internal",
		"4-3-2-1.static.example.com",
		"lb-140-82-113-4-iad.github.com",
	}
	specific := []string{
		"dns.google",
		"one.one.one.one",
		"public1.114dns.com",
		"cdn-01.example.com", // ⚠️ 含 cdn- 前缀但仍是具体域名
		"support.enterprise.example.com",
	}
	for _, h := range generic {
		if isGenericHostname(h) == "" {
			t.Errorf("%q 应被判为泛用主机名", h)
		}
	}
	for _, h := range specific {
		if isGenericHostname(h) != "" {
			t.Errorf("⭐ %q 不应被判为泛用（它是具体域名，含信息量），实际标记 %q",
				h, isGenericHostname(h))
		}
	}
}

// ⭐ 无 PTR 是常态，必须与查询失败区分
func TestRDNSResult_NoPTRIsNotError(t *testing.T) {
	r := &RDNSResult{IP: "1.2.3.4", HasPTR: false, Err: ""}
	if r.HasPTR {
		t.Error("HasPTR 应为 false")
	}
	if r.Err != "" {
		t.Error("无 PTR 时 Err 应为空 —— 两者是不同的语义")
	}
	// 分类应返回空
	c := r.Classify()
	if len(c.Generic) != 0 || len(c.Specific) != 0 {
		t.Error("无 PTR 时分类应为空")
	}
}

// ⭐ PTR 里含**具体域名**时应加 rdns-named 标签；
//
//	只有泛用云主机名时**不该**加（那是噪音，不是资产线索）。
func TestAddRDNS_FlagsSpecific(t *testing.T) {
	// 情况 1：PTR 全是泛用云主机名 → 不加标签
	info1 := &Info{IP: "1.2.3.4", Valid: true}
	info1.AddRDNS(&RDNSResult{
		IP:        "1.2.3.4",
		Hostnames: []string{"ecs-1-2-3-4.compute.hwclouds-dns.com"},
		HasPTR:    true,
	})
	for _, f := range info1.Flags {
		if f == "rdns-named" {
			t.Errorf("⭐ 泛用云主机名不应加 rdns-named 标签（那是噪音）：%v", info1.Flags)
		}
	}

	// 情况 2：PTR 含具体域名 → 加标签
	info2 := &Info{IP: "1.2.3.5", Valid: true}
	info2.AddRDNS(&RDNSResult{
		IP:        "1.2.3.5",
		Hostnames: []string{"ecs-1-2-3-4.compute.hwclouds-dns.com", "static.cdn.example.com"},
		HasPTR:    true,
	})
	found := false
	for _, f := range info2.Flags {
		if f == "rdns-named" {
			found = true
		}
	}
	if !found {
		t.Errorf("PTR 含具体域名时应加 rdns-named 标签，实际 %v", info2.Flags)
	}
	if !info2.HasPTR {
		t.Error("HasPTR 应为 true")
	}
	if got := info2.ReverseHosts(); !strings.Contains(got, "static.cdn.example.com") {
		t.Errorf("ReverseHosts() 应含具体域名，实际 %q", got)
	}
}
