package httpprobe

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

// ⭐⭐ JARM 指纹（P1-3）—— Salesforce 开源算法的忠实移植
//
// JARM = 10 个定制 TLS ClientHello 的服务器响应模糊哈希（62 字符）。
// 它反映服务端 TLS 栈的"实现特征"：换服务器/换实现/重大升级都会改变。
// 纯被动数据拿不到这个信号。
//
// ⭐⭐ 移植纪律（本项目"数据必须实测"原则的最强体现）：
//
//	字节级行为必须与参考实现（Salesforce/jarm 的 jarm.py v1.0）**完全一致**，
//	否则哈希对不上生态里已有的 JARM 库（Shodan/Censys 都收录 JARM）。
//	本实现通过与 Python 参考实现**对多台真实服务器交叉验证**来确认一致性。
//
// 参考：https://github.com/Salesforce/jarm （BSD-3-Clause）

// jarmProbe 一组探测参数
// （对应参考实现的数组格式：
//
//	[host, port, version, cipher_list, cipher_order, grease, rare_alpn, tls13_support, ext_order]）
type jarmProbe struct {
	version      string // TLS_1.2 / TLS_1.3 / TLS_1.1 ...
	cipherList   string // ALL / NO1.3
	cipherOrder  string // FORWARD / REVERSE / TOP_HALF / BOTTOM_HALF / MIDDLE_OUT
	grease       bool
	rareALPN     bool
	tls13Support string // 1.2_SUPPORT / NO_SUPPORT / 1.3_SUPPORT
	extOrder     string // FORWARD / REVERSE（作用于 ALPN 列表与 supported_versions 的顺序）
}

// jarmQueue 参考实现的 10 组探测（顺序不可变）
var jarmQueue = []jarmProbe{
	{version: "TLS_1.2", cipherList: "ALL", cipherOrder: "FORWARD", tls13Support: "1.2_SUPPORT", extOrder: "REVERSE"},
	{version: "TLS_1.2", cipherList: "ALL", cipherOrder: "REVERSE", tls13Support: "1.2_SUPPORT", extOrder: "FORWARD"},
	{version: "TLS_1.2", cipherList: "ALL", cipherOrder: "TOP_HALF", tls13Support: "NO_SUPPORT", extOrder: "FORWARD"},
	{version: "TLS_1.2", cipherList: "ALL", cipherOrder: "BOTTOM_HALF", rareALPN: true, tls13Support: "NO_SUPPORT", extOrder: "FORWARD"},
	{version: "TLS_1.2", cipherList: "ALL", cipherOrder: "MIDDLE_OUT", grease: true, rareALPN: true, tls13Support: "NO_SUPPORT", extOrder: "REVERSE"},
	{version: "TLS_1.1", cipherList: "ALL", cipherOrder: "FORWARD", tls13Support: "NO_SUPPORT", extOrder: "FORWARD"},
	{version: "TLS_1.3", cipherList: "ALL", cipherOrder: "FORWARD", tls13Support: "1.3_SUPPORT", extOrder: "REVERSE"},
	{version: "TLS_1.3", cipherList: "ALL", cipherOrder: "REVERSE", tls13Support: "1.3_SUPPORT", extOrder: "FORWARD"},
	{version: "TLS_1.3", cipherList: "NO1.3", cipherOrder: "FORWARD", tls13Support: "1.3_SUPPORT", extOrder: "FORWARD"},
	{version: "TLS_1.3", cipherList: "ALL", cipherOrder: "MIDDLE_OUT", grease: true, tls13Support: "1.3_SUPPORT", extOrder: "REVERSE"},
}

// 参考实现的两个 cipher 列表（逐字节转录）
var jarmCipherListAll = []uint16{
	0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3,
	0x009f, 0x0045, 0x00be, 0x0088, 0x00c4, 0x009a, 0xc008, 0xc009, 0xc023, 0xc0ac,
	0xc0ae, 0xc02b, 0xc00a, 0xc024, 0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9,
	0x1302, 0x1301, 0xcc14, 0xc007, 0xc012, 0xc013, 0xc027, 0xc02f, 0xc014, 0xc028,
	0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8, 0x1305, 0x1304, 0x1303, 0xcc13,
	0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0, 0x009c, 0x0035, 0x003d, 0xc09d,
	0xc0a1, 0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0, 0x0007, 0x0004, 0x0005,
}

var jarmCipherListNo13 = []uint16{
	0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3,
	0x009f, 0x0045, 0x00be, 0x0088, 0x00c4, 0x009a, 0xc008, 0xc009, 0xc023, 0xc0ac,
	0xc0ae, 0xc02b, 0xc00a, 0xc024, 0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9,
	0xcc14, 0xc007, 0xc012, 0xc013, 0xc027, 0xc02f, 0xc014, 0xc028, 0xc030, 0xc060,
	0xc061, 0xc076, 0xc077, 0xcca8, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c,
	0xc0a0, 0x009c, 0x0035, 0x003d, 0xc09d, 0xc0a1, 0x009d, 0x0041, 0x00ba, 0x0084,
	0x00c0, 0x0007, 0x0004, 0x0005,
}

// jarmCipherIndex 模糊哈希的 cipher 索引表（参考实现的 cipher_bytes list）
var jarmCipherIndex = []uint16{
	0x0004, 0x0005, 0x0007, 0x000a, 0x0016, 0x002f, 0x0033, 0x0035, 0x0039, 0x003c,
	0x003d, 0x0041, 0x0045, 0x0067, 0x006b, 0x0084, 0x0088, 0x009a, 0x009c, 0x009d,
	0x009e, 0x009f, 0x00ba, 0x00be, 0x00c0, 0x00c4, 0xc007, 0xc008, 0xc009, 0xc00a,
	0xc011, 0xc012, 0xc013, 0xc014, 0xc023, 0xc024, 0xc027, 0xc028, 0xc02b, 0xc02c,
	0xc02f, 0xc030, 0xc060, 0xc061, 0xc072, 0xc073, 0xc076, 0xc077, 0xc09c, 0xc09d,
	0xc09e, 0xc09f, 0xc0a0, 0xc0a1, 0xc0a2, 0xc0a3, 0xc0ac, 0xc0ad, 0xc0ae, 0xc0af,
	0xcc13, 0xcc14, 0xcca8, 0xcca9, 0x1301, 0x1302, 0x1303, 0x1304, 0x1305,
}

// jarmGreaseValues 参考实现的 GREASE 值表
var jarmGreaseValues = [][2]byte{
	{0x0a, 0x0a}, {0x1a, 0x1a}, {0x2a, 0x2a}, {0x3a, 0x3a},
	{0x4a, 0x4a}, {0x5a, 0x5a}, {0x6a, 0x6a}, {0x7a, 0x7a},
	{0x8a, 0x8a}, {0x9a, 0x9a}, {0xaa, 0xaa}, {0xba, 0xba},
	{0xca, 0xca}, {0xda, 0xda}, {0xea, 0xea}, {0xfa, 0xfa},
}

func jarmChooseGrease() []byte {
	var b [1]byte
	_, _ = rand.Read(b[:])
	g := jarmGreaseValues[int(b[0])%len(jarmGreaseValues)]
	return []byte{g[0], g[1]}
}

// jarmMunge 参考实现的 cipher_mung（用于 cipher / ALPN / 版本列表的重排）
func jarmMunge(items [][]byte, order string) [][]byte {
	n := len(items)
	out := make([][]byte, 0, n)
	switch order {
	case "REVERSE":
		for i := n - 1; i >= 0; i-- {
			out = append(out, items[i])
		}
	case "BOTTOM_HALF":
		if n%2 == 1 {
			out = append(out, items[n/2+1:]...)
		} else {
			out = append(out, items[n/2:]...)
		}
	case "TOP_HALF":
		if n%2 == 1 {
			out = append(out, items[n/2])
		}
		out = append(out, jarmMunge(jarmMunge(items, "REVERSE"), "BOTTOM_HALF")...)
	case "MIDDLE_OUT":
		middle := n / 2
		if n%2 == 1 {
			out = append(out, items[middle])
			for i := 1; i <= middle; i++ {
				if middle+i < n {
					out = append(out, items[middle+i])
				}
				out = append(out, items[middle-i])
			}
		} else {
			for i := 1; i <= middle; i++ {
				out = append(out, items[middle-1+i])
				out = append(out, items[middle-i])
			}
		}
	default: // FORWARD
		out = append(out, items...)
	}
	return out
}

// jarmGetCiphers 组装 cipher 字节序列
func jarmGetCiphers(p jarmProbe) []byte {
	list := jarmCipherListAll
	if p.cipherList == "NO1.3" {
		list = jarmCipherListNo13
	}
	items := make([][]byte, len(list))
	for i, c := range list {
		items[i] = []byte{byte(c >> 8), byte(c)}
	}
	if p.cipherOrder != "FORWARD" {
		items = jarmMunge(items, p.cipherOrder)
	}
	if p.grease {
		items = append([][]byte{jarmChooseGrease()}, items...)
	}
	var out []byte
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

// jarmExtServerName SNI 扩展
func jarmExtServerName(host string) []byte {
	ext := []byte{0x00, 0x00}
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(host)+5))
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(host)+3))
	ext = append(ext, 0x00)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(host)))
	ext = append(ext, host...)
	return ext
}

// jarmExtALPN ALPN 扩展
func jarmExtALPN(p jarmProbe) []byte {
	var alpns [][]byte
	if p.rareALPN {
		alpns = [][]byte{
			{0x08, 'h', 't', 't', 'p', '/', '0', '.', '9'},
			{0x08, 'h', 't', 't', 'p', '/', '1', '.', '0'},
			{0x06, 's', 'p', 'd', 'y', '/', '1'},
			{0x06, 's', 'p', 'd', 'y', '/', '2'},
			{0x06, 's', 'p', 'd', 'y', '/', '3'},
			{0x03, 'h', '2', 'c'},
			{0x02, 'h', 'q'},
		}
	} else {
		alpns = [][]byte{
			{0x08, 'h', 't', 't', 'p', '/', '0', '.', '9'},
			{0x08, 'h', 't', 't', 'p', '/', '1', '.', '0'},
			{0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'},
			{0x06, 's', 'p', 'd', 'y', '/', '1'},
			{0x06, 's', 'p', 'd', 'y', '/', '2'},
			{0x06, 's', 'p', 'd', 'y', '/', '3'},
			{0x02, 'h', '2'},
			{0x03, 'h', '2', 'c'},
			{0x02, 'h', 'q'},
		}
	}
	if p.extOrder != "FORWARD" {
		alpns = jarmMunge(alpns, p.extOrder)
	}
	var all []byte
	for _, a := range alpns {
		all = append(all, a...)
	}
	ext := []byte{0x00, 0x10}
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(all)+2))
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(all)))
	ext = append(ext, all...)
	return ext
}

// jarmExtKeyShare key_share 扩展
func jarmExtKeyShare(grease bool) []byte {
	var share []byte
	if grease {
		share = append(share, jarmChooseGrease()...)
		share = append(share, 0x00, 0x01, 0x00)
	}
	share = append(share, 0x00, 0x1d) // x25519
	share = append(share, 0x00, 0x20)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	share = append(share, key...)

	ext := []byte{0x00, 0x33}
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(share)+2))
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(share)))
	ext = append(ext, share...)
	return ext
}

// jarmExtSupportedVersions supported_versions 扩展
func jarmExtSupportedVersions(p jarmProbe, grease bool) []byte {
	var tls [][]byte
	if p.tls13Support == "1.2_SUPPORT" {
		tls = [][]byte{{0x03, 0x01}, {0x03, 0x02}, {0x03, 0x03}}
	} else {
		tls = [][]byte{{0x03, 0x01}, {0x03, 0x02}, {0x03, 0x03}, {0x03, 0x04}}
	}
	if p.extOrder != "FORWARD" {
		tls = jarmMunge(tls, p.extOrder)
	}
	var versions []byte
	if grease {
		versions = append(versions, jarmChooseGrease()...)
	}
	for _, v := range tls {
		versions = append(versions, v...)
	}
	ext := []byte{0x00, 0x2b}
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(versions)+1))
	ext = append(ext, byte(len(versions)))
	ext = append(ext, versions...)
	return ext
}

// jarmBuildExtensions 组装全部扩展（顺序与参考实现一致，不可调换）
func jarmBuildExtensions(p jarmProbe, host string) []byte {
	var all []byte
	if p.grease {
		all = append(all, jarmChooseGrease()...)
		all = append(all, 0x00, 0x00)
	}
	all = append(all, jarmExtServerName(host)...)
	all = append(all, 0x00, 0x17, 0x00, 0x00)                                                             // extended_master_secret
	all = append(all, 0x00, 0x01, 0x00, 0x01, 0x01)                                                       // max_fragment_length
	all = append(all, 0xff, 0x01, 0x00, 0x01, 0x00)                                                       // renegotiation_info
	all = append(all, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19) // supported_groups
	all = append(all, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00)                                                 // ec_point_formats
	all = append(all, 0x00, 0x23, 0x00, 0x00)                                                             // session_ticket
	all = append(all, jarmExtALPN(p)...)
	all = append(all, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01) // signature_algorithms
	all = append(all, jarmExtKeyShare(p.grease)...)
	all = append(all, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01) // psk_key_exchange_modes
	if p.version == "TLS_1.3" || p.tls13Support == "1.2_SUPPORT" {
		all = append(all, jarmExtSupportedVersions(p, p.grease)...)
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(all)))
	return append(out, all...)
}

// jarmBuildPacket 组装完整 ClientHello 报文
func jarmBuildPacket(p jarmProbe, host string) []byte {
	var recordVersion [2]byte
	var helloVersion [2]byte
	switch p.version {
	case "SSLv3":
		recordVersion = [2]byte{0x03, 0x00}
		helloVersion = [2]byte{0x03, 0x00}
	case "TLS_1":
		recordVersion = [2]byte{0x03, 0x01}
		helloVersion = [2]byte{0x03, 0x01}
	case "TLS_1.1":
		recordVersion = [2]byte{0x03, 0x02}
		helloVersion = [2]byte{0x03, 0x02}
	case "TLS_1.3":
		// ⭐ 参考实现：TLS_1.3 的 record 版本是 0301，ClientHello 版本是 0303
		recordVersion = [2]byte{0x03, 0x01}
		helloVersion = [2]byte{0x03, 0x03}
	default: // TLS_1.2
		recordVersion = [2]byte{0x03, 0x03}
		helloVersion = [2]byte{0x03, 0x03}
	}

	ch := make([]byte, 0, 512)
	ch = append(ch, helloVersion[:]...)
	random32 := make([]byte, 32)
	_, _ = rand.Read(random32)
	ch = append(ch, random32...)
	sessionID := make([]byte, 32)
	_, _ = rand.Read(sessionID)
	ch = append(ch, byte(len(sessionID)))
	ch = append(ch, sessionID...)
	ciphers := jarmGetCiphers(p)
	ch = binary.BigEndian.AppendUint16(ch, uint16(len(ciphers)))
	ch = append(ch, ciphers...)
	ch = append(ch, 0x01) // cipher methods（1 个）
	ch = append(ch, 0x00) // compression methods（null）
	ch = append(ch, jarmBuildExtensions(p, host)...)

	// handshake：类型 0x01 + 3 字节长度（0x00 || uint16）
	hs := make([]byte, 0, len(ch)+4)
	hs = append(hs, 0x01, 0x00)
	hs = binary.BigEndian.AppendUint16(hs, uint16(len(ch)))
	hs = append(hs, ch...)

	// record：类型 0x16 + 版本 + 2 字节长度
	out := make([]byte, 0, len(hs)+5)
	out = append(out, 0x16, recordVersion[0], recordVersion[1])
	out = binary.BigEndian.AppendUint16(out, uint16(len(hs)))
	out = append(out, hs...)
	return out
}

// ── 网络与解析 ───────────────────────────────────────────

// jarmProbeOnce 发送一个探测包并读回响应
// 返回 (响应数据, 是否超时)。超时语义与参考实现一致（整体判 0）。
func jarmProbeOnce(addr string, packet []byte, timeout time.Duration) ([]byte, bool) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, isTimeout(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(packet); err != nil {
		return nil, isTimeout(err)
	}
	buf := make([]byte, 1484)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, isTimeout(err)
	}
	return buf[:n], false
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// jarmReadPacket 解析 ServerHello（索引逻辑与参考实现逐字节对齐）
func jarmReadPacket(data []byte) string {
	if len(data) == 0 {
		return "|||"
	}
	// 服务器返回 alert
	if data[0] == 21 {
		return "|||"
	}
	// 必须是 ServerHello（handshake=22, 类型=2）
	if data[0] != 22 || len(data) < 6 || data[5] != 2 {
		return "|||"
	}
	serverHelloLength := int(data[3])<<8 | int(data[4])
	if len(data) < 44 {
		return "|||"
	}
	counter := int(data[43])
	if len(data) < counter+46 {
		return "|||"
	}
	selectedCipher := data[counter+44 : counter+46]
	version := data[9:11]
	return hex.EncodeToString(selectedCipher) + "|" + hex.EncodeToString(version) +
		"|" + jarmExtractExtensions(data, counter, serverHelloLength)
}

// jarmExtractExtensions 提取扩展信息（含参考实现的三个启发式特判）
func jarmExtractExtensions(data []byte, counter, serverHelloLength int) string {
	// 参考实现的特判（按原样移植）
	if counter+47 >= len(data) {
		return "|"
	}
	if data[counter+47] == 11 {
		return "|"
	}
	if counter+53 <= len(data) && data[counter+50] == 0x0e &&
		data[counter+51] == 0xac && data[counter+52] == 0x0b {
		return "|"
	}
	if len(data) >= 85 && data[82] == 0x0f && data[83] == 0xf0 && data[84] == 0x0b {
		return "|"
	}
	if counter+42 >= serverHelloLength {
		return "|"
	}
	count := 49 + counter
	length := int(data[counter+47])<<8 | int(data[counter+48])
	maximum := length + (count - 1)

	var types [][]byte
	var values [][]byte
	for count < maximum {
		if count+4 > len(data) {
			return "|"
		}
		types = append(types, data[count:count+2])
		extLength := int(data[count+2])<<8 | int(data[count+3])
		if extLength == 0 {
			count += 4
			values = append(values, nil)
			continue
		}
		if count+4+extLength > len(data) {
			return "|"
		}
		values = append(values, data[count+4:count+4+extLength])
		count += extLength + 4
	}

	result := jarmFindExtension([]byte{0x00, 0x10}, types, values) + "|"
	for i, t := range types {
		result += hex.EncodeToString(t)
		if i < len(types)-1 {
			result += "-"
		}
	}
	return result
}

// jarmFindExtension 找指定扩展类型的值（ALPN 取 ASCII，其余 hex）
func jarmFindExtension(extType []byte, types, values [][]byte) string {
	for i, t := range types {
		if len(t) == 2 && t[0] == extType[0] && t[1] == extType[1] {
			v := values[i]
			if extType[0] == 0x00 && extType[1] == 0x10 {
				// ALPN：跳过前 3 字节（列表长度 + 字符串长度）
				if len(v) >= 3 {
					return string(v[3:])
				}
				return ""
			}
			return hex.EncodeToString(v)
		}
	}
	return ""
}

// ── 模糊哈希 ─────────────────────────────────────────────

// jarmHash 参考实现的 jarm_hash
func jarmHash(raw string) string {
	if raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||" {
		return strings.Repeat("0", 62)
	}
	var fuzzy strings.Builder
	var alpnsAndExt strings.Builder
	for _, hs := range strings.Split(raw, ",") {
		comps := strings.Split(hs, "|")
		cipher, version, a, b := "", "", "", ""
		if len(comps) > 0 {
			cipher = comps[0]
		}
		if len(comps) > 1 {
			version = comps[1]
		}
		if len(comps) > 2 {
			a = comps[2]
		}
		if len(comps) > 3 {
			b = comps[3]
		}
		fuzzy.WriteString(jarmCipherByte(cipher))
		fuzzy.WriteString(jarmVersionByte(version))
		alpnsAndExt.WriteString(a)
		alpnsAndExt.WriteString(b)
	}
	sum := sha256.Sum256([]byte(alpnsAndExt.String()))
	fuzzy.WriteString(hex.EncodeToString(sum[:])[:32])
	return fuzzy.String()
}

// jarmCipherByte cipher 在索引表中的位置（参考实现：找不到则取 len+1）
func jarmCipherByte(cipher string) string {
	if cipher == "" {
		return "00"
	}
	count := 1
	found := false
	for _, c := range jarmCipherIndex {
		h := hex.EncodeToString([]byte{byte(c >> 8), byte(c)})
		if cipher == h {
			found = true
			break
		}
		count++
	}
	_ = found
	v := strconv.FormatInt(int64(count), 16)
	if len(v) < 2 {
		return "0" + v
	}
	return v
}

// jarmVersionByte 版本号 → 单字符（参考实现："0303" → "d"）
func jarmVersionByte(version string) string {
	if version == "" {
		return "0"
	}
	options := "abcdef"
	if len(version) < 4 {
		return "0"
	}
	n, err := strconv.Atoi(string(version[3]))
	if err != nil || n >= len(options) {
		return "0"
	}
	return string(options[n])
}

// JARMFailed 该结果是否为"探测失败"哨兵（62 个 0）
//
// ⭐ 全 0 不是指纹，是"任一探测超时 / 全部失败"的编码（与参考实现一致）。
//
//	它绝不能参与快照与 diff —— 否则一次网络抖动会被报成
//	"TLS 栈变了"的假阳性（审查发现的 H2）。
func (r *ProbeResult) JARMFailed() bool {
	return r.JARM == strings.Repeat("0", 62)
}

// JARMDisplay JARM 的展示文本（"" = 未采集；"失败" = 探测失败哨兵；否则完整哈希）
func (r *ProbeResult) JARMDisplay() string {
	if r.JARM == "" {
		return ""
	}
	if r.JARMFailed() {
		return "失败"
	}
	return r.JARM
}

// JARMFingerprint 对 dialHost:port 计算 JARM 指纹（62 字符）
//
//	sniHost 用于 ClientHello 的 SNI —— ⭐ IP 直连 + HostHeader 的 CDN 场景
//	必须送域名，否则拿到的是默认站点的指纹。
//
// 与参考实现一致的语义：任一探测超时 → 整体返回 62 个 0。
// 连接被拒/非 TLS 响应 → 该探测记为 "|||"，继续（大多数探测都失败时哈希仍可计算）。
func JARMFingerprint(dialHost string, port int, sniHost string, timeout time.Duration) string {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if sniHost == "" {
		sniHost = dialHost
	}
	addr := net.JoinHostPort(dialHost, strconv.Itoa(port))
	parts := make([]string, 0, len(jarmQueue))
	for _, p := range jarmQueue {
		packet := jarmBuildPacket(p, sniHost)
		resp, timedOut := jarmProbeOnce(addr, packet, timeout)
		if timedOut {
			// ⭐ 与参考实现一致：任一探测超时 → 整体判 0
			return strings.Repeat("0", 62)
		}
		parts = append(parts, jarmReadPacket(resp))
	}
	return jarmHash(strings.Join(parts, ","))
}
