package httpprobe

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ⭐ HTTP/2 SETTINGS 指纹（P1-3）
//
// 原理：TLS 握手 ALPN 协商到 h2 后，服务器会**立即**发送自己的 SETTINGS 帧
// （连接级参数：窗口大小、并发流上限、帧大小……）。这些值的组合是服务器
// 软件（nginx / Cloudflare / Go / Envoy / IIS…）的实现特征 ——
// 换软件或大版本升级会改变它，是"指纹源扩充"里最廉价的一路（仅 1 个连接）。
//
// 输出格式（Akamai 风格）: "SETTINGS|WINDOW_UPDATE"
//
//	SETTINGS      = "id:value;id:value;..."（按服务器发送顺序）
//	WINDOW_UPDATE = 连接级窗口增量（服务器未发送则为空）
//
// 例：1:65536;2:0;4:6291456;6:262144|15663105
//
//	sniHost 用于 TLS SNI —— ⭐ IP 直连 + HostHeader 的 CDN 场景必须送域名。
func H2Fingerprint(dialHost string, port int, sniHost string, timeout time.Duration) string {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if sniHost == "" {
		sniHost = dialHost
	}
	addr := net.JoinHostPort(dialHost, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sniHost,
		NextProtos:         []string{"h2"},
	})
	if err != nil {
		return ""
	}
	defer conn.Close()
	// ⭐ 必须真正协商到 h2：服务器不支持 HTTP/2 时指纹无意义
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		return ""
	}

	// 客户端连接序言 + 空 SETTINGS 帧（9 字节头，payload 为空）
	preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if _, err := conn.Write([]byte(preface)); err != nil {
		return ""
	}
	if _, err := conn.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0}); err != nil {
		return ""
	}

	var settings []string
	windowUpdate := ""
	gotSettings := false
	pending := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)

	// 读帧循环（⭐ L1：整体 deadline 兜底 —— 慢滴服务器不会拖满 3×timeout）：
	//   第 1 次读用完整超时（等 SETTINGS）；
	//   拿到 SETTINGS 后再补读一次（最多 300ms）以捕获同批的 WINDOW_UPDATE；
	//   仍没有就结束（很多服务器确实不发 WINDOW_UPDATE，不能白等）。
	overall := time.Now().Add(timeout)
	for attempt := 0; attempt < 3; attempt++ {
		remaining := time.Until(overall)
		if remaining <= 0 {
			break
		}
		wait := timeout
		if gotSettings {
			wait = 300 * time.Millisecond
		}
		if wait > remaining {
			wait = remaining
		}
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		n, err := conn.Read(tmp)
		if n > 0 {
			pending = append(pending, tmp[:n]...)
			for len(pending) >= 9 {
				length := int(pending[0])<<16 | int(pending[1])<<8 | int(pending[2])
				ftype := pending[3]
				flags := pending[4]
				if len(pending) < 9+length {
					break // 帧不完整，等更多数据
				}
				payload := pending[9 : 9+length]
				pending = pending[9+length:]

				switch ftype {
				case 4: // SETTINGS
					if flags&0x1 != 0 {
						continue // SETTINGS ACK（对客户端设置的确认），跳过
					}
					gotSettings = true
					for i := 0; i+6 <= len(payload); i += 6 {
						id := int(binary.BigEndian.Uint16(payload[i : i+2]))
						val := binary.BigEndian.Uint32(payload[i+2 : i+6])
						settings = append(settings, fmt.Sprintf("%d:%d", id, val))
					}
				case 8: // WINDOW_UPDATE（stream 0 = 连接级）
					if len(payload) >= 4 && windowUpdate == "" {
						inc := binary.BigEndian.Uint32(payload[:4]) & 0x7fffffff
						windowUpdate = strconv.FormatUint(uint64(inc), 10)
					}
				}
			}
		}
		if gotSettings && windowUpdate != "" {
			break
		}
		if gotSettings && attempt >= 1 {
			break // 补读一次后仍无 WINDOW_UPDATE → 结束
		}
		if err != nil {
			break
		}
	}

	if !gotSettings {
		return ""
	}
	return strings.Join(settings, ";") + "|" + windowUpdate
}
