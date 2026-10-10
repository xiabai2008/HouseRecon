"""
QUIC 探活原型 — 靶场服务端
==========================

用途：在 127.0.0.1 上模拟四种 UDP/443 响应状态，验证探测器的判定逻辑。

不实现完整 QUIC 协议，只实现"探活判定所依赖的最小行为"：
  1. 正常 QUIC 服务端 → 对未知 version 回 Version Negotiation
  2. 非 QUIC UDP 服务   → 回自定义垃圾字节（不响应）
  3. 静默丢弃          → 什么都不回（模拟 filtered）
  4. 端口关闭          → ICMP port unreachable（由 OS 自动产生）

QUIC 协议依据：RFC 9000 §17.2.1（Version Negotiation）、draft-ietf-quic-transport-26

关键事实（已核验）：
  - 长包头首字节：Header Form(1)=1, Fixed Bit(1)=1, Long Packet Type(2)
  - Version 字段：偏移 1..4，32bit，**明文**
  - Version Negotiation 包：Version 字段固定为 0x00000000，随后是服务端支持版本列表
  - VN 包在**解密之前**发出，所以探活不需要任何加密计算
"""

import socket
import struct
import sys
import threading
import time

# ── QUIC 常量 ──────────────────────────────────────────────
QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF          # RFC 9369
GREASED_V1 = 0x0A0A0A0A       # 保留号，真实服务商会回 VN
GREASED_V2 = 0x1A2A3A4A       # 另一个保留号

# 长包头首字节
#   bit7 Header Form = 1
#   bit6 Fixed Bit   = 1
#   bit5-4 Long Packet Type = 00 (Initial)
#   bit3-0 Type-Specific = 0
LONG_HEADER_INITIAL = 0xC0

# 包类型
PKT_INITIAL   = 0x00
PKT_0RTT      = 0x01
PKT_HANDSHAKE = 0x02
PKT_RETRY     = 0x03


def parse_long_header(data: bytes) -> dict:
    """
    解析 QUIC 长包头（仅明文部分）。

    布局（RFC 9000 §17.2）：
      0      : 1 byte  flags
      1..5   : 4 bytes version
      5      : 1 byte  DCID Len
      6..    : DCID
      ...    : 1 byte  SCID Len
      ...    : SCID
    """
    if len(data) < 7:
        return {"valid": False, "reason": "too_short"}

    flags = data[0]
    header_form = (flags >> 7) & 0x01
    fixed_bit = (flags >> 6) & 0x01
    packet_type = (flags >> 4) & 0x03

    if header_form != 1:
        return {"valid": False, "reason": "not_long_header"}

    version = struct.unpack(">I", data[1:5])[0]
    dcid_len = data[5]

    if version == 0:
        return {
            "valid": True,
            "header_form": header_form,
            "fixed_bit": fixed_bit,
            "packet_type": packet_type,
            "version": 0,
            "is_version_negotiation": True,
        }

    # version 协商包没有 CID 长度限制，直接跳到版本列表
    # （VN 包：version 之后是支持的版本列表，每 4 字节一个）
    if dcid_len > 20:
        return {"valid": True, "version": version, "error": "dcid_len>20"}

    # 提取 DCID/SCID（用于回显，模拟真实服务端行为）
    off = 6
    dcid = data[off:off + dcid_len]
    off += dcid_len
    scid = b""
    if off < len(data):
        scid_len = data[off]
        off += 1
        scid = data[off:off + scid_len]

    return {
        "valid": True,
        "header_form": header_form,
        "fixed_bit": fixed_bit,
        "packet_type": packet_type,
        "version": version,
        "dcid_len": dcid_len,
        "dcid": dcid,
        "scid": scid,
        "is_version_negotiation": False,
        "raw_len": len(data),
    }


def build_version_negotiation(supported_versions: list,
                              echo_dcid: bytes = b"\x00" * 8,
                              scid: bytes = b"\x00" * 8) -> bytes:
    """
    构造 Version Negotiation 响应包。

    格式（RFC 9000 §17.2.1）：
      - 首字节：Header Form=1, Fixed Bit=1（type 位在 VN 包中保留，客户端应忽略）
      - version：固定 0x00000000
      - DCID Len + DCID：服务端**回显客户端的 DCID**
      - SCID Len + SCID：服务端自己的 CID
      - 随后重复的服务端支持版本列表（每 4 字节）

    ⚠️ 踩坑记录：早期版本漏掉了 DCID/SCID 字段，直接在 version
       之后接版本列表。结果探测器和靶场"两边都错所以对上了"，
       面对真实 quic-go 时才暴露出解析出垃圾版本的问题。
       **真实实现的偏移必须以真抓包为准，不能靠两边互相印证。**
    """
    out = bytearray()
    out.append(0xC0)                                  # 长包头 + Fixed Bit
    out += struct.pack(">I", 0x00000000)              # version = 0 (VN 标志)
    # DCID（回显客户端的）
    dcid = echo_dcid[:20]                             # RFC 9000: v1 上限 20
    out.append(len(dcid))
    out += dcid
    # SCID（服务端自己的）
    sc = scid[:20]
    out.append(len(sc))
    out += sc
    # 支持的版本列表
    for v in supported_versions:
        out += struct.pack(">I", v)
    return bytes(out)


class RangeServer(threading.Thread):
    """
    QUIC 靶场服务端。

    mode 决定行为：
      "quic"    → 模拟真实 QUIC 服务端，对未知 version 回 VN
      "garbage" → 非 QUIC UDP 服务，回垃圾字节（应被判为非 QUIC）
      "silent"  → 静默丢弃，什么都不回（模拟 filtered）
    """

    def __init__(self, port: int, mode: str = "quic",
                 supported: list = None, host: str = "127.0.0.1"):
        super().__init__(daemon=True)
        self.port = port
        self.mode = mode
        self.supported = supported or [QUIC_V1, QUIC_V2]
        self.host = host
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 关键：SO_REUSEADDR 让"端口关闭"场景可测（重绑同一端口）
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.settimeout(0.5)
        self.running = True
        self.stats = {"recv": 0, "vn_sent": 0, "garbage_sent": 0}

    def run(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            self.stats["recv"] += 1
            if self.mode == "silent":
                continue

            parsed = parse_long_header(data)

            if self.mode == "garbage":
                # 回 32 字节随机垃圾 —— 客户端应判为"有响应但非 QUIC"
                self.sock.sendto(bytes(range(32)), addr)
                self.stats["garbage_sent"] += 1
                continue

            # mode == "quic"
            if not parsed.get("valid"):
                # 不是长包头 → 按 RFC 要求回 VN + 状态错误
                self.sock.sendto(
                    build_version_negotiation(self.supported), addr)
                self.stats["vn_sent"] += 1
                continue

            if parsed.get("version") in self.supported:
                # 支持的版本 → 真实服务端会回 Initial/Handshake 加密包
                # 原型里我们返回一个"看起来像 Handshake 长包头"的字节串
                resp = bytearray()
                resp.append(0xE0)                      # 长包头 + Handshake type
                resp += struct.pack(">I", parsed["version"])
                resp += bytes(range(8))                # 伪 DCID
                self.sock.sendto(bytes(resp), addr)
                self.stats["vn_sent"] += 1
            else:
                # ⭐ 未知/greased version → 必须回 Version Negotiation
                # ⭐ 回显客户端的 DCID/SCID（真实 quic-go 就是这么做的，
                #   这一点是本次原型实测抓包校准的关键）
                self.sock.sendto(
                    build_version_negotiation(
                        self.supported,
                        echo_dcid=parsed.get("dcid", b"\x00" * 8),
                        scid=bytes(range(8)),
                    ),
                    addr,
                )
                self.stats["vn_sent"] += 1

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass


def free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


if __name__ == "__main__":
    # 自检：直接启动一个 quic 模式服务端并打印端口
    port = free_udp_port()
    srv = RangeServer(port, "quic")
    srv.start()
    print(f"[靶场] QUIC 模式服务端已启动 127.0.0.1:{port}/udp")
    print(f"       支持版本: {['0x%08x' % v for v in srv.supported]}")
    print("       Ctrl+C 停止")
    try:
        while True:
            time.sleep(1)
            print(f"       recv={srv.stats['recv']} vn_sent={srv.stats['vn_sent']}")
    except KeyboardInterrupt:
        srv.stop()
        print("\n[靶场] 已停止")
