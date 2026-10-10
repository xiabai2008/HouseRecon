"""
QUIC 探活探测器 — 原型
======================

验证核心假设：能否在不发送任何加密载荷的前提下，确定 UDP 端口是否运行 QUIC。

判定依据（RFC 9000 §17.2.1）：
  1. 发送 Initial 包，version 填保留号（如 0x0a0a0a0a）
  2. 收到响应且首字节长包头位=1，且 version 字段 == 0x00000000
     → 这是 Version Negotiation 包 → **端口确定开着且跑 QUIC**
  3. 收到响应但不是 VN 包 → 端口开着，但不是标准 QUIC（需进一步判断）
  4. 无响应 → open|filtered，无法区分（UDP 的固有原罪）

⚠️ 这个探测器**不做任何加密计算** —— VN 包在解密之前就发出。

用法：
    python quic_probe.py -t 127.0.0.1:14430
    python quic_probe.py -f hosts.txt
    python quic_probe.py --selftest      # 跑本地靶场自测
"""

import argparse
import os
import re
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── QUIC 常量 ──────────────────────────────────────────────
QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF

# 保留版本号（greased version）—— 真实服务端遇到必须回 VN
# 依据 RFC 8999（QUIC Version Negotiation / 保留版本）
GREASED_VERSIONS = [0x0A0A0A0A, 0x1A2A3A4A, 0x2A2A2A2A, 0xFACEB00C]

# 长包头首字节：Header Form=1, Fixed Bit=1, Long Packet Type=00 (Initial)
LONG_HEADER_INITIAL = 0xC0

# Initial 包的最小长度（RFC 9000 §14.1，反射攻击防护）
MIN_INITIAL_SIZE = 1200

# QUIC 报文类型（长包头）
PKT_INITIAL   = 0x00
PKT_0RTT      = 0x01
PKT_HANDSHAKE = 0x02
PKT_RETRY     = 0x03

VER = "wukan-quic-probe/0.1.0"


class ProbeResult:
    """单次探测的判定结果。"""

    # 判定状态
    QUIC_CONFIRMED = "QUIC_CONFIRMED"       # ⭐ 确定：收到 VN 包 → 端口开且跑 QUIC
    NON_QUIC_RESP = "NON_QUIC_RESP"         # 有响应但非标准 QUIC → 端口开着
    OPEN_FILTERED = "OPEN_FILTERED"         # 无响应 → open|filtered 无法区分
    TIMEOUT = "TIMEOUT"                     # 超时（等价 OPEN_FILTERED）

    def __init__(self, host, port, state, rtt_ms=None,
                 detail="", server_versions=None, latency_buckets=None):
        self.host = host
        self.port = port
        self.state = state
        self.rtt_ms = rtt_ms
        self.detail = detail
        self.server_versions = server_versions or []
        self.latency_buckets = latency_buckets or {}

    @property
    def is_quic(self):
        return self.state == self.QUIC_CONFIRMED

    def to_dict(self):
        return {
            "host": self.host,
            "port": self.port,
            "state": self.state,
            "rtt_ms": round(self.rtt_ms, 2) if self.rtt_ms else None,
            "server_versions": self.server_versions,
            "detail": self.detail,
        }

    def __str__(self):
        icon = {
            self.QUIC_CONFIRMED: "[QUIC]",
            self.NON_QUIC_RESP:  "[UDP ]",
            self.OPEN_FILTERED: "[?   ]",
            self.TIMEOUT:       "[TIME]",
        }.get(self.state, "[????]")
        vs = ""
        if self.server_versions:
            vs = " v=" + ",".join("0x%08x" % v for v in self.server_versions[:3])
        rtt = f" {self.rtt_ms:.1f}ms" if self.rtt_ms else ""
        return f"{icon} {self.host}:{self.port}{rtt}{vs}  {self.detail}"


def build_initial_packet(version: int, dcid_len: int = 8) -> bytes:
    """
    构造一个 QUIC Initial 包的"探测头"。

    ⚠️ 关键设计：我们只构造**明文头部**，不构造加密载荷。
      这足以触发 Version Negotiation（VN 在解密前发出）。
      如果不填充到 1200 字节，某些服务端可能因长度校验直接丢弃。
    """
    out = bytearray()
    out.append(LONG_HEADER_INITIAL)              # 1 byte  flags
    out += struct.pack(">I", version)            # 4 bytes version（明文）
    out.append(dcid_len)                         # 1 byte  DCID Len
    out += bytes(range(dcid_len))                # DCID
    out.append(8)                                # 1 byte  SCID Len
    out += bytes(range(8, 16))                   # SCID
    out.append(0)                                # varint token_length = 0
    # Length 字段（varint）：声明后续长度，这里填 0
    out.append(0)
    # PADDING 填充到 1200 字节（RFC 9000 §14.1 反射攻击防护要求）
    if len(out) < MIN_INITIAL_SIZE:
        out += b"\x00" * (MIN_INITIAL_SIZE - len(out))
    return bytes(out)


def parse_quic_response(data: bytes) -> dict:
    """
    解析响应包，只读明文头部。**不解密任何内容。**

    ⭐ 布局依据 RFC 9000 §17.2（**这里踩过坑，已用真实 quic-go 抓包校准**）：

        Version Negotiation 包：
          [0]      1 byte   flags
          [1..5]   4 bytes  Version = 0x00000000   ← VN 的唯一标志
          [5]      1 byte   DCID Len (n)
          [6..6+n] n bytes  DCID   （服务端回显客户端的 CID）
          [6+n]    1 byte   SCID Len (m)
          [..]     m bytes  SCID   （服务端自己的 CID）
          之后      4 bytes × N  服务端支持的版本列表

        ⚠️ 常见错误：以为 version 之后直接就是版本列表。
           实际还有 DCID/SCID 字段，会把 CID 字节误读成版本号。
           这在真实 quic-go 上表现为解析出 0x0808090a 这类垃圾版本。
    """
    if len(data) < 5:
        return {"ok": False, "reason": "response_too_short", "len": len(data)}

    flags = data[0]
    header_form = (flags >> 7) & 0x01
    fixed_bit = (flags >> 6) & 0x01
    packet_type = (flags >> 4) & 0x03
    reserved_bits = flags & 0x0F

    # 短包头（Header Form=0）→ 1-RTT 加密包，无法判断
    if header_form == 0:
        return {
            "ok": True,
            "header_form": 0,
            "is_short_header": True,
            "raw_len": len(data),
        }

    version = struct.unpack(">I", data[1:5])[0]

    info = {
        "ok": True,
        "header_form": 1,
        "fixed_bit": fixed_bit,
        "packet_type": packet_type,
        "reserved_bits": reserved_bits,
        "version": version,
        "raw_len": len(data),
    }

    # ⭐ 核心判定：Version Negotiation 包的 version 字段恒为 0
    #
    # ⚠️ 实测校准（真实 quic-go v0.48.2）：不要对 VN 包的其它位做假设。
    #   - flags 每次探测都不同（实测 0xc9 / 0xd2 / 0xea / 0xff …）
    #     因为 quic-go 在低 4 位 reserved 里填随机值作抗指纹。
    #     RFC 9000 明确：VN 包的 Long Packet Type 与 reserved 位
    #     语义未定义，客户端必须忽略。
    #   - DCID 字段携带的是服务端选择回显的 CID，值不可预测。
    #
    #   → **唯一确定性判据就是 version == 0x00000000**
    if version != 0:
        info["is_version_negotiation"] = False
        # 判断是不是我们发的 greased version 被原样回显（异常情况）
        info["echo_of_greased"] = version in GREASED_VERSIONS
        return info

    # ── 以下为 Version Negotiation 包解析 ──
    info["is_version_negotiation"] = True

    off = 5
    # DCID
    if off >= len(data):
        info["server_versions"] = []
        info["parse_error"] = "truncated_before_dcid_len"
        return info
    dcid_len = data[off]
    off += 1
    if dcid_len > 20:
        # RFC 9000: 收到 v1 长包头且 DCID Len > 20 必须丢弃
        info["server_versions"] = []
        info["parse_error"] = f"dcid_len={dcid_len} exceeds 20"
        return info
    dcid = data[off:off + dcid_len]
    off += dcid_len

    # SCID
    scid = b""
    if off < len(data):
        scid_len = data[off]
        off += 1
        if scid_len <= 20:
            scid = data[off:off + scid_len]
            off += scid_len

    info["echoed_dcid"] = dcid.hex()
    info["server_scid"] = scid.hex()

    # 剩下的才是版本列表（每 4 字节一个）
    body = data[off:]
    vers = []
    for i in range(0, len(body) - 3, 4):
        vers.append(struct.unpack(">I", body[i:i + 4])[0])
    info["server_versions"] = vers
    # 保留原始尾部，便于事后核对解析是否正确
    info["version_list_offset"] = off

    return info


def classify_response(info: dict) -> str:
    """
    把解析结果映射为**语义正确**的描述文本。

    ⚠️ 这里修的是一个真实的缺陷：
       任意 UDP 响应只要首字节 bit7=1（长包头位）就会被识别成
       "QUIC 长包头"。真实场景中 DNS 应答、NTP 应答、SNMP 应答
       都可能碰巧满足这个位条件。判定逻辑本身是对的
       （version != 0 → 不是 VN → 不确认 QUIC），
       但**报告文本不能说"收到 QUIC Initial"** —— 那是误导。

    正确做法：只有当 Version 字段落在 QUIC 已知版本号范围内，
    或结构符合 QUIC 长包头布局（DCID Len ≤20 且长度自洽），
    才敢称其为 QUIC；否则一律称为"高位为 1 的未知 UDP 响应"。
    """
    if not info.get("ok"):
        return "无法解析"
    if info.get("is_short_header"):
        return "短包头响应（1-RTT 加密负载）"
    if info.get("is_version_negotiation"):
        return "收到 Version Negotiation（version=0x00000000）"

    ver = info.get("version", 0)
    # QUIC 已知版本号集合（RFC 9000 v1 / RFC 9369 v2 / 常见 gQUIC）
    KNOWN_QUIC_VERSIONS = {
        0x00000001,  # v1
        0x6B3343CF,  # v2 (RFC 9369)
        0x1A2A3A0A,  # 早期 draft
        0xFF00001B,  # 一些实现
    }
    if ver in KNOWN_QUIC_VERSIONS:
        pk = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
        pkname = pk.get(info.get("packet_type"), f"type={info.get('packet_type')}")
        return f"QUIC {pkname} 长包头 version=0x{ver:08x}"

    if info.get("echo_of_greased"):
        return f"服务端回显了 greased version 0x{ver:08x}（不合规范）"

    # ⭐ 兜底：长包头位为 1 但版本号不在 QUIC 命名空间
    #   典型场景：DNS / NTP / SNMP 等非 QUIC UDP 服务的应答
    #   碰巧首字节 bit7=1。**绝不能称为 QUIC。**
    return (f"未知 UDP 响应（首字节长包头位=1 但 version=0x{ver:08x} "
            f"不在 QUIC 版本空间，判定为非 QUIC）")


def probe_quic(host: str, port: int = 443, timeout: float = 3.0,
               probes: int = 2) -> ProbeResult:
    """
    探测单个 host:port 是否运行 QUIC。

    策略：发 probes 个不同 greased version 的 Initial 包（轮换），
    任何一个收到 VN 包即判定为 QUIC_CONFIRMED。
    轮换是为了排除某些服务端只缓存首个包的情况。
    """
    probes = max(1, probes)
    first_rtt = None
    last_detail = ""
    responses = 0

    for i in range(probes):
        version = GREASED_VERSIONS[i % len(GREASED_VERSIONS)]
        pkt = build_initial_packet(version)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            t0 = time.perf_counter()
            sock.sendto(pkt, (host, port))
            data, _ = sock.recvfrom(4096)
            rtt = (time.perf_counter() - t0) * 1000
            sock.close()

            if first_rtt is None:
                first_rtt = rtt

            responses += 1
            info = parse_quic_response(data)

            # ⭐ 收到 Version Negotiation → 确定判定
            if info.get("is_version_negotiation"):
                return ProbeResult(
                    host, port, ProbeResult.QUIC_CONFIRMED,
                    rtt_ms=first_rtt,
                    detail="收到 Version Negotiation（version=0x00000000）",
                    server_versions=info.get("server_versions", []),
                )

            # 有响应但不是 VN
            last_detail = classify_response(info)

        except socket.timeout:
            last_detail = "无响应（UDP open|filtered 无法区分）"
        except ConnectionRefusedError:
            return ProbeResult(host, port, ProbeResult.OPEN_FILTERED,
                               detail="ICMP port unreachable — 端口关闭")
        except OSError as e:
            last_detail = f"网络错误 {type(e).__name__}: {e}"
        except Exception as e:  # noqa: BLE001
            last_detail = f"探测异常 {type(e).__name__}: {e}"
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001, S110
                pass

    # 所有探测都没拿到 VN，但有响应 → 端口开着但不是标准 QUIC
    if responses > 0:
        return ProbeResult(host, port, ProbeResult.NON_QUIC_RESP,
                           rtt_ms=first_rtt,
                           detail=last_detail or f"{responses}/{probes} 有响应但非标准 QUIC")

    return ProbeResult(host, port, ProbeResult.OPEN_FILTERED,
                       rtt_ms=None, detail=last_detail)


# ── 批量扫描 ──────────────────────────────────────────────

IP_PORT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?$")


def parse_targets(lines):
    """解析目标：每行 host、host:port、ip、CIDR 不支持（本原型聚焦单点）"""
    out = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # 去掉 URL 前缀
        line = re.sub(r"^https?://", "", line).rstrip("/")
        line = line.split("/")[0] if "/" in line and "://" not in line else line
        m = IP_PORT_RE.match(line)
        if m:
            out.append((m.group(1), int(m.group(2) or 443)))
        else:
            out.append((line, 443))
    return out


def scan(targets, workers=16, timeout=3.0, probes=2):
    """并发批量探测"""
    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {
            ex.submit(probe_quic, h, p, timeout, probes): (h, p)
            for h, p in targets
        }
        for fut in as_completed(futs):
            h, p = futs[fut]
            try:
                results.append(fut.result())
            except Exception as e:  # noqa: BLE001
                results.append(ProbeResult(h, p, ProbeResult.TIMEOUT,
                                           detail=f"并发异常: {e}"))
    return sorted(results, key=lambda r: (not r.is_quic, r.host, r.port))


# ── 本地靶场自测 ──────────────────────────────────────────

def selftest():
    """
    跑一轮本地靶场自测，验证探测器在四种响应下的判定是否正确。

    场景：
      1. quic    模式 → 期望 QUIC_CONFIRMED
      2. garbage 模式 → 期望 NON_QUIC_RESP
      3. silent  模式 → 期望 OPEN_FILTERED
      4. 端口未监听       → 期望 OPEN_FILTERED（ICMP unreachable）
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from quic_range_server import RangeServer, free_udp_port

    print("=" * 72)
    print("QUIC 探活原型 — 本地靶场自测")
    print("=" * 72)

    cases = [
        ("quic",    "quic",    ProbeResult.QUIC_CONFIRMED, "真实 QUIC 服务端，应确认"),
        ("garbage", "garbage", ProbeResult.NON_QUIC_RESP,   "非 QUIC UDP 服务，应判 UDP"),
        ("silent",  "silent",  ProbeResult.OPEN_FILTERED,  "静默丢弃，应判 open|filtered"),
        ("closed",  None,      ProbeResult.OPEN_FILTERED,  "端口关闭，应判 open|filtered"),
    ]

    print("\n[1/2] 启动靶场服务端…")
    # 为前三个场景各起一个服务端；第四个场景故意不监听
    servers = []
    for name, mode, _, _ in cases:
        port = free_udp_port()
        if mode is None:
            print(f"  · {name:8s} → 127.0.0.1:{port}/udp  (不启动，端口关闭)")
            continue
        srv = RangeServer(port, mode)
        srv.start()
        servers.append(srv)
        print(f"  · {name:8s} → 127.0.0.1:{port}/udp  (mode={mode})")
    time.sleep(0.3)

    print("\n[2/2] 发起探测…\n")
    all_pass = True
    for idx, (name, mode, expect, desc) in enumerate(cases):
        if mode is None:
            # 端口关闭场景：故意用一个没监听的端口
            port = free_udp_port()
        else:
            # servers 按 cases 顺序启动，前三个场景与 servers 一一对应
            port = servers[idx].sock.getsockname()[1]

        r = probe_quic("127.0.0.1", port, timeout=2.0, probes=2)
        ok = (r.state == expect)
        all_pass &= ok
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] 场景 {name}")
        print(f"         目标     : 127.0.0.1:{port}/udp")
        print(f"         期望     : {expect}")
        print(f"         实得     : {r.state}")
        print(f"         说明     : {desc}")
        print(f"         细节     : {r.detail}")
        if r.server_versions:
            print(f"         服务版本 : " +
                  ", ".join("0x%08x" % v for v in r.server_versions))
        print()

    for s in servers:
        s.stop()

    print("=" * 72)
    print(f"自测结果: {'全部通过' if all_pass else '存在失败'}")
    print("=" * 72)
    return all_pass


# ── CLI ────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="QUIC / UDP-443 探活探测器（原型）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  %(prog)s -t 127.0.0.1:14430\n"
               "  %(prog)s -f hosts.txt --workers 32\n"
               "  %(prog)s --selftest\n",
    )
    ap.add_argument("-t", "--target", help="单个目标 host 或 host:port")
    ap.add_argument("-f", "--file", help="目标文件，每行一个")
    ap.add_argument("-p", "--port", type=int, default=443, help="端口（默认 443）")
    ap.add_argument("-w", "--workers", type=int, default=16, help="并发数")
    ap.add_argument("--timeout", type=float, default=3.0, help="单次超时秒数")
    ap.add_argument("--probes", type=int, default=2, help="发几个探测包（换 version）")
    ap.add_argument("-o", "--output", help="输出 JSON 文件")
    ap.add_argument("--selftest", action="store_true", help="跑本地靶场自测")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(0 if selftest() else 1)

    targets = []
    if args.target:
        targets = parse_targets([args.target])
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            targets += parse_targets(f.readlines())

    # 显式指定端口时覆盖
    if args.port != 443 and args.target and ":" not in args.target.split("//")[-1]:
        targets = [(t[0], args.port) for t in targets]

    if not targets:
        ap.print_help()
        sys.exit(2)

    if args.verbose:
        print(f"[{VER}] 目标 {len(targets)} 个 | 并发 {args.workers} "
              f"| 超时 {args.timeout}s | 每目标 {args.probes} 包")

    t0 = time.perf_counter()
    results = scan(targets, workers=args.workers,
                   timeout=args.timeout, probes=args.probes)
    elapsed = time.perf_counter() - t0

    quic = [r for r in results if r.is_quic]
    udp = [r for r in results if r.state == ProbeResult.NON_QUIC_RESP]
    unk = [r for r in results if r.state in
           (ProbeResult.OPEN_FILTERED, ProbeResult.TIMEOUT)]

    for r in results:
        print(str(r))

    print("-" * 72)
    print(f"共 {len(results)} 个目标 | 耗时 {elapsed:.2f}s")
    print(f"  ⭐ QUIC 已确认 : {len(quic)}")
    print(f"  ⚠ UDP 有响应  : {len(udp)}（非标准 QUIC）")
    print(f"  ? open|filtered: {len(unk)}（UDP 固有不确定性）")

    if quic:
        print("\n⭐ 结论：以下目标的 UDP/443 确定运行 QUIC —— "
              "传统 TCP-only 扫描器（naabu/httpx/Shodan）会完全漏掉它们")
        for r in quic:
            vs = " 支持 " + ",".join("0x%08x" % v for v in r.server_versions[:3]) if r.server_versions else ""
            print(f"   {r.host}:{r.port}{vs}")

    if args.output:
        import json
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump({
                "scanner": VER,
                "results": [r.to_dict() for r in results],
                "summary": {
                    "total": len(results),
                    "quic_confirmed": len(quic),
                    "udp_resp": len(udp),
                    "open_or_filtered": len(unk),
                },
            }, f, indent=2, ensure_ascii=False)
        print(f"\n已写入 {args.output}")


if __name__ == "__main__":
    main()
