"""
QUIC 探活原型 — 真实 quic-go 靶场验证
=====================================

这是最强的一层验证：不用自建靶场，用**生产级 QUIC 实现**
（quic-go v0.48.2，经 Docker 起的真 HTTP/3 服务）作为被打目标。

为什么这层最硬：
  - 自建靶场可以"作弊"（我们自己的实现可能和探测器一起错）
  - 真实实现的行为由 RFC 9000 约束，且经过全球生产验证
  - ⭐ 本次验证**抓出了一个自建靶场测不出来的真 bug**：
    VN 包在 Version 之后还有 DCID/SCID 字段，漏掉会解析出垃圾版本。

运行前需先起容器：
  docker run -d --name wukan-quic-lab -p 14430:14430/udp \
    -v <repo>/prototype/quic/quicserver:/app -w /app \
    golang:1.24-alpine sh -c \
    "go mod edit -require=github.com/quic-go/quic-go@v0.48.2 && \
     go mod tidy >/dev/null 2>&1 && go run . 0.0.0.0:14430"
"""

import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quic_probe import (  # noqa: E402
    GREASED_VERSIONS, MIN_INITIAL_SIZE, ProbeResult, build_initial_packet,
    parse_quic_response, probe_quic,
)

QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF
TARGET = ("127.0.0.1", 14430)

PASS, FAIL = "PASS", "FAIL"
log = []


def check(name, cond, expect, got):
    st = PASS if cond else FAIL
    log.append(st)
    print(f"  [{st}] {'OK ' if cond else 'NG '}{name}")
    print(f"         期望: {expect}")
    print(f"         实得: {got}")
    print()
    return cond


def raw_probe(version=0x0A0A0A0A, timeout=5.0):
    """发一个探测包并返回 (原始响应, 解析结果)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_initial_packet(version), TARGET)
        data, _ = sock.recvfrom(4096)
        return data, parse_quic_response(data)
    finally:
        sock.close()


def r1_core():
    """R1: 核心判定 — 面对真实实现能否确认 QUIC"""
    print("R1  核心判定（真实 quic-go）")
    r = probe_quic(TARGET[0], TARGET[1], timeout=5.0, probes=3)
    return check(
        "真实 HTTP/3 服务端 → QUIC_CONFIRMED",
        r.state == ProbeResult.QUIC_CONFIRMED,
        "state=QUIC_CONFIRMED",
        f"state={r.state}, detail={r.detail}, rtt={r.rtt_ms:.2f}ms" if r.rtt_ms else f"state={r.state}",
    )


def r2_versions():
    """
    R2: 服务端版本列表解析
    ⚠️ 修正了一个错误的预期：quic-go 除了 v1/v2 还会通告一个
       保留版本 0x9a9a1a1a（RFC 8999 允许，reserved for testing）。
       早期断言"必须恰好等于 [v1,v2]"是错的 —— 真实现才是标准。
    """
    print("R2  服务端版本列表解析")
    data, info = raw_probe()

    vers = info.get("server_versions", [])
    has_v1 = QUIC_V1 in vers
    has_v2 = QUIC_V2 in vers
    # 关键：必须含 v1；含 v2（quic-go 默认支持双版本）
    ok = has_v1 and has_v2
    return check(
        "版本列表含 QUIC v1 (0x00000001) 与 v2 (0x6B3343CF)",
        ok,
        "含 0x00000001 与 0x6B3343CF（允许额外保留版本）",
        f"{['0x%08x' % v for v in vers]}",
    )


def r3_no_garbage():
    """
    R3 ⭐ 本次实测抓出的真 bug 就在这里
    早期实现在 version 之后直接读版本列表，漏掉 DCID/SCID 字段，
    导致把 CID 字节误读成版本（0x0808090a 之类）。
    """
    print("R3  ⭐ 版本列表无垃圾（VN 包 DCID/SCID 偏移正确性）")
    data, info = raw_probe()

    # 真实的偏移应为 23 = 1(flags) + 4(version) + 1(dcidLen) + 8(dcid)
    #                          + 1(scidLen) + 8(scid)
    expect_off = 23
    off = info.get("version_list_offset", -1)
    ok_offset = off == expect_off

    # 垃圾判定：版本列表里不应出现"看起来像我们探测包字节"的值
    # 我们的探测包 DCID 是 000102...0f，SCID 是 0809...0f
    our_dcid_prefix = 0x00010203
    our_scid_prefix = 0x08090A0B
    garbage = [v for v in info.get("server_versions", [])
               if (v & 0xFFFF0000) in (our_dcid_prefix, our_scid_prefix)]

    ok = ok_offset and not garbage
    return check(
        "版本列表偏移=23 且无 CID 字节被误读为版本",
        ok,
        f"offset={expect_off}, garbage=[]",
        f"offset={off}, garbage={['0x%08x' % g for g in garbage]}, "
        f"versions={['0x%08x' % v for v in info.get('server_versions', [])]}",
    )


def r4_field_layout():
    """
    R4: 逐字段核对 VN 包布局与 RFC 一致

    ⚠️ 修正了一个错误的断言（实测发现）：
       - flags 每次探测都在变（0xea / 0xff / 0xd2 / 0xc9 …）
         → quic-go 在 VN 包的 reserved 位（低 4 bit）填充**随机值**
           作抗指纹。这符合 RFC（reserved 位在 VN 包中无语义约束）。
         → 所以**不能断言 flags 的具体值，只能断言 HeaderForm/FixedBit 位**
       - DCID 回显值不能写死：VN 包的 DCID 字段携带的是
         服务端选择回显的 CID，可能等于我们发的 DCID。
         → 只能断言"长度合法（<=20）且非空"
    """
    print("R4  VN 包字段布局核对")
    data, _ = raw_probe()

    # flags: HeaderForm=1, FixedBit=1（type 与 reserved 位在 VN 包中无固定语义）
    flags = data[0]
    hf = (flags >> 7) & 1
    fb = (flags >> 6) & 1
    ok_flags = (hf == 1 and fb == 1)

    # version 必须为 0 —— ⭐ 这是 VN 包的唯一确定性标志
    ver = struct.unpack(">I", data[1:5])[0]
    ok_ver = (ver == 0)

    # DCID 长度必须合法（RFC 9000: v1 上限 20）
    dcid_len = data[5]
    ok_dcid_len = (0 <= dcid_len <= 20)

    # SCID 长度必须合法
    off6 = 6 + dcid_len
    scid_len = data[off6] if off6 < len(data) else -1
    ok_scid_len = (0 <= scid_len <= 20)

    # 总长自洽性：5 + 1 + dcid_len + 1 + scid_len + 4*n <= len(data)
    tail = len(data) - (off6 + 1 + scid_len)
    ok_len = (tail >= 0 and tail % 4 == 0)

    ok = ok_flags and ok_ver and ok_dcid_len and ok_scid_len and ok_len
    return check(
        "HeaderForm/FixedBit=1, Version=0, CID长度合法, 总长4字节自洽",
        ok,
        "HF=1 FB=1 ver=0x00000000, 0<=CID_Len<=20, tail%4==0",
        f"HF={hf} FB={fb} ver=0x{ver:08x} dcid_len={dcid_len} "
        f"scid_len={scid_len} tail={tail}(%4={tail % 4})",
    )


def r5_greased_rotation():
    """R5: 轮换多个 greased version，真实实现都应回 VN"""
    print("R5  多 greased version 轮换")
    oks = []
    details = []
    for v in GREASED_VERSIONS:
        r = probe_quic(TARGET[0], TARGET[1], timeout=5.0, probes=1)
        # 每次都用不同 version 重新发
        data, info = raw_probe(version=v)
        ok = info.get("is_version_negotiation", False)
        oks.append(ok)
        details.append(f"0x{v:08x}→{'VN' if ok else 'FAIL'}")
    return check(
        f"4 个不同 greased version 全部触发 VN",
        all(oks),
        "4/4 VN",
        f"{' '.join(details)}",
    )


def r6_true_negative():
    """
    R6 ⭐ 阴性对照：真实 quic-go 必须在"关掉"时正确返回 open|filtered
    打一个确实没 QUIC 的端口（Docker 未映射的其他端口）
    """
    print("R6  阴性对照 — 确实无 QUIC 的端口")
    # 同一个容器内 14430 是 QUIC，用一个未监听的端口
    r = probe_quic(TARGET[0], 14431, timeout=3.0, probes=2)
    ok = (not r.is_quic) and r.state == ProbeResult.OPEN_FILTERED
    return check(
        "未监听的端口 → OPEN_FILTERED（不得误报 QUIC）",
        ok,
        "state=OPEN_FILTERED, is_quic=False",
        f"state={r.state}, is_quic={r.is_quic}, detail={r.detail[:50]}",
    )


def r7_compliance():
    """R7: 我们的探测包本身是否 RFC 合规（真实服务端能接受）"""
    print("R7  探测包 RFC 合规性（真实服务端接受度）")
    pkt = build_initial_packet(GREASED_VERSIONS[0])
    ok_len = len(pkt) >= MIN_INITIAL_SIZE
    ok_dcid = pkt[5] <= 20
    ok_flag = pkt[0] == 0xC0
    # ⭐ 实证：真实 quic-go 收到我们的包必须回 VN（若不响应说明包不合法被丢弃）
    data, info = raw_probe()
    ok_resp = info.get("is_version_negotiation", False)
    ok = ok_len and ok_dcid and ok_flag and ok_resp
    return check(
        "1200字节/DCID<=20/flags=0xC0 且真实服务端确实响应 VN",
        ok,
        "全部合规且服务端响应",
        f"len={len(pkt)} dcid={pkt[5]} flag=0x{pkt[0]:02x} "
        f"server_responded_vn={ok_resp}",
    )


def r8_stability():
    """R8: 稳定性 — 连续 25 次探测一致性"""
    print("R8  稳定性 — 连续 25 次判定一致性")
    states = []
    rtts = []
    for _ in range(25):
        r = probe_quic(TARGET[0], TARGET[1], timeout=5.0, probes=1)
        states.append(r.state)
        if r.rtt_ms:
            rtts.append(r.rtt_ms)
    ok = len(set(states)) == 1 and states[0] == ProbeResult.QUIC_CONFIRMED
    avg = sum(rtts) / len(rtts) if rtts else 0
    return check(
        "25 次连续探测判定完全一致",
        ok,
        f"全部 QUIC_CONFIRMED，平均 RTT ~3ms",
        f"唯一状态={set(states)} n={len(states)} "
        f"平均RTT={avg:.2f}ms min={min(rtts):.2f} max={max(rtts):.2f}",
    )


def main():
    print("=" * 74)
    print("QUIC 探活 — 真实 quic-go v0.48.2 靶场验证")
    print(f"目标: {TARGET[0]}:{TARGET[1]}/udp")
    print("=" * 74)
    print()

    # 连通性预检
    try:
        raw_probe(timeout=5.0)
    except Exception as e:  # noqa: BLE001
        print(f"✗ 无法连接真实 QUIC 靶场: {type(e).__name__}: {e}")
        print("\n请先起容器：")
        print("  docker run -d --name wukan-quic-lab -p 14430:14430/udp \\")
        print("    -v <repo>/prototype/quic/quicserver:/app -w /app \\")
        print("    golang:1.24-alpine sh -c 'go mod edit "
              "-require=github.com/quic-go/quic-go@v0.48.2 && "
              "go mod tidy >/dev/null 2>&1 && go run . 0.0.0.0:14430'")
        return False
    print("✓ 靶场可达\n")

    tests = [r1_core, r2_versions, r3_no_garbage, r4_field_layout,
             r5_greased_rotation, r6_true_negative, r7_compliance, r8_stability]

    for t in tests:
        try:
            t()
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  [FAIL] NG {t.__name__}: {type(e).__name__}: {e}")
            traceback.print_exc()
            log.append(FAIL)
        print("-" * 74)

    npass = log.count(PASS)
    nfail = len(log) - npass
    print(f"\n结果: {npass} 通过 / {nfail} 失败  (共 {len(log)} 项)")
    print("=" * 74)
    return nfail == 0


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
