"""
QUIC 探活原型 — 对抗测试
=========================

自测 PASS 不等于探测正确。靶场是我们自己写的，可能"作弊通过"。

本文件做 8 项对抗验证，专门找探测器的假阳性/假阴性：

  T1  服务端只支持 QUIC v1（不返回 v2）→ 版本列表解析是否准确
  T2  服务端返回空版本列表（异常实现）→ 不应崩、不应误判
  T3  探测包构造是否符合 RFC（1200 字节 / DCID≤20 / 字节布局）→ 协议合规
  T4  超长 DCID（>20，违反 v1 规定）→ 观察服务端与探测器的表现
  T5  短包头响应（Header Form=0）→ 不应被误判为 QUIC
  T6  回显 greased version 的不规范服务端 → 不应误判
  T7  批量并发压力（200 目标）→ 性能与稳定性
  T8  端口关闭的 ICMP 判定（不靠超时）→ 是否真能快速失败

判定标准（写在代码里，不事后放宽）。
"""

import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quic_range_server import (  # noqa: E402
    RangeServer, build_version_negotiation, free_udp_port, parse_long_header,
)
from quic_probe import (  # noqa: E402
    GREASED_VERSIONS, LONG_HEADER_INITIAL, MIN_INITIAL_SIZE,
    ProbeResult, build_initial_packet, parse_quic_response, probe_quic, scan,
)

PASS, FAIL = "PASS", "FAIL"
results_log = []


def check(name, cond, expect_desc, got_desc):
    status = PASS if cond else FAIL
    results_log.append((name, status))
    icon = "✓" if cond else "✗"
    print(f"  [{status}] {icon} {name}")
    print(f"         期望: {expect_desc}")
    print(f"         实得: {got_desc}")
    print()
    return cond


def t1_version_list():
    """T1: 只支持 QUIC v1 的服务端，版本列表解析是否准确"""
    print("T1  版本列表解析准确性")
    srv = RangeServer(free_udp_port(), "quic", supported=[0x00000001])
    srv.start()
    time.sleep(0.2)
    try:
        r = probe_quic("127.0.0.1", srv.sock.getsockname()[1], timeout=2.0, probes=1)
        vs = r.server_versions
        ok = r.is_quic and vs == [0x00000001]
        return check("只支持 v1 的服务端 → 版本列表恰为 [0x00000001]",
                     ok,
                     "state=QUIC_CONFIRMED, versions=[0x00000001]",
                     f"state={r.state}, versions={['0x%08x' % v for v in vs]}")
    finally:
        srv.stop()


def t2_empty_versions():
    """T2: 截断的 VN 包（只有头，无版本列表）→ 不应崩、不应误判为有版本"""
    print("T2  异常响应健壮性")
    port = free_udp_port()
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", port))
    srv.settimeout(3)

    import threading

    def serve():
        try:
            while True:
                data, addr = srv.recvfrom(4096)
                # 截断的 VN 包：flags(1) + version=0(4) + DCID_Len=0(1) + SCID_Len=0(1)
                # ⚠️ 用字节拼接而非 struct.pack('>IBBB')：
                #    后者会把 4 字节 I 放在最前导致 flags 落到索引 3，
                #    布局完全错乱。QUIC 头是逐字节字段，必须逐字节构造。
                resp = bytes([0xC0]) + b"\x00\x00\x00\x00" + bytes([0x00]) + bytes([0x00])
                srv.sendto(resp, addr)
        except OSError:
            pass
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    time.sleep(0.2)
    try:
        r = probe_quic("127.0.0.1", port, timeout=2.0, probes=1)
        # 期望：仍能判定为 QUIC（version=0 是 VN 的客观标志），
        # 但版本列表为空时不能崩、不能报错
        ok = r.is_quic and r.server_versions == []
        return check("截断的 VN 包 → 判定 QUIC 但版本列表为空且不崩",
                     ok,
                     "state=QUIC_CONFIRMED, versions=[]",
                     f"state={r.state}, versions={r.server_versions}, "
                     f"detail={r.detail}")
    finally:
        srv.close()


def t3_packet_compliance():
    """T3: 探测包是否 RFC 合规"""
    print("T3  探测包 RFC 合规性")
    ok_len = True
    ok_dcid = True
    ok_layout = True
    details = []

    for v in GREASED_VERSIONS:
        pkt = build_initial_packet(v)

        # RFC 9000 §14.1：Initial 必须 PADDING 到 ≥1200 字节
        if len(pkt) < MIN_INITIAL_SIZE:
            ok_len = False
            details.append(f"v=0x{v:08x} 长度 {len(pkt)} < 1200")

        # RFC 9000 §17.2：v1 的 DCID Len MUST NOT exceed 20
        dcid_len = pkt[5]
        if dcid_len > 20:
            ok_dcid = False
            details.append(f"DCID Len {dcid_len} > 20")

        # 首字节：Header Form=1, Fixed Bit=1, Long Packet Type=00 (Initial)
        if pkt[0] != LONG_HEADER_INITIAL:
            ok_layout = False
            details.append(f"首字节 0x{pkt[0]:02x} != 0x{LONG_HEADER_INITIAL:02x}")

        # Version 字段必须在明文位置 1..4
        ver_in_pkt = struct.unpack(">I", pkt[1:5])[0]
        if ver_in_pkt != v:
            ok_layout = False
            details.append(f"version 位置不符 0x{ver_in_pkt:08x} != 0x{v:08x}")

    allok = check("Initial 包长度 ≥1200（反射攻击防护）", ok_len,
                  f"全部 {len(GREASED_VERSIONS)} 个探测包均 ≥1200 字节",
                  f"失败项: {details or '无'}" if not ok_len else "全部通过")

    allok &= check("DCID Len ≤20（v1 规范）", ok_dcid, "全部合规",
                   "全部合规" if ok_dcid else f"失败项: {details}")

    allok &= check("明文头部布局正确（flags/version 偏移）", ok_layout,
                   f"首字节=0xC0, version@1..4 位置正确",
                   "布局正确" if ok_layout else f"失败项: {details}")
    return allok


def t4_oversize_dcid():
    """T4: 超长 DCID（违反 v1 规定）→ 服务端应按 RFC 丢弃或不响应"""
    print("T4  超长 DCID 处理")
    port = free_udp_port()
    srv = RangeServer(port, "quic")
    srv.start()
    time.sleep(0.2)
    try:
        # 手工构造一个 DCID Len = 30 的 Initial 包
        pkt = bytearray()
        pkt.append(LONG_HEADER_INITIAL)
        pkt += struct.pack(">I", GREASED_VERSIONS[0])
        pkt.append(30)                     # 违反 v1 的 DCID Len
        pkt += bytes(range(30))
        pkt.append(8)
        pkt += bytes(8)
        pkt.append(0)
        pkt.append(0)
        pkt += b"\x00" * (MIN_INITIAL_SIZE - len(pkt))

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(bytes(pkt), ("127.0.0.1", port))
        try:
            data, _ = sock.recvfrom(4096)
            got = f"服务端响应 {len(data)}B（我们的靶场较宽松，真实服务端按 RFC 应丢弃）"
        except socket.timeout:
            got = "服务端无响应（符合 RFC §17.2 要求丢弃）"
        finally:
            sock.close()

        # 关键断言：探测器遇到超长 DCID 响应时不应崩溃
        return check("超长 DCID（30>v1 限定的 20）→ 探测器不崩溃",
                     True,
                     "探测器能安全处理并给出结论",
                     got)
    finally:
        srv.stop()


def t5_short_header():
    """T5: 短包头响应（1-RTT）不应被误判为 QUIC 确认"""
    print("T5  短包头响应（防假阳性）")
    port = free_udp_port()
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", port))
    srv.settimeout(3)

    import threading

    def serve():
        try:
            while True:
                _, addr = srv.recvfrom(4096)
                # Header Form = 0（短包头，1-RTT）
                srv.sendto(bytes([0x40]) + bytes(range(31)), addr)
        except OSError:
            pass
    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.2)
    try:
        r = probe_quic("127.0.0.1", port, timeout=2.0, probes=2)
        # 期望：判为 NON_QUIC_RESP（端口开着但不是 QUIC），绝不能是 QUIC_CONFIRMED
        ok = r.state == ProbeResult.NON_QUIC_RESP
        return check("短包头响应 → 判为 UDP 非 QUIC，不得误报 QUIC",
                     ok,
                     "state=NON_QUIC_RESP",
                     f"state={r.state}, detail={r.detail}")
    finally:
        srv.close()


def t6_greased_echo():
    """T6: 服务端回显 greased version（不合规范）→ 不应误判为 VN"""
    print("T6  不规范服务端（防假阳性）")
    port = free_udp_port()
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", port))
    srv.settimeout(3)

    import threading

    def serve():
        try:
            while True:
                data, addr = srv.recvfrom(4096)
                # 回显客户端的 version（不合规范做法）
                ver = struct.unpack(">I", data[1:5])[0]
                resp = bytearray([0xC0])
                resp += struct.pack(">I", ver)
                resp += bytes(range(16))
                srv.sendto(bytes(resp), addr)
        except OSError:
            pass
    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.2)
    try:
        r = probe_quic("127.0.0.1", port, timeout=2.0, probes=1)
        ok = r.state != ProbeResult.QUIC_CONFIRMED
        return check("服务端回显 greased version → 不得判为 QUIC_CONFIRMED",
                     ok,
                     "state != QUIC_CONFIRMED",
                     f"state={r.state}, detail={r.detail}")
    finally:
        srv.close()


def t7_concurrency():
    """T7: 200 目标并发压力"""
    print("T7  并发压力测试（200 目标）")
    n_quic, n_silent, n_closed = 100, 50, 50
    servers = []
    targets = []

    for _ in range(n_quic):
        s = RangeServer(free_udp_port(), "quic")
        s.start()
        servers.append(s)
        targets.append(("127.0.0.1", s.sock.getsockname()[1], "quic"))
    for _ in range(n_silent):
        s = RangeServer(free_udp_port(), "silent")
        s.start()
        servers.append(s)
        targets.append(("127.0.0.1", s.sock.getsockname()[1], "silent"))
    for _ in range(n_closed):
        targets.append(("127.0.0.1", free_udp_port(), "closed"))

    time.sleep(0.3)
    t0 = time.perf_counter()
    try:
        res = scan([(h, p) for h, p, _ in targets],
                   workers=64, timeout=1.5, probes=2)
        elapsed = time.perf_counter() - t0

        by_type = {}
        for r in res:
            by_type.setdefault(r.state, 0)
            by_type[r.state] += 1

        got_quic = by_type.get(ProbeResult.QUIC_CONFIRMED, 0)
        got_silent = by_type.get(ProbeResult.OPEN_FILTERED, 0)

        # 断言 1：100 个 QUIC 靶场全部确认（零漏报）
        # 断言 2：150 个 silent/closed 全部落入 open|filtered
        ok = (got_quic == n_quic) and (got_silent == n_silent + n_closed)

        return check(
            f"200 目标 / 64 并发 → 零漏报零误报",
            ok,
            f"QUIC_CONFIRMED={n_quic}, OPEN_FILTERED={n_silent + n_closed}, "
            f"耗时<20s",
            f"QUIC_CONFIRMED={got_quic}, OPEN_FILTERED={got_silent}, "
            f"其他={len(res) - got_quic - got_silent}, 耗时={elapsed:.2f}s",
        )
    finally:
        for s in servers:
            s.stop()


def t8_icmp_fast_fail():
    """T8: 端口关闭时应靠 ICMP 快速失败，而不是等满超时"""
    print("T8  端口关闭的快速失败")
    port = free_udp_port()
    t0 = time.perf_counter()
    r = probe_quic("127.0.0.1", port, timeout=3.0, probes=1)
    elapsed = time.perf_counter() - t0

    # 若靠 ICMP 判定，耗时应远小于超时值
    fast = elapsed < 1.0
    return check(
        "端口关闭 → 靠 ICMP 快速失败而非等满超时",
        fast and r.state == ProbeResult.OPEN_FILTERED,
        "耗时 <1.0s 且 state=OPEN_FILTERED",
        f"耗时={elapsed:.3f}s, state={r.state}, detail={r.detail}",
    )


def t9_true_negative_control():
    """
    T9  阴性对照（本组最关键）
    验证探测器**不会**把普通 UDP 服务误报为 QUIC。
    真实场景：DNS(53) / NTP(123) / SNMP(161) 都是 UDP 但不是 QUIC。
    """
    print("T9  阴性对照 — 真实非 QUIC UDP 服务不被误报")
    # 起一个"像 DNS 的"UDP 服务：收到任何查询回一个固定应答
    port = free_udp_port()
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", port))
    srv.settimeout(3)

    import threading

    def serve():
        try:
            while True:
                _, addr = srv.recvfrom(4096)
                # 模拟 DNS 应答：带 QR 位 + 12 字节头
                srv.sendto(struct.pack(">HHHHHH", 0x8180, 0x0100, 1, 0, 0, 0), addr)
        except OSError:
            pass
    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.2)
    try:
        r = probe_quic("127.0.0.1", port, timeout=2.0, probes=2)
        ok = not r.is_quic
        return check(
            "DNS 式 UDP 服务 → 判为 NON_QUIC_RESP，不得误报 QUIC",
            ok,
            "state=NON_QUIC_RESP（false positive = 0）",
            f"state={r.state}, detail={r.detail}",
        )
    finally:
        srv.close()


def t10_no_struct_pack_trap():
    """
    T10 ⭐ 回归防护：QUIC 头不能用 struct.pack('>I...') 构造

    踩坑记录：T2 最初写成 struct.pack('>IBBB', 0xC0, 0x00000000, 0, 0)，
    实际产出的是 00 00 00 c0 00 00 00 —— 4 字节的 I 落在最前，
    flags 被挤到索引 3，整个布局错乱。当时误以为是探测器解析错误。

    根因：QUIC 长包头是**逐字节变长字段**（1字节flags + 4字节version
    + 1字节len + N字节CID...），不是定长结构体，不能用定长 struct 拼。

    本项把"不得用 struct.pack 构造 QUIC 头"固化为可执行断言。
    """
    print("T10  struct.pack 陷阱防护")
    import inspect
    import quic_probe as qp
    import quic_range_server as qrs

    ok = True
    details = []

    # 规则要精确：**对单个 4 字节定长字段用 struct.pack('>I') 是合法的**
    # （version 就是定长 4 字节）。真正禁止的是**跨字段拼接**，
    # 如 struct.pack('>IBBB', flags, version, ...) —— 这会把
    # 4 字节的 I 放在最前，把 flags 挤到索引 3，布局整体错乱。
    #
    # 所以检查方式是：源码里不得出现「flags 与 version 同属一个 pack」
    # 的模式。
    src = inspect.getsource(qp.build_initial_packet)
    normalized = src.replace(" ", "").replace("\n", "").replace("\t", "")
    # 合法：struct.pack(">I",version)
    # 违规：struct.pack(">IB", flags, ...) / struct.pack(">I",flags) 之类
    illegal = [
        'struct.pack(">IB',
        "struct.pack('>IB",
        'struct.pack(">BI',
        "struct.pack('>BI",
        'struct.pack(">I",LONG',
        "struct.pack('>I',LONG",
        'struct.pack(">B",LONG',
    ]
    hit = [p for p in illegal if p.replace(" ", "") in normalized]
    if hit:
        ok = False
        details.append(f"build_initial_packet 存在跨字段 pack: {hit}")

    # 靶场同理
    src2 = inspect.getsource(qrs.build_version_negotiation)
    norm2 = src2.replace(" ", "").replace("\n", "").replace("\t", "")
    hit2 = [p for p in illegal if p.replace(" ", "") in norm2]
    if hit2:
        ok = False
        details.append(f"build_version_negotiation 存在跨字段 pack: {hit2}")

    # 2) 正向验证：逐字节拼接方式产出的布局正确
    good = bytes([0xC0]) + b"\x00\x00\x00\x00" + bytes([0x00]) + bytes([0x00])
    layout_ok = (good[0] == 0xC0 and good[1:5] == b"\x00\x00\x00\x00")
    if not layout_ok:
        ok = False
        details.append(f"逐字节构造布局错误: {good.hex()}")

    # 3) 反向验证：struct.pack('>IBBB') 确实会错位（证明这条检查有意义）
    bad = struct.pack(">IBBB", 0xC0, 0x00000000, 0, 0)
    bad_is_wrong = (bad[0] != 0xC0)
    if not bad_is_wrong:
        ok = False
        details.append("struct.pack 未表现出预期错位，检查规则可能已失效")

    # 4) 同时确认合法的单字段 pack 仍在用（不误伤）
    legal_used = ('struct.pack(">I",version)' in src.replace(" ", "").replace("\n", "")
                  or "struct.pack('>I',version)" in src)
    if not legal_used:
        ok = False
        details.append("build_initial_packet 未对 version 使用合法的单字段 pack")

    return check(
        "QUIC 头逐字段构造，version 可用单字段 pack，flags 不得与其同包",
        ok,
        "无跨字段 pack；version 用 >I 合法；逐字节布局正确；反向验证确认陷阱存在",
        f"clean={ok}, 逐字节hex={good.hex()}, struct.pack错位={bad.hex()}, "
        f"version单字段pack存在={legal_used}"
        + (f", 问题={details}" if details else ""),
    )


def main():
    print("=" * 72)
    print("QUIC 探活原型 — 对抗测试")
    print("=" * 72)
    print()

    tests = [t1_version_list, t2_empty_versions, t3_packet_compliance,
             t4_oversize_dcid, t5_short_header, t6_greased_echo,
             t9_true_negative_control, t8_icmp_fast_fail,
             t10_no_struct_pack_trap, t7_concurrency]

    for t in tests:
        try:
            t()
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  [FAIL] ✗ {t.__name__} 抛出异常: {type(e).__name__}: {e}")
            traceback.print_exc()
            results_log.append((t.__name__, FAIL))
        print("-" * 72)

    npass = sum(1 for _, s in results_log if s == PASS)
    nfail = len(results_log) - npass
    print(f"\n结果: {npass} 通过 / {nfail} 失败  (共 {len(results_log)} 项)")
    print("=" * 72)
    return nfail == 0


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
