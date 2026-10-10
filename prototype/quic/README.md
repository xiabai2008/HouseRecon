# QUIC 探活原型

QUIC / UDP-443 探活技术的可行性原型与验证代码。

## 核心原理

QUIC 长包头的 Version 字段是**明文**（偏移 1..4，32bit）。发一个带**保留版本号**的
Initial 包，服务端发现版本不支持时会回 **Version Negotiation** 包（Version 字段恒为
`0x00000000`）—— 且 VN 包在**解密之前**发出，所以探测**不需要任何加密计算**。

判定依据是确定性的，绕开了 UDP 扫描 `open|filtered` 无法区分的原罪。

协议依据：RFC 9000 §14.1（PADDING 防护）、§17.2（长包头 / VN 包）、RFC 8999（保留版本）。

## 文件

| 文件 | 作用 |
|---|---|
| `quic_probe.py` | 探测器本体（CLI + 库） |
| `quic_range_server.py` | 本地四态靶场服务端（quic / garbage / silent / closed） |
| `test_adversarial.py` | 对抗测试 12 项（含防假阳性、阴性对照、并发压测） |
| `test_real_quic.py` | 真实 quic-go 靶场验证 8 项 |
| `quicserver/main.go` | 真实 HTTP/3 靶场（quic-go v0.48.2，需 Docker） |
| `field_test_result.json` | 28 个国内站点的野外实测结果 |

## 快速开始

```bash
# 1. 本地自测（无需额外依赖）
python quic_probe.py --selftest

# 2. 对抗测试
python test_adversarial.py

# 3. 单目标探测
python quic_probe.py -t 127.0.0.1:14430 -v

# 4. 批量扫描
python quic_probe.py -f targets.txt -o result.json -w 32
```

## 真实靶场（可选，最强验证）

```bash
docker run -d --name wukan-quic-lab -p 14430:14430/udp \
  -v "$(pwd)/quicserver:/app" -w /app \
  golang:1.24-alpine sh -c \
  "go mod edit -require=github.com/quic-go/quic-go@v0.48.2 && \
   go mod tidy >/dev/null 2>&1 && go run . 0.0.0.0:14430"

# 等待 20 秒让 quic-go 编译完成，然后：
python test_real_quic.py

# 清理
docker rm -f wukan-quic-lab
```

> **Git Bash on Windows** 若报 `working directory is invalid`，前置
> `export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"`。

## 判定状态

| 状态 | 含义 | 判定依据 |
|---|---|---|
| `QUIC_CONFIRMED` | ⭐ 确定：端口开且跑 QUIC | 收到 VN 包（version==0） |
| `NON_QUIC_RESP` | 端口开着，但不是标准 QUIC | 有响应但不符合 QUIC 特征 |
| `OPEN_FILTERED` | 无法区分 open / filtered | 无响应，或 ICMP 不可达 |

## ⚠️ 踩坑记录（三条，都已固化为测试断言）

### 1. VN 包在 Version 之后还有 DCID/SCID 字段

```
flags(1) | Version=0(4) | DCID_Len(1) | DCID | SCID_Len(1) | SCID | 版本列表
                                                            ↑
                                            真实偏移 = 1+4+1+8+1+8 = 23
```

漏掉这两个字段会把 CID 字节误读成版本号（实测得到 `0x0808090a` 这类垃圾）。
**自建靶场和探测器犯同一个错时两边会对上 —— 所以必须用真实实现验证。**

### 2. 不要对 VN 包的 flags 位做假设

quic-go 每次探测的 flags 都不同（实测 `0xc9` / `0xd2` / `0xea` / `0xff`）——
低 4 位 reserved 被填了随机值作抗指纹。**只能断言 HeaderForm / FixedBit 位。**

### 3. QUIC 头不能用 `struct.pack` 定长拼接

```python
struct.pack(">IBBB", 0xC0, 0x00000000, 0, 0)
# 实际: 00 00 00 c0 00 00 00   ← flags 被挤到索引 3，布局全错
```

QUIC 长包头是逐字节变长字段，不是定长结构体。必须逐字节 append。
**`struct.pack(">I", version)` 对 version 单字段是合法的**，禁止的是跨字段拼接。

## 已知局限

- **`open|filtered` 仍是 UDP 的固有原罪**。本工具的价值在于能把"确定开"从"可能开"里
  分离出来，无法消除无响应的歧义。
- **本机公网 UDP/443 不可达**（Cloudflare / Google 全部无响应），但国内站点可达。
  若要测公网，建议选国内目标。
- **版本号映射表尚未建立**。实测发现国内自研栈会通告非 RFC 版本号
  （腾讯 `0x51303339` = ASCII `"Q039"`、阿里 `0xff00001d`、字节 `0x5aea5a8a`），
  工具需要能识别这些而不是报"未知"。

## 验证结论

三层靶场，24 项断言，零失败：

| 层 | 内容 | 结果 |
|---|---|---|
| 真实生产级 | quic-go v0.48.2 HTTP/3 服务 | 8/8 PASS |
| 野外真实 | 28 个国内大站 | 14 确认 QUIC，0 误报，6.05s |
| 本地可控 | 四种响应状态 | 4/4 PASS |
| 对抗 | 防假阳性 / 阴性对照 / 并发 | 12/12 PASS |

性能：200 目标 / 64 并发 = **3.05s**，100 个 QUIC + 100 个 silent，零漏报零误报。

详见 `../../doc/项目规划/QUIC探活原型验证报告.md`。
