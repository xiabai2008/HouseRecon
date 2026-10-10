# quicprobe — QUIC / UDP-443 探活（Go 版）

屋勘 HouseRecon 的 QUIC 探活模块。**零外部依赖**，单 exe 4.8MB。

## 原理（一句话）

QUIC 长包头的 **Version 字段是明文**（偏移 1..4）。发一个带**保留版本号**的 Initial 包，
服务端发现版本不支持时会回 **Version Negotiation（VN）** 包，其 Version 恒为
`0x00000000`。⭐ **VN 在解密之前就发出，所以探测不需要任何加密计算** —— 只拼 20 字节明文头。

这一招绕开了 UDP 扫描"无响应 = open\|filtered 无法区分"的原罪：
**收到 VN 包是确定性证据。**

## 编译

```bash
# 需要 Go 1.24+
go build -o wukan-quic.exe ./cmd/quicprobe
```

## 用法

```bash
# 单目标
./wukan-quic.exe -t example.com -v
./wukan-quic.exe -t 127.0.0.1:14430

# 批量
./wukan-quic.exe -f targets.txt -o result.json -w 32
./wukan-quic.exe -f targets.txt --csv        # 供 Excel 打开

# 提高可靠性（网络抖动时必用）
./wukan-quic.exe -t example.com -probes 4 --timeout 4s

# 内置自测（不依赖网络）
./wukan-quic.exe -selftest
```

### 主要参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-t` | — | 单目标 `host` / `ip` / `host:port` / URL |
| `-f` | — | 目标文件，每行一个（`#` 开头为注释） |
| `-p` | 443 | 默认端口 |
| `-w` | 32 | 并发数 |
| `--timeout` | 3s | 单包超时 |
| `-probes` | 2 | 每目标发几个包（轮换不同 version） |
| `-o` | — | 输出 JSON |
| `--csv` | — | 输出 CSV |
| `-no-raw` | 关 | 不保留原始响应 hex（减小输出） |
| `-v` | 关 | 详细输出 + 进度条 |
| `-selftest` | — | 内置自测 |

## ⭐ 置信度机制（重要）

实测（2026-10-04，28 个国内站点，每目标 8 轮重复）发现**同一目标的判定会因 UDP 丢包波动**：

| 目标 | 8 轮确认次数 | 置信度表现 |
|---|---|---|
| www.toutiao.com | 8/8 | conf=65~100（稳定） |
| www.sina.com.cn | 7/8 | conf=15~65（抖动大） |
| www.xiaohongshu.com | 0/8 | 零证据 |

所以**不能只输出"确认/不确认"**。本工具同时输出：

```
[QUIC] www.sina.com.cn:443 25.27ms  2/4确认 conf=40 v=0x00000001 [QUIC v1]
        └── 4 个包里只有 2 个收到 VN，置信度 40
```

**置信度评分规则**：

| 情形 | 分数 |
|---|---|
| 全部包确认 | 100 |
| 3/4 确认 | 75-10=65 |
| 2/4 确认 | 50-10=40 |
| 1/4 确认 | 25-10=15 |
| 有响应但非 QUIC | 15（结论确定但方向相反） |
| 完全无响应 | 0（UDP 原罪，零证据） |

**实践建议**：边界目标用 `-probes 4` 以上的设置；`conf < 40` 时结论应视为"疑似"。

## 判定状态

| 状态 | 含义 | 判据 |
|---|---|---|
| `QUIC_CONFIRMED` | ⭐ 确定：端口开且跑 QUIC | 至少 1 个包收到 VN |
| `NON_QUIC_RESP` | 端口开着，但不是 QUIC | 有响应但不符合 QUIC 特征 |
| `OPEN_FILTERED` | 无法区分 | 无响应（UDP 固有原罪） |

## ⭐ 国内自研 QUIC 栈识别

工具内置非 RFC 版本号映射（**教科书查不到，实测得来**）：

| 版本号 | ASCII | 归属 |
|---|---|---|
| `0x00000001` | — | QUIC v1 (RFC 9000) |
| `0x6B3343CF` | — | QUIC v2 (RFC 9369) |
| `0x51303339` | `"Q039"` | **腾讯自研** |
| `0x51303433` | `"Q043"` | 腾讯自研 |
| `0x51303434` | `"Q044"` | 腾讯自研 |
| `0x51303436` | `"Q046"` | 腾讯自研 |
| `0x51303530` | `"Q050"` | 腾讯自研 |
| `0xFF00001D` / `0xFF00001E` | — | **阿里自研** |
| `0x5AEA5A8A` | — | **字节跳动自研** |

野外实测的归属分布示例：

```
腾讯+draft-29+阿里+QUIC v1  4    （sohu/imooc/zhihu/cloud.tencent）
QUIC v1+阿里                6    （taobao/tmall/163/aliyun/1688/douyin）
QUIC v1+阿里+腾讯            2    （suning/toutiao）
QUIC v1                     1    （sina）
```

## ⚠️ 三条踩坑记录（都已固化为断言）

### 1. VN 包在 Version 之后还有 DCID/SCID 字段

```
flags(1) | Version=0(4) | DCID_Len(1) | DCID | SCID_Len(1) | SCID | 版本列表
                                                    ↑
                                     偏移 = 1+4+1+8+1+8 = 23
```

漏掉这两个字段会把 CID 字节误读成版本号。**自建靶场与探测器犯同一个错时两边会对上**，
所以 `S4` 断言用真实抓包的权威 hex 做交叉校验。

### 2. 不要对 VN 包的 flags 具体值做假设

实测 quic-go 每次探测的 flags 都不同（`0xc9`/`0xd2`/`0xea`/`0xff`）——
低 4 位 reserved 被填随机值作抗指纹。**只能断言 HeaderForm / FixedBit 位。**

### 3. QUIC 头不能用 `struct.pack` 定长拼接（Python 版踩过）

QUIC 长包头是**变长字段序列**，用定长结构体会弄乱布局：

```python
struct.pack(">IBBB", 0xC0, 0x00000000, 0, 0)
# 实际: 00 00 00 c0 00 00 00   ← flags 被挤到索引 3
```

Go 版对应的注意事项：`binary.BigEndian.PutUint32` 只用于**单个定长字段**（version），
flags 必须单独 `append`。

## 代码结构

```
quicprobe-go/
├── go.mod
├── quicprobe/
│   ├── probe.go        (763 行)  探测器本体：构造 / 解析 / 置信度 / 厂商识别
│   └── scan.go         (127 行)  并发扫描、目标加载、汇总
└── cmd/quicprobe/
    └── main.go         (486 行)  CLI + 内置自测
```

**零第三方依赖** —— 只用标准库（`net` / `encoding/binary` / `sync` / `time`）。

## 内置自测

```bash
./wukan-quic.exe -selftest
```

12 项，覆盖：
- 探测包布局（1200 字节 / flags / CID 长度）
- Version 字段在明文位置
- ⭐ **真实抓包 VN 解析**（用权威 hex 交叉校验偏移 23）
- ⭐ 截断 VN 包不 panic
- 短包头防假阳性
- greased version 回显防假阳性
- 响应过短优雅降级
- ⭐ 国内自研栈识别（腾讯 / 阿里 / 字节 / RFC v1）
- 混合厂商合并识别
- 目标解析（host:port / URL / 纯 IP / 注释）
- 超长 DCID 不 panic

## 已知局限

1. **`open|filtered` 是 UDP 的固有原罪**。本工具能把"确定开"从"可能开"里分离出来，
   但无法消除无响应的歧义。零证据时只报 `OPEN_FILTERED`，不做任何猜测。
2. **网络抖动影响判定**。已用置信度如实反映，但 `conf < 40` 的结论仍应视为"疑似"。
3. **只探 UDP/443**。其他 UDP 端口（DNS 53 / NTP 123 / SNMP 161）不在范围内 ——
   判据不同（它们不是 QUIC），且需要授权。
4. **reserved 版本号无法归属**。quic-go 等实现每次连接都会生成新的随机 reserved 版本，
   工具会标注为 `reserved (RFC 8999)` 而非猜测厂商。

## 交叉验证

Go 版与 Python 版（`../quic_probe.py`）对同一真实靶场判定完全一致：

```
[QUIC] 127.0.0.1:14430 3.27ms  3/3确认 conf=100 v=0x...,0x00000001,0x6b3343cf [QUIC v1+QUIC v2]
state=QUIC_CONFIRMED rtt=2.92ms  versions=0x00000001 0x... 0x6b3343cf
```

唯一差异是 reserved 版本号（每次随机，预期行为）。
