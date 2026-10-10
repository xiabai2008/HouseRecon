# 屋勘 HouseRecon — 技术方案与实施计划

> **文档版本**：v1.0
> **撰写日期**：2026-10-04
> **前置依据**：《信息收集工具全景调研报告》（2026-10-03 核验）+ 附录 A/B/C
> **定位**：轻量化网络空间资产侦察与信息收集工具，低交互、静默、可追溯
> **CLI 名**：`wukan`

---

## 目录

- [第 0 章 核心判断：不要做什么](#第-0-章-核心判断不要做什么)
- [第 1 章 三个技术方案对比](#第-1-章-三个技术方案对比)
- [第 2 章 推荐方案：Go 内核 + 插件化采集器](#第-2-章-推荐方案go-内核--插件化采集器)
- [第 3 章 差异化设计：四个不可替代的能力](#第-3-章-差异化设计四个不可替代的能力)
- [第 4 章 数据模型与存储设计](#第-4-章-数据模型与存储设计)
- [第 5 章 合规硬约束（写进代码而不是写进 README）](#第-5-章-合规硬约束写进代码而不是写进-readme)
- [第 6 章 实施路线图 P0 / P1 / P2 / P3](#第-6-章-实施路线图-p0--p1--p2--p3)
- [第 7 章 风险登记册](#第-7-章-风险登记册)
- [第 8 章 技术选型速查](#第-8-章-技术选型速查)

---

# 第 0 章 核心判断：不要做什么

## 0.1 三个"看起来很美但价值≈0"的方向

| 方向 | 为什么看起来美 | 为什么实际价值低 | 结论 |
|---|---|---|---|
| **套壳式流水线**（subfinder→naabu→httpx→nuclei） | 30 行 shell 就能实现，四件套全 MIT、中文资料最多 | 用户自己 `\|` 一下就赢了。PD 套件已经是 3 万 star 的成熟品，你没有任何增量 | ❌ 不做 |
| **自研 SYN/ZMap 式无状态扫描** | 技术含量高，能讲原理故事 | ZMap 已 Apache-2.0 且 v4.4.0 活跃；masscan 是 C 写的老代码。个人项目写不出比 ZMap 更好的，而且**全网扫描在国内法律风险极高**（见第 5 章） | ❌ 不做 |
| **自研指纹识别 / 引入 ML** | "AI 识别技术栈"听起来前沿 | 报告已查证：httpx 的技术栈识别就是 **Wappalyzer 规则匹配**，favicon hash 是**确定性哈希**（零学习成分），"85-90% 准确率"是反欺诈领域的营销 SEO 内容。**换成 ML 消不掉哈希碰撞**，因为 favicon 只有几百字节，框架默认图标必然碰撞 | ❌ 不做 |

## 0.2 应该做的：把"验证"做成产品

调研报告里已经点明了 2026 年的真实瓶颈：

```
采集能力已经过剩
    ↓
真正的瓶颈在三个地方：
  ① 验证   —— 指纹误报是哈希的数学性质，不是模型精度问题
  ② 分诊   —— 凭据监控的噪音本质是"没有基线"，不是工具不好
  ③ 追溯   —— LLM 带来的最大风险不是虚构，是"自信地编"（拒答率 31%→≈0）
```

**这三个东西没有一个是"扫描器"能解决的，但全部可以做成软件。** 这就是屋勘的产品空间。

## 0.3 一句话产品定义

> **屋勘不是"扫得更快的工具"，是"扫完敢签字的台账"。**

交付物的形态是：**一份带证据链、能 diff、能追溯到原始报文、能在合规边界内自动执行的信息收集流水线。**

---

# 第 1 章 三个技术方案对比

## 1.1 方案总览

| 维度 | 方案 A：Go 单体内核 | 方案 B：Python 编排器 | 方案 C：Go 内核 + 插件化 + Web UI |
|---|---|---|---|
| **一句话** | 全 Go 单二进制，采集器硬编码 | Python 主控，采集器用 subprocess | Go 内核 + 采集器插件 + 本地 Web 控制台 |
| **首版工期** | **3 周** | **1.5 周** | **8-10 周** |
| **分发方式** | 单 exe / 单二进制 ⭐ | pip install + 依赖地狱 | 单二进制 + 内嵌静态资源 |
| **跨平台** | ⭐ 原生 | ⭐ | ⭐ |
| **性能（万级域名）** | ⭐ 并发 goroutine 无压力 | 🟡 asyncio 尚可，CPU 密集段会卡 | ⭐ |
| **内存占用** | < 100MB ⭐ | 300MB+ 🟡 | < 150MB |
| **扩展新数据源** | 改代码 + 重编译 🟡 | 写个 .py 丢进目录 ⭐⭐ | 写插件 + 声明清单 ⭐ |
| **可测试性** | 单测需 mock 边界 | mock 容易 | 插件可独立测试 ⭐ |
| **Web 可视化** | ❌ | 🟡 需另起服务 | ⭐ 内置 |
| **许可证风险** | 只依赖 MIT/Apache 组件 ⭐ | 同左，但依赖树更大 | 同左 |
| **适合阶段** | **MVP（P0）** | 概念验证（P0 前期） | **产品化（P1+）** |

## 1.2 方案 A：Go 单体内核（推荐）

**架构**：

```
wukan 子命令层（cobra）
    ↓
Pipeline 编排器（Stage 抽象 + 依赖 DAG）
    ↓
Collector 接口（统一签名，一次实现多处复用）
    ├── SubdomainCollector   （被动，纯 API）
    ├── DNSCollector         （解析记录 / NS / MX / TXT）
    ├── PortCollector        （主动，默认关闭）
    ├── HTTPCollector        （状态码 / 标题 / 证书 / 技术栈）
    └── SearchCollector      （搜索引擎 / CT 日志 / 归档 URL）
    ↓
Verifier 层（⭐ 差异化：交叉验证 + 置信度打分）
    ↓
SQLite Store（资产表 + 快照表 + 证据表 + diff 引擎）
```

**核心接口设计**（Go）：

```go
// Collector 统一抽象：任何数据源实现它就能接入流水线
type Collector interface {
    Name() string
    Passive() bool                      // 是否被动（决定要不要授权）
    Run(ctx context.Context, target Target, out chan<- Observation) error
}

// Observation 是所有采集器唯一的输出类型
type Observation struct {
    Kind      ObsKind     // domain / ip / port / service / cert / endpoint
    Value     string
    Attributes map[string]string   // 任意来源的键值对
    // ⭐ 证据回溯三件套（强制字段，不允许为空）
    Source    string      // 采集器名，如 "subfinder:crtsh"
    ObservedAt time.Time   // UTC
    RawHash   string      // 原始响应体的 SHA256
    RawRef    string      // 原始内容本地路径（.work/raw/...）
}

// Target 携带授权信息 —— 没有它，主动采集器直接拒绝执行
type Target struct {
    Domain   string
    ScopeID  string    // ⭐ 指向 scope.json 中的授权条目
}
```

**为什么选它**：

- ✅ **许可证干净**。全 MIT/Apache-2.0，报告已核实 PD 套件整套 MIT、ZMap/Amass 是 Apache-2.0，**避开 Nmap 的 NPSL**（明确禁止嵌入商业产品）和 masscan/TruffleHog 的 AGPL
- ✅ **单二进制 + 低内存**是"个人工具"该有的样子，`apt install` 式体验
- ✅ Go 的 goroutine 天然适合"每个域名一条 pipeline、并发受限流控制"这个模型
- ✅ 接口化设计让 P2 阶段加 Web UI 时**采集器一行不用改**
- 🟡 代价：扩展新数据源要重新编译（可用 Go plugin 或退化成"外置 JSON 规则"缓解）

**Go 依赖白名单（只允许这四个方向）**：

| 用途 | 库 | 许可证 |
|---|---|---|
| CLI 框架 | spf13/cobra | Apache-2.0 |
| HTTP 客户端 | resty 或标准库 net/http | MIT / BSD |
| DNS 查询 | miekg/dns | MIT |
| SQLite 驱动 | modernc.org/sqlite | Apache-2.0 ⚠️ **注意：不要用 mattn/go-sqlite3**（CGO + 传递 GPL 争议） |
| 数据结构 | 无需外部 | — |

> ⚠️ **License 陷阱提醒**：`mattn/go-sqlite3` 虽然是 MIT，但它**静态链接了 SQLite 源码**，曾引发过 GPL/PSF 双许可争议。`modernc.org/sqlite` 是纯 Go 转写，无 CGO，是 Go 项目的安全路径。

## 1.3 方案 B：Python 编排器

**适合**：想 1.5 周看到东西、验证产品假设是否成立。

```python
# Pipeline DSL 示意
class Pipeline:
    def __init__(self, target, scope_id):
        self.target = target
        self.scope_id = scope_id      # ⭐ 授权绑定
    def run(self):
        obs = collect_subdomain(self.target)     # 被动
        obs += collect_dns(obs)                  # 被动
        if self.scope.active_probe_allowed():    # ⭐ 授权闸门
            obs += collect_http(obs)             # 主动
        return verify(obs)                       # ⭐ 交叉验证
```

**致命问题**：

| 问题 | 后果 |
|---|---|
| Windows 分发 | 需要用户装 Python 环境 + 编译依赖（cryptography、hypothesis 等），劝退 |
| 内存 | 300MB+ 起步 |
| 依赖供应链 | 一次 `pip install` 拉进 200+ 传递依赖，**任意一个供应链投毒直接打到用户** |
| 与 PD 套件的关系 | 只能 subprocess 调用，丢失结构化输出，只能解析文本 → 脆弱 |

**结论**：可以作为 **P0 前期 3 天的原型验证**，但不要作为最终形态。

## 1.4 方案 C：Go 内核 + 插件化 + Web UI（终态）

在方案 A 之上加：

- **采集器插件系统**：每个采集器编译成独立二进制或 Go plugin，声明 `manifest.yaml`（能力、是否主动、需要哪些 key、限速要求）
- **本地 Web 控制台**：FastAPI / Go + embedded assets，`localhost:7890`
  - 资产列表（按 IP/端口/技术栈筛选）
  - 时间轴视图（每次扫描的 diff 高亮）
  - 证据面板（点开看原始报文 + 哈希校验）
  - 授权台账（哪些域在授权范围内、到期时间）
- **定时快照 + 告警**：每日/每周自动跑，diff 出"新增资产"，这才是能长期留存的杀手功能

**什么时候做**：P2 阶段。别在 MVP 就上。

---

# 第 2 章 推荐方案：Go 内核 + 插件化采集器

## 2.1 最终选型

> **方案 A 起步，架构上为方案 C 留门。MVP 用单二进制跑通全流程，P1 再拆插件，P2 加 Web。**

| 阶段 | 形态 | 交付物 |
|---|---|---|
| P0 | 单二进制 CLI，纯管道编排 + 证据链 | 能跑通、结果可信、有台账 |
| P1 | 采集器插件化 + 定时快照 + diff 告警 | 能长期跑，能发现新资产 |
| P2 | 本地 Web 控制台 | 能看、能查、能演示 |
| P3 | 关系图谱 + 报告生成 | 能交付给别人看 |

## 2.2 MVP 命令面设计

```bash
# ⭐ 核心命令（注意：主动探测必须显式 + 授权）
wukan init <domain>                 # 初始化工作区，建 .work/ 目录
wukan scope add <cidr|domain>       # ⭐ 登记授权范围，写 scope.json
wukan scope show                    # 查看当前授权台账
wukan scan passive -d example.com   # 只跑被动采集（零风险，无需授权）
wukan scan full    -d example.com   # ⭐ 需要有效 scope，否则拒绝执行
wukan verify --deep                 # 交叉验证 + 置信度打分
wukan diff --since 7d               # 与 7 天前快照对比
wukan evidence <asset-id>           # ⭐ 打印完整证据链
wukan report --format md|html       # 生成报告（带证据引用）
```

**设计原则**：`passive` 和 `full` 必须是**两个不同的子命令**，不是同一个命令加个 flag。

**理由（这是合规设计，不是 UX 设计）**：报告里写明"主动 SMTP 探测应单独书面授权"。如果 `--active` 只是一个 flag，用户会无脑加上；做成独立子命令，"我只跑了 passive"在审计日志里就是一句话能说清的事实。

## 2.3 目录结构

```
wukan/
├── cmd/wukan/              # CLI 入口（cobra）
├── internal/
│   ├── scope/              # ⭐ 授权闸门（所有主动采集的唯一入口校验点）
│   ├── pipeline/           # 编排器：Stage 定义 + DAG + 限流
│   ├── collector/          # 采集器接口 + 内置实现
│   │   ├── subdomain/      # subfinder / crt.sh / 被动 DNS
│   │   ├── dns/            # A / AAAA / NS / MX / TXT / CNAME
│   │   ├── http/           # 状态码 / 标题 / 证书 / 链
│   │   ├── port/           # ⚠️ 主动，默认关闭
│   │   └── search/         # 搜索引擎 / 归档 URL
│   ├── verify/             # ⭐ 交叉验证 + 置信度
│   ├── store/              # SQLite + 迁移
│   ├── diff/               # 快照对比
│   ├── report/             # Markdown / HTML 生成
│   └── evidence/           # 证据链：哈希、原文存储、校验
├── api/                    # 采集器 manifest 定义（P1 插件化用）
├── .work/                  # ⭐ 工作区（运行产物，默认 .gitignore）
│   ├── scope.json          # 授权台账
│   ├── wukan.db            # SQLite
│   ├── snapshots/          # 每日快照 JSON
│   └── raw/                # ⭐ 原始响应体（证据溯源）
└── docs/
```

---

# 第 3 章 差异化设计：四个不可替代的能力

**这一章是屋勘真正的护城河。** 前面是及格线，这里是加分项。

## 3.1 ⭐ 能力一：Scope 授权闸门（合规设计的强制前置）

### 问题

报告里两条硬线：

- 《刑法》285 条第 2 款：**"情节严重"门槛低得惊人** —— 非法控制计算机信息系统 **20 台**以上、获取其他身份认证信息 **500 组**以上即入刑
- 《刑法》285 条第 3 款：**开发或销售"用于"扫描/攻击的工具，即使未实际攻击也可能构成犯罪**（参考丁某案：售卖爬虫工具获刑 1 年 6 缓 2 年）

⚠️ 注意第二条：**"我做的是合法工具"在法律上不构成免责事由**。已有明确案例认定"AI 作为工具，不改变违法行为的法律性质"。

### 做法

```jsonc
// .work/scope.json —— 授权台账
{
  "authorizations": [
    {
      "id": "scope-001",
      "type": "cidr",                    // cidr | domain | url_prefix
      "value": "93.184.216.0/24",
      "granted_by": "书面授权书-2026-XXXX.pdf",
      "granted_at": "2026-10-01",
      "expires_at": "2026-12-31",       // ⭐ 强制过期，不允许 null
      "allowed": {
        "passive": true,
        "active_probe": true,
        "ports": [80, 443],              // 显式端口白名单，禁止 -p-
        "rate_limit": 10,                // pps，硬上限
        "time_window": "09:00-18:00"     // 禁止非工作时间扫描
      }
    }
  ]
}
```

### 强制规则（写进代码，不是写进 README）

| 规则 | 实现点 |
|---|---|
| R1 任何主动采集器**必须**声明 `Passive() == false` | 接口强制 |
| R2 主动采集器执行前**必须**调 `scope.AssertAllowed(target, port)` | 唯一入口，无法绕过 |
| R3 `-p-`（全端口）**在 scope 模式下直接拒绝**，只能显式列举端口 | 校验层拦截 |
| R4 授权过期 → 拒绝执行 | 每次执行前校验 `expires_at` |
| R5 超出 `time_window` → 拒绝执行 | 端口/探测类采集器 |
| R6 每次执行写审计日志（时间、目标、端口、发起人、结果） | SQLite `audit_log` 表，只追加不删除 |
| R7 `passive` 子命令**完全不读** scope 也不校验 —— 检索公开索引风险极低，不给用户添摩擦 | 保持易用性 |

> 💡 **R7 是刻意设计的**：如果连被动查询都要先配 scope.json，90% 的用户会在第一次用的时候就放弃这个工具。**易用性和合规要分层，不是二选一。**

### 这一条的隐藏价值

- 对**你自己**：不会因为"手滑多打了一个 `-p-`"把自己送进去
- 对**项目**：这是开源工具最有说服力的差异化点。**市场上 99% 的扫描工具没有任何合规设计**。README 里写"请遵守 laws.txt"和代码里写 `AssertAllowed()` 是两件完全不同的事
- 对**评委/客户**：能演示"扫描前系统会主动要求授权"，这是安全产品该有的形态

## 3.2 ⭐ 能力二：交叉验证器（把报告里"最值钱的一步"产品化）

### 问题

调研报告的原话：

> **⚠️ 阶段 4（交叉验证）是最容易被跳过、但最值钱的一步。** 不做交叉验证，你的报告里会全是 SYN Proxy 造成的误报。

三个高频误报源：

| 误报源 | 现象 | 解法 |
|---|---|---|
| **SYN Proxy**（AWS Global Accelerator / 各类 DDoS 防护） | 半开扫描收到 SYN-ACK 就判 open，21/23/179/636/3306/3389/5432/5985 **全误判** | 改用完整连接扫描 `-sT -sV` 交叉验证 |
| **云上安全组 DROP ICMP** | 主机发现失败 → **直接跳过该主机端口扫描** → 所有云主机都显示 down | 加 `-Pn` 跳过主机发现 |
| **下一代防火墙 RST rate limiting** | 应为 filtered 的端口被误判 closed | 交叉验证 |

### 做法

```go
// internal/verify/verifier.go
type Confidence int
const (
    ConfConfirmed  Confidence = 90  // 两种方法一致
    ConfLikely     Confidence = 70  // 单方法 + 已知模式匹配
    ConfUnverified Confidence = 30  // 单一弱证据
    ConfSuspect    Confidence = 10  // ⭐ 命中已知误报模式
)

// VerifyPort 对每个"开放端口"结论做交叉验证
func (v *Verifier) VerifyPort(p PortObservation) (result Verification) {
    // 规则 1：命中 SYN Proxy 疑似 IP 段（AWS GA、各类 DDoS 防护指纹）
    if v.isKnownSynProxy(p.IP) {
        // 必须做完整连接扫描才能确认
        if !p.FullConnectProbed {
            return result.Confidence = ConfSuspect  // ⭐ 明确标注"未经交叉验证"
        }
    }
    // 规则 2：SYN 与 T-CONTEXT 结果不一致 → 冲突标记
    if p.SynResult != p.TcpConnectResult {
        return result.Conflict = true
    }
    // 规则 3：云主机（EIP 段）未加 -Pn → 提示可能漏扫
    // ...
}
```

### 输出效果

```
example.com:443   TCP   open       confidence=90  [syn+http 交叉验证一致]
example.com:3389  TCP   open       confidence=10  ⚠️ 疑似 SYN Proxy 误报，未交叉验证
example.com:22    TCP   filtered   confidence=70  [ip-源，AWS EIP 段，已启用 -Pn]
```

**这一条输出的价值**：把报告里"评委最容易追问的点"变成了产品的默认行为。报告方法论章节那句话——"**扫描给你的是从互联网视角可达什么，不是主机上真实监听什么**"——直接印在报告脚注里。

## 3.3 ⭐ 能力三：证据回溯链（Evidence Chain）

### 问题

报告给的两条硬约束：

> 1. 多模型交叉验证（不同厂商的幻觉谱系不同，可互相证伪）
> 2. **每条结论必须能回溯到原始证据 URL + 抓取时间戳**
> 3. 保留人工署名与复核记录

并且：

> **拒答率从 31% 跌到接近 0 这个数字，比 18%→35% 的虚假率上升更值得警惕 —— 一个"不知道"的模型是安全的，一个"自信地编"的模型不是。**

### 做法

**每一张资产表都带证据，缺证据的结论不允许入库。**

```
asset_id:  a-3f2a91
kind:      service
value:     nginx/1.24.0
conf:      78
evidence:
  - source:    http:headers
    observed:  2026-10-04T02:14:33Z
    raw_ref:   .work/raw/20261004T021433Z-example.com_443.txt
    raw_sha256:9f2c1e...（现场校验）
  - source:    tls:cert.issuer
    observed:  2026-10-04T02:14:35Z
    raw_ref:   .work/raw/20261004T021435Z-example.com_cert.pem
    raw_sha256:41b8d0...（现场校验）
  - source:    search:wappalyzer-rules
    observed:  2026-10-04T02:14:35Z
    note:      ⚠️ 规则匹配，非 ML 推断
```

`wukan evidence a-3f2a91` 一次性打印：原始报文、哈希、采集器、抓取时间、置信度构成。

**原始响应体必须落盘**（`.work/raw/`），不只存哈希。理由：哈希只能证明"没被改过"，不能证明"内容是什么"。两者都要。

### 与 LLM 的配合纪律

如果 P2 阶段接入 LLM 做**采集指引生成**（比如自动生成 Google Dork 查询串），必须遵守报告定下的三条：

| 纪律 | 实现 |
|---|---|
| LLM 只做**噪声削减**（去重、分组、排序），不做**发现** | Dork 串生成必须可人工编辑后执行 |
| LLM 产出的每条结论**必须带 evidence URL** | 数据库层强制非空约束 |
| 报告里**区分**「工具实测」和「LLM 推测」两栏 | 报告模板硬编码两列，不允许合并 |

## 3.4 ⭐ 能力四：基线与 Diff（长期价值的来源）

### 问题

报告的洞察：

> 凭据暴露领域的噪音本质不是工具不好，是**没有基线**。
>
> **最省钱的实践建议：至少用两个引擎做两次查询取 diff，新出现的资产往往就是配置最粗糙的那批。**

以及 Censys 的 **Predictive Scanning 贡献 40%+ 新发现服务** —— 印证了"增量"比"总量"更有价值。

### 做法

```bash
# 每日/每周定时快照
wukan scan passive -d example.com --snapshot daily
wukan scan full    -d example.com --snapshot daily

# 7 天后对比
wukan diff --since 7d
```

```
╔══════════════ 资产变化报告 · 过去 7 天 ══════════════╗
║ 新增资产          3                                          ║
║   ⭐ 93.184.216.34:8443   nginx/1.18.0   ⚠️ 未知指纹    ║
║     └ 首次出现，无基线可比，置信度低，建议人工核         ║
║     └ 证据 http:headers @ 2026-10-01                     ║
║   ⭐ test-staging.example.com  Cloudflare              ║
║     └ ⚠️ 子域名从未被记录过 → 疑似影子资产              ║
║ 下线资产          1                                          ║
║   ✗ 203.0.113.9:3306                                     ║
║ 证书变更          2                                          ║
║   ⚠️ 证书 SAN 新增 *.internal.example.com               ║
║   ⚠️ 证书将于 23 天后过期                                 ║
╚═══════════════════════════════════════════════════════════╝
```

**为什么这一条最值钱**：单次扫描是一次性的，**基线是复利的**。这是"个人工具"能对抗商业 ASM 平台（$1,750~19,999/月）的唯一方式 —— 商业平台卖的是"数据量"，你卖的是"我比你更关心这个域"。

## 3.5 明确不做的能力（同样重要）

| 不做 | 理由 |
|---|---|
| **SMTP 邮箱枚举** | ⛔ 报告的禁止性建议原文："**不要为了'验证一下'而跑 SMTP 枚举。** 用 Hunter 这类合规的规模化服务，或只做被动查询。这条线的法律风险收益比极差" |
| **人员情报 / 邮箱发现 / 社工库** | PIPL 第 3 条管辖范围比 GDPR 更宽；Lusha 案被罚 200 万欧元的核心要点是"**正当利益不能支撑为第三方自身营销目的提供联系方式数据**" |
| **暗网 / stealer log 检索** | 数据源自犯罪基础设施，**持有即持有他人明文凭据**，合法边界极窄 |
| **漏洞利用 / nuclei 模板执行** | 从"信息收集"跨到"安全测试"是另一个法律量级。屋勘只负责"发现并记录"，不负责"验证可利用性" |
| **全网扫描（ZMap 式）** | 端口扫描在中国司法实践中已被明确作为犯罪行为的实施环节（董某案：扫描县政府网站获刑 9 个月，**即使被防火墙拦截、即使未成功**） |

> 💡 **"不做什么"要写进 README 第一节。** 这既是对用户的责任声明，也是项目最好的定位说明 —— 一个**明确说自己不做什么**的工具，比一个什么都能做但什么都不敢做的工具可信 10 倍。

---

# 第 4 章 数据模型与存储设计

## 4.1 SQLite 表结构

```sql
-- 资产实体（当前状态，快照式）
CREATE TABLE asset (
  id           TEXT PRIMARY KEY,       -- 短 hash，稳定标识
  target_id    TEXT NOT NULL,          -- FK → target
  kind         TEXT NOT NULL,          -- domain/ip/port/service/cert/endpoint/ns/mx
  value        TEXT NOT NULL,
  parent_id    TEXT REFERENCES asset(id),   -- ⭐ 图关系：ip→port→service
  confidence   INTEGER NOT NULL,       -- 0-100
  status       TEXT NOT NULL,          -- active/gone/suspect
  first_seen   TIMESTAMP NOT NULL,
  last_seen    TIMESTAMP NOT NULL,
  UNIQUE(target_id, kind, value)
);

-- 证据链（只追加，不修改，不删除）⭐ 核心表
CREATE TABLE evidence (
  id           TEXT PRIMARY KEY,
  asset_id     TEXT NOT NULL REFERENCES asset(id),
  source       TEXT NOT NULL,          -- "http:headers" / "tls:issuer" / "ct:crt.sh"
  observed_at  TIMESTAMP NOT NULL,
  raw_ref      TEXT NOT NULL,          -- .work/raw/ 下的文件路径
  raw_sha256   TEXT NOT NULL,
  payload      TEXT,                   -- 结构化提取结果（JSON）
  -- ⭐ 硬约束：没有 evidence 的 asset 不允许存在于视图 v_verified_asset
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT
);

-- 授权台账
CREATE TABLE scope (
  id           TEXT PRIMARY KEY,
  type         TEXT NOT NULL,          -- cidr/domain/url_prefix
  value        TEXT NOT NULL,
  granted_by   TEXT NOT NULL,          -- 授权文件出处
  granted_at   TIMESTAMP NOT NULL,
  expires_at   TIMESTAMP NOT NULL,     -- ⭐ NOT NULL，不允许永久授权
  passive      INTEGER NOT NULL,
  active_probe INTEGER NOT NULL,
  ports        TEXT NOT NULL,          -- JSON array，禁止 "-"
  rate_limit   INTEGER NOT NULL,
  time_window  TEXT
);

-- 扫描任务
CREATE TABLE scan (
  id           TEXT PRIMARY KEY,
  target_id    TEXT NOT NULL,
  scope_id     TEXT REFERENCES scope(id),   -- passive 任务为 NULL
  mode         TEXT NOT NULL,          -- passive/full
  started_at   TIMESTAMP NOT NULL,
  finished_at  TIMESTAMP,
  stats        TEXT                    -- JSON: counts per kind
);

-- 审计日志（只追加）⭐ 合规证据
CREATE TABLE audit_log (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  ts           TIMESTAMP NOT NULL,
  actor        TEXT NOT NULL,          -- OS 用户名
  action       TEXT NOT NULL,          -- scan/start, port/probe, scope/add ...
  target       TEXT NOT NULL,
  detail       TEXT,                   -- JSON
  result       TEXT NOT NULL           -- allowed/denied
);
-- ⭐ 没有任何 DELETE / UPDATE 权限授予应用
```

## 4.2 存储选型理由

| 选项 | 判断 |
|---|---|
| **SQLite** ⭐ | 单文件、零运维、可 git 忽略、支持 FTS5 全文检索、Python/Go 双端成熟。个人工具的正解 |
| BoltDB / bbolt | 更快但查询能力弱、无全文检索，只适合 KV |
| JSON 文件 | diff 友好但查询和关联查询会写成痛苦的手工代码 |
| PostgreSQL | 需要起服务，个人工具 overkill。**除非 P3 阶段要多用户** |

**全文检索**：用 SQLite FTS5 建一张 `evidence_fts` 虚表，让 `wukan search --evidence "jarm 指纹"` 能搜到历史证据。

## 4.3 资产图关系

```
domain: example.com
├── ip: 93.184.216.34
│   ├── port: 443 (tcp, open, conf=90)
│   │   └── service: nginx/1.24.0 (conf=78)
│   │       └── cert: SAN=[*.example.com, example.com] (expire 89d)
│   └── port: 3389 (tcp, open, conf=10) ⚠️ 疑似 SYN Proxy
├── ns: ns1.example.com → 192.0.2.1
├── mx: mail.example.com
└── endpoint: https://example.com/admin/  (来自历史归档, ⚠️ 未验证是否存活)
```

用 `parent_id` 单列自引用表达层级，**不引入图数据库**。理由：层级关系本质是树，用递归 CTE 就够；一旦需要真正的多对多关联再上 SQLite 边表。**Maltego 卖 €3,000/年的教训是：图的价值在"人做关联决策"，不在"存图"** —— 那是交互设计的钱，不是存储的钱。

---

# 第 5 章 合规硬约束（写进代码而不是写进 README）

## 5.1 三个不可协商的架构约束

| # | 约束 | 落地方式 |
|---|---|---|
| **C1** | **无 scope 拒绝一切主动探测** | `scope.AssertAllowed()` 是主动采集器的强制构造参数，无法传 nil |
| **C2** | **禁止全端口语法** | `ports` 字段是显式数组，`-p-` / `--top-ports` 在 scope 模式下解析阶段直接报错 |
| **C3** | **默认被动，主动需显式选子命令** | `scan passive` / `scan full` 分离；无 `--active` 之类的通用 flag |

## 5.2 代码级禁令（lint 规则拦截）

在 CI 里用自定义 lint 规则或 grep 检查，命中即失败：

| 禁止模式 | 原因 |
|---|---|
| `RCPT TO` / `SMTP RCPT` 字符串 | 邮箱枚举是「目录收割攻击」的协议层机制，报告明确禁止 |
| `-p-` / `65535` 出现在 scope 模式的代码路径 | 可能越过"非法控制计算机信息系统 20 台"的入刑门槛 |
| `nmap` 作为外部依赖链入 | NPSL 许可证污染 |
| `--disable-verify` / 跳过证据落盘的代码路径 | 违反产品的核心承诺 |
| 任何 `DELETE FROM audit_log` | 审计日志必须只追加 |

## 5.3 README 第一节必须写明

```markdown
## 屋勘会做什么 / 不会做什么

✅ 会做：
  - 对你自己拥有或已获**书面授权**的资产做低交互资产测绘
  - 保留完整证据链与审计日志
  - 强制在授权范围内执行，超范围直接拒绝

❌ 不会做：
  - 不会扫描任何不在你授权台账中的目标
  - 不提供 SMTP 邮箱枚举 / 人员情报 / 社工库
  - 不检索暗网或 stealer log
  - 不执行漏洞利用代码
  - 不做全网无差别扫描

⚖️ 法律提示：《刑法》285 条第 2 款"情节严重"门槛为非法控制 20 台以上
   或获取身份认证信息 500 组以上；第 3 款规定开发/销售"用于"扫描攻击的
   工具即使未实际使用也可能构成犯罪。**本工具内置授权闸门，但这不构成
   法律意见，合法性由使用者自行负责。**
```

---

# 第 6 章 实施路线图 P0 / P1 / P2 / P3

## 6.1 P0 — MVP（3 周）：跑通 + 可信

**目标**：能对自建靶场/自己域名跑一次完整扫描，产出一份带证据链的 Markdown 报告。

| 任务 | 交付 | 优先级 | 验收标准 |
|---|---|---|---|
| T0.1 项目骨架 + cobra CLI + `.work/` 目录管理 | 目录结构 | 🔴 P0 | `wukan --help` 可用 |
| T0.2 SQLite store + 迁移机制 | 4 张表 + 迁移 | 🔴 P0 | 单测覆盖 CRUD |
| T0.3 **Scope 授权闸门**（§3.1 全部 7 条规则） | `internal/scope` | 🔴 **P0（最高）** | 无 scope 时 `scan full` 返回拒绝；过期 scope 被拒；`-p-` 被拒 |
| T0.4 Collector 接口 + Observation 结构 | 接口定义 | 🔴 P0 | 接口文档 + 一个 mock 实现 |
| T0.5 子域名采集器（crt.sh + 被动 DNS，**纯被动**） | `collector/subdomain` | 🔴 P0 | 对测试域能拿到 ≥3 个真实子域 |
| T0.6 DNS 采集器（A/AAAA/NS/MX/TXT/CNAME） | `collector/dns` | 🔴 P0 | 单测 + 真实域名验证 |
| T0.7 HTTP 采集器（状态码/标题/证书/服务器头） | `collector/http` | 🔴 P0 | 正确解析 HTTP/2 与 HTTP/3 响应 |
| T0.8 证据落盘 + 哈希校验 | `evidence/` | 🔴 P0 | `wukan evidence <id>` 打印完整链路 |
| T0.9 **交叉验证器**（§3.2 规则 1-3） | `verify/` | 🟡 P1 | SYN Proxy 误报能被标为 suspect |
| T0.10 置信度打分 + 报告生成（Markdown） | `report/` | 🟡 P1 | 报告含方法论脚注 + 证据引用 |
| T0.11 审计日志 | `audit_log` 表 | 🔴 P0 | 每次执行可追溯 |

**P0 出口标准**：
```bash
$ wukan scan passive -d example.com      # 无 scope 也能跑
$ wukan scan full -d example.com         # 拒绝：no active scope
$ wukan scope add 93.184.216.0/24 --ports 80,443 --expires 2026-12-31
$ wukan scan full -d example.com         # ✅ 执行，全程审计
$ wukan evidence a-3f2a91                # 原始报文 + 哈希校验
$ wukan report --format md > recon.md    # 带证据引用的报告
```

## 6.2 P1 — 可长期运行（4 周）

| 任务 | 交付 | 优先级 |
|---|---|---|
| T1.1 端口采集器 + Scope 强制校验 + 限流 + 时间窗 | `collector/port` | 🔴 P0 |
| T1.2 **快照 + Diff 引擎**（§3.4） | `diff/` + `snapshots/` | 🔴 **P0（核心价值）** |
| T1.3 定时任务（cron / Windows 任务计划） | `--snapshot` 调度 | 🟡 P1 |
| T1.4 证书变更追踪（SAN 增删、到期提醒） | TLS 采集增强 | 🟡 P1 |
| T1.5 **多引擎交叉**：subfinder + crt.sh + 被动 DNS 取 diff | 数据源仲裁 | 🟡 P1 |
| T1.6 采集器插件化（manifest 化） | `api/` | 🟢 P2 |
| T1.7 CI：单测 + lint + §5.2 禁令检查 + 覆盖率 | GitHub Actions | 🟡 P1 |
| T1.8 README + LICENSE（MIT）+ 开源发布 | 仓库 | 🟡 P1 |

> **T1.2 是整个项目的价值拐点**。单次扫描谁都能做，diff 出来的"影子资产发现"是商业 ASM 平台才卖的能力。**优先级提到 P0 是有意的。**

## 6.3 P2 — 产品化（6 周）

| 任务 | 交付 |
|---|---|
| T2.1 本地 Web 控制台（FastAPI 或 Go + embed） | `localhost:7890` |
| T2.2 资产列表 / 筛选 / 搜索（含 FTS5 证据搜索） | Web |
| T2.3 时间轴视图（快照 diff 可视化） | Web |
| T2.4 授权台账管理界面 | Web |
| T2.5 报告 HTML 导出（自带证据附录） | Web |
| T2.6 多目标 / 资产组管理 | 核心 |
| T2.7 `agent-browser` 自动化：定时跑 + 截图报告 | 集成 |

## 6.4 P3 — 差异化纵深（按需）

| 任务 | 说明 |
|---|---|
| T3.1 关系图谱视图 | ⭐ 手工关联优先，不自动推断（报告的教训：LLM 实体识别比专用基线低 25%） |
| T3.2 多用户 + 协作 | 团队场景才需要 |
| T3.3 历史 URL 挖掘 | ⚠️ **必须授权**，gau 官方文档自己也强调"仅用于授权域名" |
| T3.4 LLM 辅助的采集指引生成 | ⚭� 严格遵守 §3.3 三条纪律，LLM 只做噪声削减 |

---

# 第 7 章 风险登记册

| # | 风险 | 概率 | 影响 | 缓解措施 | 状态 |
|---|---|---|---|---|---|
| R1 | **法律风险**：被用于未授权扫描 | 中 | 🔴 极高（入刑） | Scope 闸门 + `-p-` 禁令 + README 声明 + 审计日志。**这是已知的不可消除风险，只能降低** | 🟡 缓解中 |
| R2 | Scope 闸门被绕过（代码 bug） | 低 | 🔴 极高 | 主动采集器构造参数强制非 nil + 单测断言无 scope 必失败 + CI lint 拦截 | ⟡ 待实现 |
| R3 | 性能：万级域名下内存/耗时不可接受 | 中 | 🟡 中 | goroutine 池 + 令牌桶限流 + 采集器并发分级；10k 域名压测作为 P0 验收项 | ⟡ 待验证 |
| R4 | 依赖供应链投毒 | 低 | 🟡 中 | 依赖白名单（§1.2）+ `go.sum` 锁定 + 定期 `govulncheck` | 🟢 计划中 |
| R5 | 许可证污染（NPSL/AGPL 传递） | 低 | 🔴 高（商用） | 只用 MIT/Apache-2.0；**避开 Nmap、masscan、TruffleHog、waybackurls（无许可证）**；CI 做 license check | 🟢 计划中 |
| R6 | 变成"又一个套壳流水线" | **高** | 🔴 高（项目价值归零） | **§3 四个差异化能力全部实现才算 v1.0**；diff 引擎不可延期 | 🔴 **需持续警惕** |
| R7 | 数据源 API 额度/封禁 | 中 | 🟡 中 | 采集器按源独立限速（subfinder 的 `-rls` 模式）；API key 缺失时优雅降级 | ⟡ 待实现 |
| R8 | 长时间不维护（个人项目通病） | 高 | 🟡 中 | 选 Go（编译型、依赖少、维护成本低）；架构简单化优先于功能丰富 | 🟢 设计中已考虑 |
| R9 | **过度依赖 LLM 做判断** | 中 | 🟡 中 | 报告结论：LLM 只做噪声削减，不做发现。**每条结论必须落证据** | 🟢 原则已定 |

---

# 第 8 章 技术选型速查

## 8.1 语言与框架

| 用途 | 选型 | 版本 | 理由 |
|---|---|---|---|
| 主语言 | **Go** | ≥1.23 | 单二进制、低内存、并发模型天然匹配、MIT/BSD 生态 |
| CLI | spf13/cobra | 最新 | PD 套件同款，命令面一致 |
| 配置 | viper 或 YAML 原生 | — | 配置简单，YAML 足够 |
| 存储 | modernc.org/sqlite | 最新 | **纯 Go，无 CGO**（避开 mattn/go-sqlite3 的许可争议） |
| DNS | miekg/dns | 最新 | 纯 Go |
| HTTP | resty | v2 | 支持重试/超时/代理 |
| Web（可选） | Go net/http + embed | — | 单二进制内嵌静态资源，比 FastAPI 更契合 |
| 测试 | 标准库 + testcontainers（可选） | — | 主动采集器测试用本地 docker 起靶场 |

## 8.2 采集器依赖（严格白名单）

| 数据源 | 用什么 | 许可证 | 备注 |
|---|---|---|---|
| 子域名 | `projectdiscovery/subfinder` 作为库 或 独立二进制 | MIT | 支持 `-rls` 按源限速 |
| 证书透明度 | `crt.sh` 官方 JSON API | N/A | 免费无需 key |
| 被动 DNS | SecurityTrails 免费层 | 商业 | 额度有限，优雅降级 |
| HTTP 探测 | 自研（用 resty） | — | 不引 httpx，避免 flag 解析的坑 |
| 端口探测 | 自研（miekg/dns + net.Dial） | — | **不引 nmap（NPSL）**；scope 闸门在此层 |
| 搜索引擎 | 官方 API（Google Custom Search / Bing） | 商业 | **不爬 SERP** |
| 历史 URL | `lc/gau` 或 waybackurls | MIT / ⚠️ 无许可 | **waybackurls 无 LICENSE = 保留所有权利，商用不可用** |
| 技术栈指纹 | Wappalyzer 数据集 | MIT | **规则匹配，报告里必须如实标注非 ML** |
| favicon hash | 自研 mmh3 | — | ⚠️ **必须实现 RFC 2045 每 76 字符换行 + 有符号整数**，否则永远对不上 Shodan |

## 8.3 ⚠️ 明确不引入的依赖

| 依赖 | 原因 |
|---|---|
| `nmap` / `nmap-service-probes` | **NPSL**：禁止嵌入商业产品；仅"读取 probes 文件"即被定义为衍生作品 |
| `masscan` | AGPL-3.0 网络传染 |
| `TruffleHog` | AGPL-3.0（工具本身好用，但不合入本项目） |
| `waybackurls` | **无 LICENSE = 保留所有权利** |
| `mattn/go-sqlite3` | CGO + SQLite 许可争议 |
| 任何"AI 指纹识别"库 | 报告已查证：不存在可信基准，httpx 本身就是 Wappalyzer 规则匹配 |

---

## 一句话收尾

> **采集能力已经过剩，验证和分诊才是瓶颈。**
>
> 屋勘的机会不在"扫得更多"，在"扫完你敢签字"——
> 授权有据、证据可追、变化可比、结论可辩。

---

*文档完。合规章节为一般性提示，不构成法律意见。涉及具体使用请咨询执业律师。*
