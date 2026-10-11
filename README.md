# 屋勘 HouseRecon

> **一屋之内，勘遍全网**
> 短标语：屋中勘察，尽收踪迹

```
  /\
 /  \
/____\
| [] |  屋勘 HouseRecon  v0.1.0
|____|  一屋之内，勘遍全网
```

轻量化网络空间资产侦察与信息收集工具。**Go 实现，零第三方依赖，单文件 exe。**

---

## ⚠️ 授权使用要求

本工具包含**主动探测**功能，**仅限对你拥有或已获书面授权的目标使用**。

| 命令 | 性质 | 默认 |
|---|---|---|
| `ipinfo` | 纯被动（第三方公开 API） | ✅ 开 |
| `recon` | 主要是被动（DNS / RDAP / CT / 公开 API） | ✅ 开 |
| `recon --ports` | **主动**（建立 TCP 连接并抓 banner） | ⛔ 关 |
| `recon --tech` | **主动**（发送 HTTP 请求 + 抓 favicon） | ⛔ 关 |
| `recon --quic` | **主动**（发送 UDP 探测包） | ⛔ 关 |
| `ports` | **主动**（同 `--ports`） | — |
| `tech` | **主动**（同 `--tech`） | — |

主动功能全部**默认关闭**，必须显式开启。端口扫描内置白名单约束（拒绝全端口扫描、单次上限 10000 端口）。

**使用者须自行确保行为符合当地法律。** 在中国大陆，未经授权扫描他人系统可能触犯《刑法》第 285/286 条及《网络安全法》。工具内的约束不构成法律豁免。详见 [LICENSE](LICENSE)。

---

## 它与其他工具的区别

现有信息收集工具（httpx / nuclei / subfinder / naabu / theHarvester…）做的是**采集**：把多个来源的结果拼在一起输出。

屋勘在采集之外多做了一件事：**判断这些结果之间是否自相矛盾，并把矛盾翻译成可行动项。**

| | 常见工具 | 屋勘 |
|---|---|---|
| 输出 | 「这些是数据」 | 「**这些是数据 + 哪里有问题 + 你该做什么**」 |
| 多来源指纹 | 拼接输出，不校验一致性 | ⭐ **交叉校验，冲突单独报出** |
| 端口扫描 | 多为 SYN 半开（快，但会误报） | ⭐ **TCP connect（慢一个 RTT，但零误报）** |
| 结论置信度 | 通常只给"是/否" | ⭐ **给 0-100 置信度 + 证据链** |

---

## 六个子命令

```bash
wukan recon <域名>     # 目标信息卡：DNS/注册信息/证书子域/被动DNS/rDNS/端口/指纹
wukan tech <URL>       # HTTP 指纹采集 + ⭐冲突检测（+JARM/H2 深度指纹）
wukan ports <主机>     # TCP connect 端口扫描
wukan ipinfo <IP>      # IP 归属批量查询（含 rDNS 反查）
wukan diff <域名>      # ⭐ 快照对比（变化监控，需先 recon --snapshot）
wukan timeline <域名>  # ⭐ 本地资产时间线（何时迁移、迁移到哪）
```

一条龙：

```bash
wukan recon example.com --ports 80,443 --tech --quic

# 变化监控：存快照 → 自动对比上次 → 随时离线复查
wukan recon example.com --snapshot
wukan diff example.com --since 7d
wukan timeline example.com

# 交付报告（Markdown / 自包含 HTML，扩展名自动推断）
wukan recon example.com -o report.md
wukan recon example.com -o report.html
```

---

## 快速上手

```bash
# 编译
go build -o wukan.exe ./prototype/wukan-go/cmd/wukan

# 被动侦察（不向目标发包）
wukan recon example.com

# 一条龙（主动，需授权）
wukan recon example.com --ports 80,443 --tech

# 只看指纹冲突
wukan tech https://example.com --conflicts

# IP 归属 + rDNS
wukan ipinfo 8.8.8.8 1.1.1.1 --rdns

# 输出格式
wukan recon example.com -o result.json      # 扩展名自动推断格式
wukan tech -f urls.txt --csv -o out.csv
```

### 环境变量

| 变量 | 作用 |
|---|---|
| `WUKAN_NO_BANNER=1` | 不输出 ASCII 启动页 |
| `WUKAN_FORCE_BANNER=1` | 强制输出启动页 |
| `NO_COLOR=1` / `WUKAN_NO_COLOR=1` | 关闭 ANSI 颜色（遵循 [no-color.org](https://no-color.org/) 约定） |
| `WUKAN_FORCE_COLOR=1` | 强制彩色 |
| `WUKAN_HACKERTARGET_KEY` | hackertarget API key（可选）：免费层仅 50 次/天，配置后按套餐提升额度 |
| `WUKAN_OTX_KEY` | OTX API key（可选）：启用被动 DNS **时间线**（"何时迁移、迁移到哪"）。OTX 已限制匿名访问，免费注册即可 |

启动页与颜色**默认只在终端（TTY）下启用**：输出被重定向或接入管道时自动降级为纯文本，
保证 `wukan help > doc.txt` 和 `wukan version | awk ...` 拿到的是干净、可解析的输出。

---

## 核心特色

### 1. 可行动发现（而非数据堆砌）

`recon` 不输出"一堆 DNS 记录"，而是给出**30+ 类带严重程度和处置建议的发现**：

```
🔴 [risky_ports] 发现 2 个高风险端口直接暴露在公网
     这些端口一旦被利用，后果通常是数据泄露或系统控制。
     典型风险源：数据库可被直接访问或弱口令；远程管理常是勒索软件入口。
     建议：① 改绑内网或走跳板机 ② 限制来源 IP ③ 检查是否有弱口令
     ├ 3306/tcp mysql 5.7.42
     └ 6379/tcp redis
```

发现示例：`shadow_asset`（历史证书里已下线的子域）、`stale_passive_ip`（历史 IP）、
`rdns_identity_mismatch`（IP 归属异常）、`subdomain_stack_diversity`（子域技术栈差异）、
`txt_tokens`（TXT 泄露第三方验证 token）、`wildcard`（泛域名导致存活判断失真）……

### 2. 指纹冲突矩阵 ⭐

采集 5 路**相互独立**的指纹并交叉校验：

| 来源 | 内容 |
|---|---|
| ① HTTP 响应头 | Server / X-Powered-By / Set-Cookie / CDN 特征头 |
| ② TLS 层 | 版本 / 加密套件 / ALPN / 证书 SAN |
| ③ favicon 哈希 | MurmurHash3（Shodan 兼容） |
| ④ 正文特征 | 标题 / CMS 关键词 |
| ⑤ 一致性 | 各来源之间是否自相矛盾 |

**冲突本身往往指向真实问题**：

```
🟡 [cdn_leak] 声称使用 CloudFront (AWS)，但源站特征泄露
     CDN 会隐藏源站特征，但以下响应头穿透了代理：Server: nginx、X-Powered-By: PHP/8.2.0
     └ 判读: 泄露的头会帮攻击者识别源站软件与版本，进而匹配对应 CVE。

🟡 [cert_mismatch] 证书 SAN 未覆盖当前访问的主机名
🟡 [cookie_flags] 会话 Cookie 缺少 Secure / HttpOnly
```

**设计原则：冲突检测器自身不能产生假阳性。** 为此做了两处专门规避（都有测试固化）：
- CDN 判定必须来自**独立于 Server 头**的信号（否则 `Server: Tengine` 会既当"声称"又当"反证"）
- IP 直连时**不报**证书 SAN 不匹配（这是访问形式的必然结果，不是配置错误）

**探测失败自动降级重试**：先跳过重定向（拿原始 301/302 —— Server/Location/Cookie 本身就是有效指纹），再改试 `http://`（覆盖只跑 HTTP 的子域）。实测把"重定向后超时"的失败子域变成可分析的结果；结果在表格/JSON 中如实标注 `retried_with`。

### 3. 端口扫描：用 TCP connect 规避 SYN Proxy 误报

AWS Global Accelerator 等服务的边缘使用无状态 SYN Proxy —— **无论端口背后有无真实服务，都会对任何 SYN 回 SYN-ACK**。
只做半开 SYN 扫描的逻辑（"收到 SYN-ACK ⇒ 开放"）会把 3306 / 3389 / 5432 全部误判为开放。

TCP connect 扫描**必须完成三次握手**才能判定开放，SYN Proxy 伪造不出"已建立的连接" —— **天然免疫**。

代价（已在输出中如实告知）：目标侧留下完整 established 记录；超时无法区分"被 DROP 的开放端口"与"不存在的端口"。

### 4. 变化监控：基线与 Diff ⭐

单次扫描是一次性的，**基线是复利的**。`--snapshot` 保存每次运行的资产快照并自动与上次对比：

- 新增/消失的子域、解析 IP、开放端口、HTTP 指纹变化（含 JARM/H2 指纹）—— 每条都带判读
- **覆盖门控**：数据源失败或运行参数变化时，差异标记为"不可比"（`coverage_changed`），而不是误报成片"资产消失"
- **CDN 节点轮换归并**：同一端口随解析 IP 移动归并为低危提示，不冒充"新暴露端口"
- `wukan diff <域名> [--since 7d]` 离线复查，退出码适配定时监控脚本
- `wukan timeline <域名>` 从快照历史聚合迁移轨迹（零外部依赖）；配 `WUKAN_OTX_KEY` 还可接入 OTX 的更早历史
- ⭐ **定时任务封装**：`scripts/monitor/`（Windows 任务计划 / cron / systemd timer 一键脚本 + 通知钩子，完整配置文档）
- `recon --snapshot --exit-code`：0=无告警变化 / 1=有变化 / 2=失败 —— 调度器直接可用的信号

### 5. 深度指纹与交付报告

- **JARM TLS 指纹**：与 Salesforce 官方参考实现**逐字符交叉验证**（6 台真实服务器全一致），默认关（每目标 +10 连接）
- **HTTP/2 SETTINGS 指纹**：1 个连接读取服务器连接参数（Akamai 风格），默认开
- **报告导出**：`--format markdown / html`（扩展名自动推断）—— HTML 自包含单文件，适合直接交付/存档
- **favicon 扩展表工具**：`cmd/favicon-collect` 批量采集 + 人工核对清单，产出可直接生效的扩展表

---

## 实测数据

以下均为开发过程中实测，非估算：

| 项 | 数据 |
|---|---|
| 全流程（gitee.com，缓存命中） | 3.8s |
| `tech` 阶段（15 个目标） | 10.8s（冷）→ 0s（缓存命中），**整体快 6 倍** |
| 端口缓存（本地靶场 8 端口） | 冷扫 0.63s → 二次 8/8 全命中 **0.00s**（零连接） |
| tech 降级重试（本地靶场） | 重定向黑洞 → 跳过重定向拿到 **302**；TLS 失败 → http 回退拿到 **200**（对照组均失败） |
| 变化监控 E2E | 覆盖率门控：CT 失败时 **0 条假"消失"**；12 连跑 **0 崩溃**（修复前 1/12 并发写 map 崩溃） |
| JARM 交叉验证 | 与 Salesforce Python 参考实现对 **6 台真实服务器逐字符一致**（github/cloudflare/baidu/qq/bing/example.com） |
| favicon 工具链验证 | 真实采集复测内置表 **21/21 哈希一致**（另 2 条因网络未采到） |
| 子域批量指纹的增量价值 | 根域探测发现 **0** 处冲突，子域探测发现 **5** 处 |
| rDNS | 6 个 IP 中 2 个**无 PTR**（无 PTR 是常态，非异常） |
| favicon 哈希表 | 23 条，**全部实测**（含 md5 可核对） |
| 单元测试 | 147 项全过 |

### 数据源实测结论

| 源 | 状态 | 备注 |
|---|---|---|
| `dns.alidns.com` (DoH) | ✅ 0.1s | 默认解析器 |
| `rdap.org` | ✅ | 注册商 / 过期时间 / NS / DNSSEC |
| `api.certspotter.com` | ✅ 3.1s | ⚠️ **免费层 100 次/小时** |
| `crt.sh` | 🟡 间歇 502 | 作备源，自动降级 |
| `api.hackertarget.com` | ✅ | ⚠️ **免费层 50 次/天**（被动 DNS / IP 反查）；可配 `WUKAN_HACKERTARGET_KEY` 提升额度 |
| `ipwho.is` + `ip-api.com` | ✅ | IP 归属，双源互补 |

**降级链路**：缓存 → certspotter → crt.sh。全部失败时**不崩溃、不静默**，明确报告原因。

---

## 架构

```
prototype/
├── wukan-go/                    # 主程序（13k 行，零第三方依赖）
│   ├── cmd/wukan/main.go        # CLI（4 个子命令）
│   └── internal/
│       ├── recon/               # 目标信息卡
│       │   ├── dns.go           # 记录类型 + 泛域名检测
│       │   ├── doh.go           # DoH（兼容 Question 对象/数组两种返回形态）
│       │   ├── rdap.go          # RDAP 客户端
│       │   ├── ct.go            # 证书透明度 + ⭐CNAME 跟随 + 缓存
│       │   ├── passive.go       # 被动 DNS / IP 反查
│       │   ├── recon.go         # 编排 + ⭐可行动发现分析
│       │   └── output.go        # table / json / hosts / subs
│       ├── httpprobe/           # HTTP 指纹
│       │   ├── probe.go         # 5 路指纹采集 + Shodan 兼容 favicon hash
│       │   ├── conflict.go      # ⭐冲突检测 + favicon 哈希表
│       │   └── cache.go         # 指纹缓存（⭐键含 Host 头）
│       ├── portscan/            # 端口扫描（TCP connect + 端口白名单）
│       ├── ipinfo/              # IP 归属 + rDNS 反查
│       └── quic/                # QUIC/UDP-443 探活
└── quic/                        # QUIC 探活原型（Python 验证 + Go 实现）
```

### 构建

```bash
# 需要 Go 1.21+
go build -o wukan.exe ./prototype/wukan-go/cmd/wukan

# 测试
go test ./prototype/wukan-go/...
```

### 缓存文件

| 缓存 | 路径 | TTL |
|---|---|---|
| IP 归属 | `~/.wukan/ipinfo-cache.json` | 7 天 |
| CT 证书 | `~/.wukan/ct-cache.json` | 7 天 |
| 被动 DNS | `~/.wukan/passive-cache.json` | 14 天 |
| HTTP 指纹 | `~/.wukan/tech-cache.json` | **1 天**（负缓存 10 分钟） |
| 端口扫描 | `~/.wukan/ports-cache.json` | **6 小时**（filtered/error 10 分钟） |
| 资产快照 | `~/.wukan/snapshots/<域名>.json` | 每目标保留最近 30 个（内容相同 24h 内去重） |

指纹缓存 TTL 特意设为 1 天而非 7 天：**HTTP 指纹是"当前状态"**，换版本、开关服务、改安全头都会立刻改变。
过时的安全结论比没有结论更危险。

端口缓存 TTL 特意设为 6 小时（比指纹更短）：**端口状态变化更快**（服务临时下线、部署窗口、防火墙调整）。
filtered/error 是**不确定结论**（超时无法区分"被丢掉的开放端口"与"不存在"），只用 10 分钟短 TTL，防止一次抖动被固化成错误结论。

---

## 已知局限

诚实列出，避免误用：

1. **CT 源配额紧**（certspotter 100 次/小时），大量目标需分批或自备 key
2. **被动 DNS 配额 50 次/天**（hackertarget 免费层）—— 可配 `WUKAN_HACKERTARGET_KEY` 提升额度
3. **子域"存活"仅验证 DNS 解析** —— 有泛域名时几乎全部"存活"，需 HTTP 探测确认
4. **端口扫描超时无法区分** "被 DROP 的开放端口"与"不存在的端口"（TCP connect 的固有代价）
5. **不查被动 DNS 历史解析的完整时间线**（只取当前快照）
6. **favicon 表覆盖有限**（内置 23 条，且图标天然易碰撞 —— 命中只能作线索，不能作结论）。
   可通过 `~/.wukan/favicon-extra.json` 覆盖/扩充，或用 `cmd/favicon-collect` 批量采集（⚠️ 数据须实测/人工核对）
7. **JARM 默认关闭**（每目标 10 个连接较重）；`--tech-jarm` / `--jarm` 显式开启
8. **OTX 时间线需要 API key**（免费注册）：无 key 时本地时间线（`wukan timeline`）仍可用
7. **rDNS 约 1/3 公网 IP 无 PTR**，无法用 rDNS 确认归属时需靠 WHOIS/BGP/台账
8. **未做真实 CDN 绕过** —— 检测到 CDN 时会报告"扫描结果反映的是边缘节点"，但不自动找源站

---

## 文档

`doc/项目规划/` 下是完整的调研与规划材料：

| 文档 | 内容 |
|---|---|
| [⭐ 后续开发路线图](doc/项目规划/HouseRecon-后续开发路线图.md) | **换机交接 + 开发原则（踩坑教训）+ P0/P1/P2 路线** |
| [技术方案与实施计划](doc/项目规划/HouseRecon-技术方案与实施计划.md) | 总体设计与分阶段计划 |
| [信息收集方法全景分类](doc/项目规划/信息收集方法全景分类.md) | 方法论分类与合法性边界 |
| [可创新扫描手法评估](doc/项目规划/可创新扫描手法评估.md) | 差异化机会评估 |
| [实用功能清单与开发优先级](doc/项目规划/实用功能清单与开发优先级.md) | 功能取舍 |
| [QUIC 探活原型验证报告](doc/项目规划/QUIC探活原型验证报告.md) | QUIC 探活的实测报告 |
| [信息收集工具全景调研报告](doc/项目规划/调研报告/信息收集工具全景调研报告.md) | 主报告：工具生态全景 |
| [附录 A：主动扫描与资产测绘](doc/项目规划/调研报告/附录A-主动扫描与资产测绘.md) | 主动扫描技术调研 |
| [附录 B：OSINT 情报平台](doc/项目规划/调研报告/附录B-OSINT情报平台.md) | 网络空间搜索引擎与商业情报平台选型 |
| [附录 C：人员情报与泄露面](doc/项目规划/调研报告/附录C-人员情报与泄露面.md) | SOCMINT / 凭据泄露监控 / **合规边界警示** |

> 附录 C 含大量**合规风险警示**（如明确标注「社工库明文组合属非公开个人信息，无任何合法性基础」「批量枚举用于撞库 500 组即达情节严重」），
> 性质为防御性调研，不构成任何操作指引。

---

## English

**HouseRecon** is a lightweight network asset reconnaissance toolkit in Go — **zero third-party dependencies, single binary**.

Six subcommands: `recon` (asset card), `tech` (HTTP fingerprinting + **conflict detection** + JARM/H2), `ports` (TCP connect scan), `ipinfo` (IP attribution + rDNS), `diff` (snapshot diff for change monitoring), `timeline` (local asset timeline).

**What sets it apart:**

- **Actionable findings, not raw dumps** — 30+ finding types with severity, evidence and remediation guidance.
- **Fingerprint conflict matrix** — collects 5 independent fingerprint sources and **cross-validates them**. Existing tools merely concatenate results; contradictions usually point to real issues (CDN origin leaks, certificate misconfiguration, cookies missing security flags).
- **TCP connect scanning to avoid SYN Proxy false positives** — stateless SYN proxies reply SYN-ACK to *any* SYN, making half-open scanners report 3306/3389/5432 as open. connect scanning requires a completed handshake and is immune.
- **Change monitoring with baselines** — `recon --snapshot` saves asset snapshots and diffs them against the previous run. **Coverage gating** keeps data-source failures or flag changes from producing false "disappeared" alarms.
- **JARM cross-validated against the reference implementation** — byte-level port with per-server hash equality verified on real servers. Plus HTTP/2 SETTINGS fingerprinting and self-contained Markdown/HTML reports.

**Authorized use only.** Active scanning features are disabled by default. See [LICENSE](LICENSE).

---

## 授权

MIT License。附加授权使用要求见 [LICENSE](LICENSE)。
