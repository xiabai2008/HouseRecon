# 附录 A：主动式网络资产测绘工具完整调研

> 本附录是《信息收集工具全景调研报告》的分领域原始调研，聚焦「主动式网络资产测绘/扫描/侦察」类开源工具的工作原理、技术栈与优缺点。
> **数据核验于 2026-10-03**（GitHub API 实际拉取 + 官方文档抓取 + 厂商/法院公开材料），含全部来源链接。
> **方法说明**：标注为「社区说法」的未经独立验证；不确定的已明确说明。

---

## 〇、开篇三个反直觉结论

调研前以为、查证后发现相反的事实：

**1. Censys 已经不用 ZMap 做周期扫描了。** 官方文档明确写道：ZMap 扫描属于 "Deprecated IPv4 Scans" 类别，"While we no longer perform scheduled scans, we retain and can grant access to this historical data"。Censys 现在自称使用 "continuous scanning engine with automatic protocol detection"。
（来源：[Censys Research Access](https://support.censys.io/hc/en-us/articles/360038761891-Research-Access-to-Censys-Data)，2026-10 抓取）
→ 中文技术文章里"Censys 靠 ZMap 扫全网"的说法已过期。

**2. naabu 没有内置 NPSL 指纹库。** 网上（含一篇中文 blog）普遍称 naabu 的 `-sV` 直接调用 `nmap-service-probes` 从而沾染 NPSL 风险。**实测官方文档：naabu 无 `-sV` 旗标**，服务识别需显式 `-nmap-cli 'nmap -sV'` 外挂 nmap。naabu 端口扫描部分是纯 MIT，NPSL 暴露只发生在你自己 chain nmap 的环节。
（来源：[naabu Usage 文档](https://docs.projectdiscovery.io/opensource/naabu/usage)）

**3. Nmap 已经到 7.991，且许可证是商业禁用型。** 不是大家说的 7.95。NPSL 明确禁止把 Nmap 嵌入商业软硬件产品（含 Docker 镜像、VM、appliances）。
（来源：[nmap.org/download.html](https://nmap.org/download.html)、[NPSL annotated](https://nmap.org/npsl/npsl-annotated.html)）

---

## 一、实测元数据表（2026-10-03 经 GitHub API 拉取）

| 工具 | 仓库 | stars | 许可证 | 语言 | 最新发布 | 最近推送 |
|---|---|---|---|---|---|---|
| nuclei | projectdiscovery/nuclei | 31,687 | MIT | Go | **v3.11.1** (2026-08-08) | 2026-10-02 |
| katana | projectdiscovery/katana | 17,613 | MIT | Go | v1.7.0 (2026-08-05) | 2026-09-29 |
| ffuf | ffuf/ffuf | 16,801 | MIT | Go | — | 2026-09-26 |
| subfinder | projectdiscovery/subfinder | 14,552 | MIT | Go | v2.16.0 (2026-08-22) | 2026-09-25 |
| nuclei-templates | projectdiscovery/nuclei-templates | 13,051 | MIT | — | — | 2026-10-03 |
| amass | owasp-amass/amass | 15,250 | **Apache-2.0**（GitHub 显示 NOASSERTION） | Go | **v5.1.1** (2026-04-07) | **2026-07-19** ⚠️ |
| masscan | robertdavidgraham/masscan | 26,061 | **AGPL-3.0** | C | **1.3.2 (2021-01-31)** ⚠️ | 2026-04-23 |
| httpx | projectdiscovery/httpx | 10,443 | MIT | Go | v1.12.0 (2026-09-08) | 2026-09-23 |
| ZMap | zmap/zmap | 6,390 | Apache-2.0 | C | **v4.4.0** (2026-05-29) | 2026-08-28 |
| naabu | projectdiscovery/naabu | 6,275 | MIT | Go | v2.6.1 (2026-05-05) | 2026-09-28 |
| gau | lc/gau | 5,112 | MIT | Go | — | 2026-03-20 |
| waybackurls | tomnomnom/waybackurls | 4,564 | **无许可证** | Go | — | **2024-05-01** ⚠️ |
| uncover | projectdiscovery/uncover | 3,072 | MIT | Go | v1.2.1 (2026-05-20) | 2026-08-31 |
| dnsrecon | darkoperator/dnsrecon | 3,076 | GPL-2.0 | Python | — | 2026-09-18 |
| gospider | jaeles-project/gospider | 3,001 | MIT | Go | — | **2024-04-21** ⚠️ |
| zgrab2 | zmap/zgrab2 | 2,189 | NOASSERTION | Go | **v1.0.0 (2025-12-04)** | 2026-09-21 |
| dnsx | projectdiscovery/dnsx | 2,887 | MIT | Go | v1.3.1 (2026-08-31) | 2026-09-29 |
| xsstrike | s0md3v/XSStrike | 15,210 | GPL-3.0 | Python | — | 2025-04-26 |
| tlsx | projectdiscovery/tlsx | 1,147 | MIT | Go | v1.4.0 (2026-09-07) | 2026-09-07 |
| fofax | xiecat/fofax | 840 | GPL-3.0 | Go | — | 2026-03-06 |
| **RustScan** | **bee-san/RustScan** | 20,492 | **GPL-3.0** | Rust | 2.4.1 (2025-02-23) | 2026-10-03 |

---

## 二、工作原理（协议层 / 数据包层）

### 2.1 Nmap：状态机扫描 + NSE

**TCP SYN 半开扫描（-sS）**：发送 SYN，收 SYN-ACK 判 open，收 RST 判 closed，超时判 filtered。**不完成第三次握手**，因此不占用内核 socket、不消耗目标侧连接表 —— 这是它分不清「无监听」与「被 SYN Proxy 伪装」的根本原因（见 §5.2）。

**TCP Connect（-sT）**：完整三次握手，内核接管 socket，无需 root，但每个连接有真实状态、会在目标侧留下 `established` 记录，IDS 更容易捕获。

**ACK 扫描（-sA）为什么慢**：ACK 扫描判定依据是"目标是否回 RST"——**回 RST 说明端口可达（closed），不回说明被过滤（filtered）**。它无法区分 open 和 closed，因为 open 端口收到裸 ACK 时的行为取决于内核实现（多数回 RST）。

因为 `filtered` 只能靠**超时**判定，而超时成本固定（naabu 默认 `-timeout 1000` ms），Nmap 官方建议给 ACK 扫描设更短超时。这意味着 ACK 扫描的耗时本质上被"等待超时"支配 —— 大量 closed/filtered 端口时，速度远慢于 SYN 扫描（后者 open 立即回 SYN-ACK、closed 立即回 RST，只有真过滤才超时）。

**ACK 扫描在现代网络已基本失去存在价值**：它既不能发现 open 端口（除非配合 -sS 分段），又必然产生全端口流量、更易触发 IDS。社区共识是"仅用于穿透 stateless firewall 判断主机是否在线"（`-PA`）。

**服务指纹（-sV）**：`nmap-service-probes` 定义探针（明文匹配 / 正则 / 版本提取），配合 `totalwaitms`/`tcpwrappedms` 计时器和 `matches`/`portversion`/`probeonly` 指令逐条比对。**这套数据库受 NPSL 约束**，直接读取 `nmap-service-probes` 即构成"衍生作品"。

**NSE**：Lua 脚本引擎，可在 pre-rule（发包前）、port-rule、host-rule、post-rule 四阶段介入 —— 本质是把"发什么包/怎么判"外置成可编程逻辑。

**2026 年 Nmap 的真实变化**（来源：[HackTricks Nmap Summary](https://book.hacktricks.wiki/sw/generic-methodologies-and-resources/pentesting-network/nmap-summary-esp.html) 转述官方 changelog + openSUSE 打包记录）：

- **7.94 起**：可探测被 DTLS 包裹的 UDP 服务（对 IoT/ICS 管理协议很重要，这类设备普遍用 DTLS 而非裸 UDP）
- **7.95**：新增 grpc / mysqlx / remotemouse / tuya 等指纹，新增 `iec61850-mms`、`hartip-info` 等 ICS 向 NSE 脚本；OS 指纹匹配改进（允许 TCP 选项中的范围字符串）；每次重试用新源端口加速 OS 检测
- **7.96 起**：正向 DNS 查询并行化，大 hostlist 显著加速
- **7.95 修了 CVE-2026-58058**：构造的 IPv6 响应带截断扩展头会触发越界读与崩溃（来源：[openSUSE commit 记录，2026-07-28](https://mail-archive.com/commit@lists.opensuse.org/msg145084.html)）—— 扫描 IPv6 目标时值得注意

### 2.2 无状态扫描器：ZMap / masscan

**ZMap 的核心洞见**：有状态扫描的内存占用是 **O(N)**（每个未完成连接都要 socket + 定时器 + 连接跟踪表项）。ZMap 把会话状态**编码进报文本身** —— 用 TCP 初始序列号（ISN）承载"这是我发给哪个 IP 的"，或 ICMP identifier 承载。发包线程发完即忘，收包线程独立比对源 IP/端口/ISN 回填。**内存因此是 O(1)。**

**地址生成用 32 位 IPv4 空间的循环乘法群**：取随机原根 g，对全空间做排列，伪随机顺序恰好访问每个地址恰好一次。这比顺序递增 IP 优越得多 —— 顺序扫描会打满相邻路由器队列并直接触发子网 IDS 阈值告警，而群排列天然负载分散，**且统计上可证明覆盖完整**（研究用途需要"任何时刻已覆盖确定比例"，随机扫描做不到这一点）。

**性能路径**：绕过内核栈，用 **PF_RING ZC（Zero Copy，直接网卡访问）+ netmap**，把发包与包生成线程解耦。中文技术文档《ZMap 扫描机制剖析》对此有准确的原理解读（来源：[腾讯云社区转载](https://cloud.tencent.com.cn/developer/article/1423195)）。

**已知代价**：单包探测意味着单包确认，约 **2% 的响应丢失**（无状态 + 高速发包下的丢包无法重传校正）。1.37 Mpps @ 1Gbps（社区/二手资料，未独立验证）。

**masscan**：架构与 ZMap 同源（自研异步 TCP/IP 栈），但**支持多端口同时扫** —— 这是与 ZMap（单次扫描单端口）的本质区别。**AGPL-3.0** + 网络服务传染条款：内部 SaaS 产品通过网络提供服务需开源全部代码。

### 2.3 ProjectDiscovery 套件

**naabu**：`-s SYN` 为默认。root 下用 SYN，**非 root 自动降级为 CONNECT 扫描**（文档示例输出中可见 `[INF] Running SYN scan with root privileges` / `Running CONNECT scan with non root privileges`）。默认 `-rate 1000` 包/秒、`-c 25` 工作线程。官方文档明确警告：*"Increasing it while processing hosts may lead to increased false-positive rates"*。

支持 ASN 输入（`echo AS14421 | naabu`）、SOCKS5 代理、`-passive`（走 Shodan InternetDB API 查被动开放端口）、`-exclude-cdn`（识别 cloudflare/akamai/incapsula/sucuri 后仅扫 80/443）。IPv6 需接口配好 `inet6` 地址与默认网关，root 下走 SYN、非 root 走 CONNECT。

**httpx**：从 httprobe 演进的多探针 HTTP 工具。默认 https，失败自动回退 http。

- **默认开启的探针**：URL / IP / Title / CNAME / Status Code / Content Length / TLS Certificate / CSP Header / Content Line & Word Count / Location / Web Server / Response Time / **Body Hash** / **Header Hash** / URL Scheme
- **默认关闭**：`favicon hash`、`JARM hash`、`ASN`、`CDN`、`HTTP2`、`WebSocket`、`Ports`、`Paths`、`Virtual host`、`Raw HTTP`、`Redirect chain`

技术栈识别基于 **Wappalyzer 数据集**；favicon 走的是 **Shodan 风格的 mmh3(favicon_bytes) + base64** 方案（未能抓到 httpx 官方文档该页，404；此点来自社区实现惯例，**标记为未完全核实**）。

`header hash` / `body hash` 是发现同源资产的实用手段 —— CDN 背后多域名同源检测。

**katana**：爬虫，默认**无 JS 引擎**（需 headless 模式才执行 JS），这对内网 SPA 覆盖率影响很大。

**tlsx**：TLS 证书解析 —— SNI、证书链、有效期、签名算法、JARM（JA3 类指纹）。**tlsx 是当前最适合做 TLS 层资产梳理的工具**：比 Nmap 的 `-sV` 更专注，且 MIT。

### 2.4 被动收集原理

**subfinder**：**纯被动**，只调用第三方 API/网页，**不对目标发任何包**（官方 README：*"passive model guarantees speed and stealthiness"*）。数据源涵盖 crtsh（证书透明度）、github、shodan、zoomeye 等，需自备 API key。

支持 `-rls "hackertarget=10/s,shodan=15/s"` **按源分别限速** —— 这点很重要，共享 IP 批量跑 subfinder 极易被 CT 日志和搜索引擎风控封禁。

**uncover**：不是扫描器，是 Shodan/Censys/FOFA 等的 CLI 客户端。**实测支持 14 个引擎**：

```
shodan, shodan-idb, fofa, censys, quake, hunter, zoomeye,
netlas, criminalip, publicwww, hunterhow, google, driftnet, daydaymap
```

**对中国从业者特别重要的一点：FOFA（北京百马汇）、Quake（360）、Hunter（奇安信）、ZoomEye 在列表里** —— 这些引擎对国内 IDC/政务系统的收录远优于 Shodan/Censys。

**Amass v5 架构**（官方仓库 go.mod + Dockerfile 实测）：不再是单体命令，而是拆成 **9 个二进制**：`amass, oam_enum, amass_engine, ae_isready, oam_subs, oam_assoc, oam_viz, oam_track, oam_i2y`。

核心依赖三个模块：`owasp-amass/open-asset-model`（资产类型）、`asset-db`（存储）、`resolve`（解析）。数据流变成"资产 → OAM 记录 → 写库 → 后续查询数据库而非重跑发现"。

**许可证是 Apache-2.0**（直接拉取 LICENSE 原文确认："License: Apache2.0"，Copyright 2017 Jeff Foley）。GitHub API 显示 NOASSERTION 是因为子组件有独立许可证，**不必因此认为它不能商用**。

**Amass 的真实状态警示**：v5.1.1 发布于 2026-04-07，**最后推送 2026-07-19（约 2.5 个月前）**，而 v4.2.0 → v5.0.0 之间隔了**近 2 年**（2023-09 → 2025-08）。发布节奏以季度甚至年计。**项目未归档，但活跃度远低于 ProjectDiscovery 套件。**

选型时若看重维护密度，subfinder 更稳；Amass 优势在于资产库 + OAM 建模 + 可视化（`oam_viz`）。

---

## 三、许可证（商用选型的硬约束）

| 许可证 | 工具 | 商用影响 |
|---|---|---|
| **NPSL** | Nmap | ❌ **明确禁止**将 Nmap 用于/再分发于商业软硬件产品，含 appliance、VM、Docker 镜像。项目方靠卖 Nmap OEM 授权盈利。**仅"读取 nmap-os-db / nmap-service-probes"即被定义为衍生作品**（Gentoo 因此将其 license-mask，Debian 也有对应 bug 讨论）。7.90/7.91/7.92 三个版本可选用旧许可证 |
| **AGPL-3.0** | masscan | ⚠️ 网络服务传染条款。闭源 SaaS 慎用 |
| **GPL-3.0** | RustScan, XSStrike, fofax | ⚠️ copyleft。仅内部工具无碍；链接进闭源产品有风险 |
| **GPL-2.0** | dnsrecon | ⚠️ 同上 |
| **Apache-2.0** | ZMap, zgrab2(NOASSERTION 待核), **Amass** | ✅ 商用友好，含专利授权 |
| **MIT** | 整个 PD 套件 | ✅ 最宽松 |
| **无许可证** | waybackurls | ⚠️ **无 LICENSE = 保留所有权利**，默认不可商用再分发 |

> 注意 Sliver（C2 框架）为 GPL-3.0，RustScan 亦为 GPL-3.0 —— 这两个常被误认为 MIT。

**若要做商业产品**：端口扫描 + Web 指纹用 MIT 套件或 Apache-2.0 的 ZMap 是安全路径；必须用 Nmap 引擎则买 OEM。

---

## 四、优缺点与场景（按工具族）

**Nmap**：覆盖面最广（OS 指纹、NSE、脚本生态、无脚本也能用），是**内网资产梳理的事实标准**，也是唯一能给出可信 OS 指纹的工具。

- 缺点：慢（状态机 + 版本探测串行）、需要 root、NPSL 污染、IDS 特征明确
- 场景：蓝队内网梳理、合规检查、CTF

**masscan / ZMap**：速度换精度。

- **masscan 近年处于"低维护但可用"状态** —— 最后 release 是 2021 年 1 月的 1.3.2，但 commit 持续到 2026-04（最近一次是修 SMB 越界读 segfault）。能用，但不要指望新功能或及时安全修复
- ZMap 反过来维护活跃（v4.4.0，2026-05）
- 场景：大网段端口普查、CTF 大范围扫段

**RustScan**：定位是"nmap 的多线程封装"而非独立扫描器 —— 它做端口发现后把结果 pipe 给 nmap 做 `-sV`。

- **RustScan 本身是 GPL-3.0**，若你打算把它的输出逻辑抄进商业工具，注意许可
- 文档未更新，README 中 Docker 与安装脚本路径指向 `RustScan/RustScan` 而 API 显示 `bee-san/RustScan`（仓库似乎发生过转移），**迁移状态未完全查证，建议直接验证安装路径**

**naabu + httpx + katana**：现代红队流水线（`subfinder → naabu → httpx → nuclei`）的事实标准，全部 MIT、全部 Go、单二进制、全部活跃维护。naabu 的 `-exclude-cdn`、`-passive`、ASN 输入是**蓝队也用得上的功能** —— 内网资产梳理可以直接上这套。

**XSStrike / dnsrecon / fofax / gau / waybackurls**：单点小工具。

- **gospider 最后推送 2024-04、waybackurls 2024-05** —— 这两个已基本停止维护，社区仍有大量使用（尤其 waybackurls 作为被动 URL 收集），但要有心理预期
- fofax 是 GPL-3.0 的 FOFA 客户端，840 stars，规模小

**nuclei-templates 社区生态**：13,051 stars，**每日多次提交**（查询时 2026-10-03 03:25 有推送）。MIT。

这是 nuclei 真正的护城河 —— 模板质量决定检出率，也是最容易被误用的地方（模板含 exploit 类内容时，**未经授权对非自有资产运行 `-severity critical` 模板是刑事风险**）。

---

## 五、专门问题回答

### 5.1 主动 vs 被动的边界：哪些数据被动拿不到

**被动能拿到**：子域名（CT 日志、PassiveDNS、历史解析记录）、DNS 记录、已开放端口的**历史快照**（Shodan/Censys/FOFA 索引）、证书、WHOIS。

**被动拿不到（必须主动）**：

1. **"现在"是否还开着** —— 被动索引必然滞后。网上流传的"Censys 平均 12.3 小时发现新服务、Shodan 76.5 小时"来自一篇 dev.to 文章，**未能独立验证，标记为社区说法**。Censys 官方营销页则自称非云资产每 24 小时、云资产每 4 小时刷新
2. **服务版本与配置** —— 必须发协议握手才能拿到 banner
3. **子域名解析到的 IP 是否仍属于目标** —— DNS rebinding、悬垂记录（dangling CNAME）只能主动验证
4. **WAF/中间件后的真实暴露面** —— 被动看到的是 CDN 边缘 IP
5. **内网可达性** —— 完全不可能
6. **目录/敏感文件、已知漏洞的实际可利用性** —— nuclei 的活儿

**反向边界**：主动扫描会**留下痕迹**（防火墙日志、IDS 告警、WAF 日志、目标侧的 established 记录）。蓝队在生产环境做全量 SYN 扫描会触发安全团队告警 —— **这是授权流程要解决的事，不是技术问题**。

### 5.2 云环境下 Nmap 的实际效果与已知问题

这是本次调研信息增量最大的部分。

**问题 1：AWS Global Accelerator 的 SYN Proxy 导致大规模端口误报**

这是**厂商确认的已知行为**。机制：Global Accelerator 边缘使用**无状态 SYN Proxy**（SYN Cookies）抗 DDoS —— **无论端口背后有无真实服务，都会对任何 SYN 回 SYN-ACK**，但其中编码了 challenge cookie。

扫描器若只做半开 SYN（`nmap -sS`），逻辑"收到 SYN-ACK ⇒ 端口开放"就会把 21/23/179/636/3306/3389/5432/5985 等全部误判为 open。而由于扫描器不回 ACK，SYN Proxy 也就永远不会暴露"该端口无监听"。

**验证方法**：改用完整连接扫描 `nmap -sT -sV -p <port>` —— 会得到 no response，即真实状态。
（来源：[ThoughtFarmer 技术公告](https://helpdesk.thoughtfarmer.com/hc/en-us/articles/50262164179987-Port-Scan-False-Positives-AWS-Global-Accelerator-SYN-Proxy)）

**推广结论**：任何采用 SYN Proxy / SYN Cookie 的 DDoS 防护（不只是 AWS）都会造成同类误报。**蓝队必须要求扫描方用 -sT/-sV 交叉验证，否则告警全是噪声。**

**问题 2：安全组 DROP 导致 "Host is down" 误判**

云上主机默认 drop ICMP，Nmap 主机发现失败会**直接跳过该主机的端口扫描** —— 于是所有云主机都显示 down。解法：`-Pn` 跳过主机发现。**这是新手在云上用 Nmap 最常见的第一个坑。**

**问题 3：NAT 会话表老化**

家用级 NAT（如 OpenWrt）在 TCP 空闲约 60s 后清除映射，导致半开连接（SYN→SYN-ACK）无后续 ACK 时被归类为 filtered。（来源：CSDN 问答，**社区说法，未独立验证**）

**问题 4：RST rate limiting 反制**

下一代防火墙（如 Palo Alto PAN-OS）默认对高频 SYN 返回**伪造 RST**，Nmap 会把本应 filtered 的端口误判为 closed。（**社区说法**）

**关于阿里云**：**没有找到**关于阿里云特有扫描行为的权威一手资料。国内云厂商的文档可及性较差。**不做断言。**

**云上扫描的根本性局限**：从公网扫云上资产，扫到的是**安全组/网络 ACL 允许的公网入口**，不是"主机上真实监听的服务"。

要回答"这台机器实际开了什么"，唯一权威方法是登录主机执行 `ss -lunp` / `ss -ltnp`。**扫描给你的是"从互联网视角可达什么"，这两者永远不等价** —— 这点应写进任何资产梳理报告的方法论章节。

### 5.3 HTTP/2 与 HTTP/3 (QUIC) 带来的扫描盲区

**核心盲区：绝大多数端口扫描器根本不看 UDP/443。** Nmap/naabu/masscan 的全端口扫描会对 UDP 发探测包，但 UDP 探测天然不可靠（无响应 = open|filtered，无法区分），因此**默认端口列表里几乎不含 UDP/443 的可靠判定**。

结果是：一个只开放 HTTP/3 的服务，TCP/443 关闭，扫描器报 "filtered"，你完全看不到它。

而 HTTP/3 的部署率在快速上升 —— 浏览器通过 HTTP/1.1/2 响应里的 `Alt-Svc` 头或 DNS HTTPS 记录（RFC 9460）得知服务端支持 HTTP/3，然后切到 QUIC。**结果是：同一个站点，TCP 探测和浏览器实际使用的协议可能完全不同。**

**QUIC 给防守方带来的连带盲区**（有实证支撑）：QUIC 加密了传输层头部本身（包号、CID 轮换全在密文里），SNI 位于加密的 CRYPTO frame 内，配合 ECH 后**明文里连服务器名都看不到**。连接用 CID 而非四元组标识，CID 可客户端随时轮换，**基于四元组的 beaconing 检测直接失效**。

2026 年 8 月 Seqrite 披露的 Operation QUICSILVER（针对缅甸外交部人员的 Go 后门 QUICAgent）就是利用 UDP/443 做 C2 隐蔽信道。
（来源：[TechTimes, 2026-08-18](https://techtimes.com/articles/324886/20260818/china-linked-backdoor-hides-c2-traffic-quic-spy-myanmar-diplomats.htm)）

**选型启示**：

- 对**资产测绘**：必须准备 UDP/443 探测能力（ZMap 有 UDP 探针模块；**zgrab2 无 QUIC 模块 —— 其 35 个模块里没有 QUIC，这是个功能空白**）
- 对**防守**：不要盲封 UDP/443（会打断 CDN 和浏览器），改用 QUIC-aware 检查点
- 对**红队**：QUIC 既是隧道也是检测规避面，值得单独评估

### 5.4 AI 用于指纹识别：现状比宣传落后很多

**必须澄清**：针对 favicon hash + ML 做了专门检索，**返回结果几乎全是 anti-detect 浏览器和指纹浏览器营销 SEO 垃圾**，声称"AI 浏览器指纹识别准确率 85-90%""FingerprintJS 开源版 60-80%、商业版 99.5%"。

**这些是厂商自我宣传数字，不是可独立验证的技术评估**，且指的是"浏览器设备指纹"（反欺诈/反爬场景），**与资产测绘的"Web 技术栈识别"是完全不同的问题**。

**没有找到任何可信的、关于 ML 用于 favicon hash / HTTP 指纹识别的 2026 年权威基准或误报率研究。**

**实测到的实际情况**：

- httpx 的技术栈识别**仍是基于 Wappalyzer 数据集的规则匹配**，不是 ML
- favicon hash 是**确定性哈希**（Shodan 风格的 mmh3 + base64），零学习成分。它的**误报率来源是根本性的**：favicon 只有几百字节，不同应用共用同一图标（尤其是框架默认图标、CSS 框架默认 favicon）必然碰撞。**这是哈希本身的性质，不是模型精度问题**
- **唯一真实的 2026 年 ML 动向在 nuclei**，且是实测确认的：nuclei v3 加入了 `-llm` 旗标做**语义匹配**。完整参数（从源码 README 拉取）：

```
-llm                          enable llm matchers and extractors (semantic matching)
-llm-provider string openai, ollama, llamacpp, vllm, lmstudio, groq, openrouter, together
-llm-model / -llm-base-url / -llm-timeout (默认 30s)
-llm-max-calls int            maximum llm calls per scan (默认 5000)
-llm-concurrency int          默认 4
-llm-cache                    默认 true
```

配套 commit `llm matchers and extractors on all protocols`（2026-10-01，仓库最新 commit）—— **语义匹配已扩展到所有协议**。

同时 nuclei 支持本地 ollama/llamacpp/vllm/lmstudio，**这对数据不出境的合规要求是关键卖点**。

**结论**：把 "AI 指纹识别" 写进选型报告要谨慎。目前**可查证、可落地的仍是规则+哈希**；ML 在资产测绘侧的真实位置是 nuclei 的语义匹配（用于漏洞响应内容判定，而非资产指纹）。

### 5.5 eBPF 加速扫描：没有找到证据

检索 eBPF/XDP 2025-2026 的进展，得到的是 XDP/DPDK 在**流量处理与 DDoS 清洗**上的数据（XDP_NATIVE DROP 约 15 Mpps @30% CPU、Cloudflare/Facebook/Cilium 生产部署）。但：

- **没有找到任何主流资产测绘工具采用 eBPF/XDP 做扫描加速**。ZMap/masscan 走的是 **PF_RING ZC / netmap / DPDK** 这条用户态 + 零拷贝路径，不是 eBPF
- **技术上也说得通**：eBPF/XDP 的优势是"对每个进来的包做一次快速决策"。扫描器的工作是"向 42.9 亿个地址各发一个包并收响应"，瓶颈在**发包侧的批量吞吐与网卡驱动的 DMA 效率**，属于 eBPF 不解决的路径。XDP 更适合的是"在本机作为入口过滤器丢弃不需要的包"
- 少数与扫描相关的 eBPF 用法是**主机侧发现**（观测本机 outbound 连接以反推暴露面），而非网络侧扫描

**2026 年真实的性能竞争点**在：ZMap v4.4（2026-05）、10/25G 网卡 + netmap/PF_RING，以及**云上分布式扫描**（Censys 多 PoP）。这是选型时更值得关注的方向。

---

## 六、法律边界：中国法律下的实际风险

以下均为**公开司法材料，非推测**。

**《刑法》第 285 条**（非法侵入计算机信息系统罪 / 非法获取计算机信息系统数据、非法控制计算机信息系统罪 / **提供侵入、非法控制计算机信息系统程序、工具罪**）：

- 第 1 款：针对国家事务/国防建设/尖端科技领域系统，3 年以下
- 第 2 款：针对其他系统，情节严重 3 年以下，情节特别严重 **3-7 年**并处罚金

**司法解释的量化门槛**（两高《关于办理危害计算机信息系统安全刑事案件应用法律若干问题的解释》第 1 条）：非法控制计算机信息系统 **20 台以上**即构成"情节严重"。

⚠️ **注意这个门槛远低于很多工具的默认行为** —— 一次 `naabu -p-` 对一个 /16 打全端口，就可能越过这条线。

**两个直接判例**：

**1. 董某案**：租赁境外虚拟主机，远程运行扫描软件，**多次对县政府信息网站扫描**（被防火墙拦截），被查获。法院认定构成非法侵入计算机信息系统罪，**判处有期徒刑 9 个月**。

注意：**扫描本身即被认定为"侵入"的实施行为**，即使未成功。
（来源：[中国宁波网·网警说法，2025-03-31](http://www.cnnb.com.cn/dwhzlm/system/2025/03/31/030659015.shtml)）

**2. 丁某案**：购入"可绕过服务器防火墙"、非法获取用户昵称/UID/sec_uid 的爬虫软件，包装转售。无锡梁溪区法院以**提供侵入计算机信息系统程序罪**判**有期徒刑一年六个月，缓刑二年**。

法官明确阐释认定"专门用于侵入的程序工具"的三个要素，特别指出"是否专门用于侵入"要**结合是否具有其他合法用途**。
（来源：[搜狐转载人民法院案例库案例，2024-09 入库](https://www.sohu.com/a/873453003_362042)）

**给从业者的实操结论**：

1. **端口扫描在中国司法实践中已被明确作为犯罪行为的实施环节**，不是"未造成后果就无罪"。第 285 条第 3 款（提供侵入工具罪）尤其值得警惕 —— **分发/售卖扫描工具并明知他人用于侵入，是独立罪名**
2. **书面授权是唯一可靠的抗辩来源**，且授权范围必须具体到：目标 IP/CIDR 段、允许的协议端口、允许的时间窗、**允许的扫描类型**（是否允许 SYN 半开、是否允许 UDP 探测、是否允许 DoS 类脚本）。**口头授权在争议中无效**
3. **云环境特别危险**：公有云上存在大量**不属于你的**实例（他人托管的 SaaS、扫描器作者的测试机、你不知道的影子资产）。对云厂商网段做整段扫描极易打到第三方并触发云厂商风控与报案。naabu 支持 ASN 输入，**用 ASN 前务必确认该 ASN 内所有 IP 的归属**
4. **红队测试窗口必须是书面且可核验的**，最好有甲方书面邮件或工单号
5. nuclei 的模板库中包含大量 exploit/内网横向类模板。**对非自有资产运行高危模板 = 明确的高风险行为**，误触可能导致数据泄露并触发刑事报案

---

## 七、选型建议（速查）

| 场景 | 推荐组合 | 理由 |
|---|---|---|
| **蓝队内网资产梳理** | Nmap（-sT 内网合规）+ naabu + httpx + tlsx | MIT 全覆盖，OS 指纹只有 Nmap 能给；tlsx 专精证书层 |
| **蓝队公网暴露面监控** | uncover（FOFA+Quake+Hunter+Censys 多引擎）+ nuclei + tlsx | 国内引擎覆盖是 Shodan/Censys 补不了的；nuclei 社区活跃 |
| **红队外部打点（授权内）** | subfinder → naabu → httpx → katana → nuclei | 全 MIT，管道化，全中文资料最多 |
| **大网段端口普查** | ZMap（研究/普查）+ masscan（多端口，注意 AGPL） | ZMap 维护活跃；masscan 低维护但可用 |
| **商业产品集成** | MIT（PD 套件）+ Apache-2.0（ZMap/Amass），**避开 Nmap NPSL 与 AGPL/GPL** | NPSL 明确禁商用嵌入 |
| **CTF / 大范围扫段** | RustScan + nmap；ZMap 扫单端口找彩蛋 | RustScan 有速率自适应与端口随机化（-g 传参 nmap） |
| **数据不出境** | nuclei `-llm-provider ollama/llamacpp` + 自建 Wappalyzer 指纹 | nuclei v3 实测支持本地 LLM 端点 |

**红旗清单**：

- waybackurls（无许可证，2024-05 停更）
- gospider（2024-04 停更）
- masscan（release 停在 2021）
- XSStrike（2025-04 停更）
- Nmap（版本节奏慢但 CVE 修复及时，CVE-2026-58058 于 2026-07 修复）

---

## 八、来源清单

**实测拉取（GitHub REST API，2026-10-03）**

- `api.github.com/repos/{projectdiscovery/nuclei,httpx,naabu,katana,subfinder,dnsx,tlsx,uncover,nuclei-templates,owasp-amass/amass,zmap/zmap,zmap/zgrab2,robertdavidgraham/masscan,bee-san/RustScan,jaeles-project/gospider,s0md3v/XSStrike,darkoperator/dnsrecon,xiecat/fofax,ffuf/ffuf,lc/gau}` + `/releases/latest`
- `raw.githubusercontent.com/owasp-amass/amass/master/LICENSE`（Apache-2.0 原文）
- `raw.githubusercontent.com/projectdiscovery/{nuclei/dev,uncover/main,subfinder/dev,naabu}/README.md`
- `nmap.org/download.html`（7.991 / Npcap 1.89）

**官方文档 / 许可**

- Nmap NPSL：https://nmap.org/npsl/ 、https://nmap.org/npsl/npsl-annotated.html 、https://nmap.org/man/man-legal.html
- NPSL 争议：https://issues.nmap.org/2199 （Gentoo license-mask，Debian bug 972216）
- Censys 扫描与数据集：https://support.censys.io/hc/en-us/articles/360038761891-Research-Access-to-Censys-Data （ZMap 已弃用、3,500+ 端口/100 协议）
- Censys ASM 定位：https://censys.com/blog/internet-intelligence-foundation-exposure-management-ctem/
- naabu 用法：https://docs.projectdiscovery.io/opensource/naabu/usage 、/running
- httpx 探针清单：https://github.com/projectdiscovery/httpx
- ZMap/ZGrab2 原理：https://cloud.tencent.com.cn/developer/article/1423195 、https://github.com/zmap/zgrab2

**技术分析 / 厂商材料**

- AWS Global Accelerator SYN Proxy 误报：https://helpdesk.thoughtfarmer.com/hc/en-us/articles/50262164179987-Port-Scan-False-Positives-AWS-Global-Accelerator-SYN-Proxy
- ZMap 架构分析（USENIX Security 2013）：https://vulnerabilityscanner.info/scanners/zmap
- Nmap 云环境误判（社区）：https://ask.csdn.net/questions/9660559 、https://stackharbor.com/en/knowledge-base/nmap-network-service-scanning
- QUIC 盲区：https://techtimes.com/articles/324886/20260818/... （Seqrite Operation QUICSILVER，2026-08-18）、https://www.sycope.com/?p=4852/
- eBPF/XDP 基准：https://api.emergentmind.com/topics/extended-berkeley-packet-filter-ebpf-technology

**法律材料**

- 中国宁波网·网警说法（董某案，9 个月）：http://www.cnnb.com.cn/dwhzlm/system/2025/03/31/030659015.shtml
- 人民法院案例库·丁某案（提供侵入工具罪，1 年 6 个月缓 2 年）：https://www.sohu.com/a/873453003_362042
- 最高检/最高法司法解释原文（经上述案例引用）

**明确存疑 / 未核实**

- Censys 12.3h vs Shodan 76.5h 平均发现时间：仅见 dev.to 文章，无一手来源
- httpx favicon hash 的具体实现（mmh3+base64）：官方文档页 404，依据社区惯例推断
- 阿里云特有扫描行为：未找到权威资料，不做断言
- **"favicon + ML 指纹识别的 2026 基准与误报率"：不存在可信来源**，检索结果均为反欺诈/设备指纹领域的营销内容，与资产测绘无关
- RustScan 仓库从 `RustScan/RustScan` 到 `bee-san/RustScan` 的迁移状态：未查证

---

**免责声明**：本报告的速率、pps、检测时间等数字中，部分来自社区与二手资料，已逐项标注。许可证条款以项目官方 LICENSE 为准，涉及商业产品的合规判断请咨询法务并购买官方授权。
