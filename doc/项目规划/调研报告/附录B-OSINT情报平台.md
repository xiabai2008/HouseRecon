# 附录 B：OSINT 情报平台 / 网络空间搜索引擎完整调研

> 本附录是《信息收集工具全景调研报告》的分领域原始调研，聚焦 Shodan / Censys / FOFA 等网络空间搜索引擎与商业情报平台。
> **面向中国安全从业者的工具选型深度报告**
> **查询与核验时间：2026-10-03**（所有定价数字均以此时间为准，变化极快，采购前必须复核）
> **标注约定**：**【已查证】**＝来自厂商官方页面或官方文档；**【社区说法】**＝来自第三方评测/博客/从业者经验，未获官方确认；**【存疑】**＝来源相互冲突或无法验证。

---

## 〇、先纠正三个前提错误

选型文档里最常见的三个错误，读者先记住：

### 1. Quake 不是绿盟的

Quake（`quake.360.cn`）是 **360 网络安全响应中心**自研的网络空间测绘系统【已查证，GitHub QuakeAPI / 多个工具站】。

绿盟（NSFOCUS）对应产品线是 CTEM / 威胁与漏洞管理平台 TVM / 绿盟云，其资产测绘能力**不以 "Quake" 品牌对外提供**【已查证，nsfocus.com.cn 官网产品目录】。

搞错这条，采购沟通会直接对不上人。

### 2. 指纹哈希算法不是 MD5

Shodan 的 `http.favicon.hash` 是 **MurmurHash3 x86 32 位**，且输入不是原始图标文件，而是**按 RFC 2045 每 76 字符插入换行的 Base64 字符串**，输出为**有符号整数**【已查证，blog.shodan.io/deep-dive-http-favicon 官方原文】。

Shodan 官方文档没写清楚换行规则，Jorian Woltjer 通过 preimage 实验（`http.favicon.hash:1337` 全网唯一命中他的站点）反推出来。

**这条被无数中文教程抄错，导致自建工具算出的 hash 永远对不上。**

### 3. Lattica 与 ByteMeAI 不是 OSINT 平台

检索到的 Lattica 是加密货币 AI 推理市场（`ai.lattica.org`，2026-08 上线，BTC/LTC 支付、12% 抽成）；ByteMe 是中贝通信/武汉大公智能的"数字分身"AI 产品（`ai.byteme.chat`）。

**两者均与代码搜索/网络空间测绘无关** —— 这两个名字很可能来自需求方信息源有误，建议澄清后重新评估。

---

## 一、平台对比总表

### 1.1 国外 / 全球引擎

| 平台 | 数据来源与采集原理 | 索引类型 | 指纹识别原理 | 免费额度【已查证】 | 定价【已查证】 | 关键局限 | 国内可用性 |
|---|---|---|---|---|---|---|---|
| **Shodan** | 自有分布式扫描节点主动扫全网 IPv4，约 1,200–2,000 个常用/高危端口，抓 banner；每周至少覆盖全网一次 | service banner、SSL 证书、历史 IP/端口时间线、HTTP 截图、ASN/组织 | banner 文本 + `product:`/`version:` 结构化抽取 + SSL 证书 + favicon hash(MMH3) + HTTP 头 + `http.html` 正文 | 无账户 10 条结果；注册 50 条；**InternetDB API 完全免费** | Freelancer **$49 一次性**；Small Business **$69/月**；Corporate **$359/月**；Enterprise **$1,099/月** | 仅 ~1,237 端口（非标端口盲区大）；新服务发现延迟 ~76h；免费层不含 `vuln`/`tag` 过滤器 | **需代理**，直连慢；`api.shodan.io` 不稳定 |
| **Censys** | ①全 IPv4 的 100+ IANA 端口持续扫 ②AWS/Azure/GCP IP 清单日扫 ③**Predictive Scanning** 用当前+历史数据生成动态目标做**全 65,535 端口 port walk**（官方称贡献 40%+ 新发现服务）④自动协议识别 | 主机/服务、**TLS 证书（最强项）**、Active DNS 历史、CPE、WHOIS/ASN、威胁情报(155+恶意家族 C2)、Reputation Score、CensEye pivot | 服务 banner + 证书字段 + CPE + 自动协议识别（HTTP 返 SSH banner 则断连改用 SSH 握手）+ `services.http.response.favicons.md5_hash` | **250 查询/月**、API 0.4 req/s、主机历史 1 周、每查询 500 条、Collections 2 个 | 已改积分制，起步 **$100**；Individual $100 起，Enrichment API 20K calls/day；ASM/Gov 询价 | CPE/正则语法门槛高于 Shodan；免费 250 查询/月远不够批量 | 直连可用但慢，部分时段超时 |
| **ZoomEye**（知道创宇） | Xmap（设备探测）+ Wmap（网页探测）双引擎，约 3,828 端口 | 主机、Web、证书、**漏洞关联**、蜜罐、Tor 标签、"钟馗之眼"攻击者画像 | 协议/端口解析 + 证书 SAN/CT 日志 + 漏洞库联动（`vul.cve`） | 5 结果/日、3,000/月、**无 API**、无历史数据 | Personal **$190/年**；Professional **$1,090/年**；Business **$10,990/年**；Corporate **$100,000/年** | **免费层无 API 是硬伤**；数据刷新慢于国内同业；多域名账号不互通 | 直连，快 |
| **BinaryEdge** | 瑞士 SaaS，主动全网扫描 + **蜜罐 + DHT 网络采集**，主打流式 Firehose API | 端口、服务 banner、OS、SSL 证书、IoT 设备 | 通用 banner + 证书 | 极低（第三方配置注释称 250 次/月，有效期仅 1 个月）【存疑】 | 纯订阅，无公开价目 | **只做 SaaS 无私有化**，数据全存海外；**国内 IP 覆盖不全** | 访问不稳定，国内覆盖差 |
| **Onyphe** | 自有全网扫描 + 被动 DNS + WHOIS + 威胁馈送（IOCEAN 分类）+ 暗网/paste 索引；**EU 数据驻留** | 主机、被动 DNS、inetnum、威胁列表、paste | 通用 banner + 威胁上下文标注 | 1 查询/分钟、10 条结果【社区说法】 | Eagle **$10/月**、Whale **$50/月**【社区说法】；AlternativeTo 另称一次性 $59 或 $99–999/月 —— **口径冲突** | 知名度低、集成与文档少；非欧洲区域密度低于 Shodan | 直连可用 |
| **Netlas** | 自有全网扫描 + DNS/IP WHOIS + SSL + CT 日志；提供 Private Scanner 与批量数据集 | 互联网扫描、DNS、SSL、IP/Domain WHOIS、CVE | 通用 banner + 1,000+ 设备/软件 tag（Business 起） | Community 永久免费：**50 请求/日、2,500 结果/月、单次下载 200 条** | Freelancer **$49/月**（年付 $40.83）；Business **$249/月**（年付 $207.50） | 免费层 50 请求/日极紧；中文资料少 | 直连可用 |
| **LeakIX** | 自有扫描器 + **社区研究者志愿回传**（明确自我定位为漏洞披露平台，用"赞助研究者"换志愿者提交数据） | 主机、服务、Critical/RCE 漏洞插件、子域 API | 通用 banner + 插件化漏洞匹配 | €0：**25 结果页、3,000 API 请求/月、结果延迟 15–30 天、无支持** | Bounty Hunter **€25/月**；Enterprise **€350/月**（均含 Critical/RCE 插件） | **免费层 15 天延迟对应急响应致命** | 访问不稳定 |
| **FullHunt** | ASM 定位：资产发现 + 子域枚举 + 拼写错误域名监控 + DNS 情报 | 资产、子域、DNS、品牌风险 | 通用 banner | **10 API credits/月**【存疑，官网未直接核实】 | Builder $149/月；Freelancer $49/月；ASM $1,499/月【存疑】 | 免费额度小到基本不可用 | 直连可用 |
| **PublicWWW** | 网页源码/HTML/JS **全文检索**（CMS、邮箱、JS 密钥、后台路径） | 前端可见源码、HTML/JS 内容 | 源码关键字匹配（不扫端口） | 可检索但结果受限 | 未取到公开价目页【存疑】 | 只覆盖前端可见内容 | 直连可用 |
| **grep.app** | 实时索引 50 万+ 公开 GitHub 仓库 | 代码片段、行级上下文 | 字符串/正则匹配 | **完全免费、无需账号、无查询上限** | 免费 | **只覆盖公开 GitHub**，无代码导航 | 直连可用 |
| **Sourcegraph** | 跨仓库代码索引，支持云端与自托管 | 代码定义/引用/依赖图 | 跨仓库符号与文本检索 | 云端免费层受限（约 200 万公开仓库） | 完整能力需企业版【社区说法】 | 学习曲线陡；免费层能力有限 | 直连可用 |

### 1.2 国内平台

| 平台 | 归属 | 数据来源与原理 | 索引类型 | 指纹识别原理 | 免费额度【已查证】 | 定价【已查证】 | 关键局限 | 国内可用性 |
|---|---|---|---|---|---|---|---|---|
| **FOFA** | 奇安信 | 全球分布式节点主动扫描 IP/端口/协议/服务/证书/网页特征，**35 万+ 指纹库（13 大类/130+ 子类）** | 主机、域名、端口、Web 组件、证书、favicon icon_hash、**网站特征聚类 FID**、**规则聚类 APP**、云资产标识、三方 SDK、ICP 备案 | icon_hash + HTTP 头/正文/标题 + 证书 + Web 组件特征 | 300 查询/月、3,000 条/月、44 语法、**仅可见前 60 条、不可导出、无 API** | 个人 **¥199**（年付 ¥119/月）；专业 **¥999**（年付 ¥719/月）；商业 **¥9,999**（年付 ¥7,199/月）；企业 V2 **¥36,000/月起**。F 点：1 万 ¥35 / 10 万 ¥350 / 40 万 ¥1,200，有效期 1 年 | 免费层形同虚设；**免费/个人/专业版均不可商用** | 直连，**快** |
| **Hunter**（鹰图） | 奇安信（与 hunter.io 无关） | 主动全网探测 + **整合奇安信本土威胁情报与 ICP 备案**；支持 SaaS 与**私有化部署**（数据不出网） | 公网 IP/端口/域名/Web 组件/设备指纹、备案 | 通用指纹 + 备案关联 + 威胁情报标签 | 据称每日 10 条【社区说法】 | 未查到官方公开价目页 | 免费版据称仅子域检索、无 API【社区说法，可信度一般】 | 直连，快 |
| **Quake** | **360** | 覆盖 1000+ 协议（含工控/区块链/IoT）；城市级资产分布地图；**等保合规报告**；工控协议可解析从站 ID、寄存器信息 | 主机、协议、漏洞、备案、ASN、网段 | 深度协议交互解析（工控能力强）+ 漏洞库联动 | 注册赠积分，需企业邮箱审核 | 企业版据称**年费 10 万+**【社区说法】 | **门槛最高，个人用户基本不可用** | 直联，快 |
| **天眼查** | 腾讯系 | 工商 + 司法 + 股权 + 风险，覆盖约 3 亿家企业 | 工商登记、股东、股权、司法案件、行政处罚、年报 | 不适用（非测绘工具） | 仅基础工商信息，股东名单/司法/全在付费墙 | **VIP ¥548/年、SVIP ¥2,688/年**（个人） | **无英文界面、不支持国际信用卡、需中国手机号实名** | 直联 |
| **企查查** | 苏州 | 同上，关系图谱更清晰 | 同上 | 不适用 | 同上 | **VIP ¥388/年**（连续包年 ¥358）、**SVIP ¥1,799–1,800/年**；三年 SVIP ¥3,599；企业 VIP ¥348/人/年起、SVIP ¥1,580/人/年起 | 数据延迟 1–3 工作日 | 直联 |
| **七麦数据** | 北京七麦科技 | iOS App Store + 国内安卓市场（华为/小米/OPPO/vivo/应用宝）榜单监测 | 榜单、ASO 关键词、下载量预估、评论情感 | 不适用（非测绘工具） | 免费版 0 元 + 赠 7 天 VIP | **VIP ¥4,680/用户/年；SVIP ¥15,600/年；企业版 ¥34,320/年** | **只覆盖 App 生态**；下载量是算法估算非官方披露 | 直联 |
| **CHINAZ** | 站长工具 | 域名/主机/网站信息、SEO | 域名与主机归属 | 不适用 | 未取到 | 未取到当前价目页【存疑】 | — | 直联 |
| **百度/必应国内版** | 搜索引擎 | 中文网页内容检索，可辅助定位弱资产（`site:` 找遗留测试页面） | 网页内容 | 不适用 | 免费 | 免费 | **不是测绘引擎** —— 无端口/证书/指纹维度 | 直联 |

---

## 二、国外平台逐一详解

### Shodan

**采集原理【已查证，book.shodan.io + about 页】**：分布式扫描节点对随机 IPv4 地址发起探测，预选约 1,200–2,000 个常用/高危端口；端口响应即抓取 banner（协议元数据），解析为结构化字段。

**明确不做的事**：不尝试认证、不执行 payload、不绕过任何技术屏障。

**定价【已查证，account.shodan.io/billing，2026-10-03 实测抓取】**：

| 计划 | 价格 | 查询额度/月 | 扫描额度/月 | 监控 IP | 结果页数 |
|---|---|---|---|---|---|
| Freelancer | **$49 一次性** | 100 | 100 | 16 | 20 |
| Small Business | $69/月 | 10,000 | 5,120 | 5,120 | 20 |
| Corporate | $359/月 | 200,000 | 65,536 | 65,536 | 200 |
| Enterprise | $1,099/月 | 无限 | 无限 | 无限 | 200 |

⚠️ **2026 年定价结构已变**：Freelancer 是 **49 美元一次性买断**，不再是"$49/月"。这个旧口径在 theHarvester 等工具文档里仍在流传。

另有**完全免费的 InternetDB API**，无需账户即可查单 IP 轻量元数据。

**真实局限**：免费层 10 条结果形同虚设（`shodan count` 报 2,400 条时你只能看到 10 条）【已查证，bugbounty.info】；仅扫约 1,237 端口【社区说法，plisio.net / bugbounty.info，方向可信但具体数字未获官方口径确认】；新服务发现延迟约 76 小时【社区说法】；免费层不含 `vuln` 和 `tag` 过滤器。

**国内可用性**：需挂代理 —— 中文技术社区几乎每篇 Shodan 教程开头都写"需要挂梯子"【社区说法，多篇 CSDN 博客一致】。API 域名直连不稳定。

### Censys

**采集原理【已查证，docs.censys.com 官方文档】**：三层扫描策略，这是它和 Shodan 的本质差异 ——

1. **Global scan**：全部 IPv4 的 100+ 个 IANA 常用端口持续快速扫描
2. **Cloud provider scans**：AWS/Azure/GCP 的 IP 与常用端口清单，每日至少扫一次
3. **Predictive Scanning engine（预测扫描）**：用前两层的当前+历史数据生成动态目标，做**全部 65,535 端口的 port walk**。官方称**预测扫描贡献了今天互联网上 40%+ 的新发现服务**，新增约 1.07 亿个服务
4. **Automatic protocol detection**：即使端口非标准也分析响应判断真实服务。例：HTTP 请求返回 SSH banner，则断开并改用 SSH 握手重试

刷新节奏：每天检查全部 **30 亿+ 服务**的观测时间戳，超过 24 小时未命中的立即重扫，高价值服务数据**平均年龄约 16 小时**。

**定价【已查证，censys.com/pricing 与 censys.com?p=2780，2026-10-03】**：现行是 **Censys Credits 积分制**，积分包起步 $100。分 Community / Individual / ASM Platform / SecOps / Threat Hunting。

- Community 档：**250 查询/月、API 0.4 req/s、主机历史 1 周、每查询可见 500 条、Collections 2 个**
- Individual 档起 **$100**，API 20K calls/day

⚠️ **【存疑】一项需自行验证的变更**：第三方 AI 技能库 2026 年记录称 Censys 新 Platform **收紧了免费 API**，`search` 和 `aggregate` 端点在免费账户返回 403，网页 UI 仍全功能可用但 API 的搜索/聚合需付费【来源为 claudepluginhub 技能文档，非官方公告】。若你依赖 Censys API 做自动化，免费层可能已不可用，**务必先实测**。

**JARM 补充**：Censys 官方提到 **JA4+ 指纹**用于威胁情报归因。JARM 与 JA3 的关键区别在于 ——

- **JA3/JA3S 是基于流量被动分析**（服务器面对不同客户端产生不同 JA3S）
- **JARM 是完全主动的**：向 TLS 服务器发送 **10 个精心构造的 ClientHello**（不同 TLS 版本、密码顺序、扩展组合），采集 10 个 ServerHello 响应后哈希成 **62 字符指纹** —— 前 30 字符是每个 ClientHello 对应的密码与 TLS 版本选择结果（"000" 表示拒绝协商），后 32 字符是累积扩展的截断 SHA256（忽略 x509 证书数据）【已查证，Salesforce JARM 原始论文 + 多篇技术解读】

这套方法之所以有效，是因为 ServerHello 的差异会反映操作系统、OpenSSL 版本、库调用顺序、自定义配置。

### ZoomEye / BinaryEdge / Onyphe / Netlas / LeakIX / FullHunt / PublicWWW / grep.app / Sourcegraph

这几个平台的完整数据来源、索引、指纹、额度与局限已在上文 **1.1 总表** 逐列列出，此处只补充三个关键判断：

**LeakIX 的模式值得单独注意**：它把自己定位为"漏洞披露平台"，用"赞助研究者"机制换取社区志愿者每月数百份免费报告。这决定了它的数据新鲜度依赖社区活跃度，也解释了为什么免费层会给 15–30 天结果延迟 —— 志愿者贡献的数据本身就有滞后。**做应急响应时这个延迟是不可接受的**，必须上付费档。

**Onyphe 的价格口径冲突必须并列看待**：osintbench 2026-04-03 评测给的是 Eagle $10/月、Whale $50/月【社区说法】；AlternativeTo 给的是一次性 $59 或订阅 $99–999/月【社区说法】。两者差了一个数量级，官网 `/pricing` 路径本次返回 404。**采购前必须直接联系厂商。**

**grep.app 对安全从业者价值极高**：完全免费、无需账号、**无查询上限**、实时索引 50 万+ 公开 GitHub 仓库、支持正则、返回行级上下文。在"某个内部函数名是否被泄露到公开仓库"这类问题上，它比 GitHub 原生搜索快且可靠得多。**局限也很明确**：只覆盖公开 GitHub，无 GitLab/Bitbucket，无代码导航。

**searchcode** 未在上表的原因：本次查证出现**两个互相冲突的描述** ——

- staquest.com（2026-09）称其为"免费无限量、索引 4000 万+ 项目、243 种语言、覆盖 GitHub/GitLab/Bitbucket 及 Google Code 历史归档"
- itechguides.com（2026-09-20）称其为"免费 beta 版，含仓库分析、secret scanning、MCP/REST API 集成 Claude Code/Cursor 等"

**两种描述可能对应不同版本**【存疑】。SaaSHub 非官方状态页显示近 30 天 uptime 100%，**未下线**。

---

## 三、国内平台逐一详解

### FOFA（奇安信）

**采集原理【已查证，fofa.info/vip 官方会员页 + 多个技术站字段说明】**：全球分布式节点主动扫描 IP/端口/协议/服务/证书/网页特征，通过 **35 万+ 指纹库（13 大类 / 130+ 子类）**建立资产索引。

⚠️ **注意一处表述冲突**：部分第三方文章称"FOFA 自身不主动向目标发包、仅基于已抓取指纹检索"，而官方教程称"主动扫描"。

**综合判断：数据采集由官方扫描节点完成，用户侧为纯索引检索（合规性较好），但平台方是主动扫描方。** 这个区分对你判断"我在 FOFA 上查询是否合规"很关键 —— 你在检索已公开索引，与你自己向目标发包探测是两件不同的事。

**定价【已查证，fofa.info/vip，2026-10-03 实测】**：

| 档位 | 价格 | 查询请求/月 | 数据量/月 | 可用语法 | API 导出字段 | 并发 | 商业用途 |
|---|---|---|---|---|---|---|---|
| 注册用户 | ¥0 | 300 | 3,000 条 | 44 | — | — | ❌ 仅非商业 |
| 个人版 | **¥199**（年付折 ¥119/月） | 10,000 | 10 万条 | 60 | 37 | 1 req/s | ❌ |
| 专业版 | **¥999**（年付折 ¥719/月） | 80,000 | 80 万条 | 62 | 41 | 1 req/s | ❌ |
| 商业版 | **¥9,999**（年付折 ¥7,199/月） | 900,000 | 900 万条 | 全部 | 48 | 2 req/s | ✅ 5 用户 |
| 企业版 V2 | **¥36,000/月起** | 可定制 | 500 万条（页面）/5 千万（API） | 全部 | 全部 | 5 req/s | ✅ |

另售 F 点：1 万点 ¥35 / 10 万点 ¥350 / 40 万点 ¥1,200，**有效期 1 年**。所有付费档附 FOFA AI+（专业版起 5 次/天，企业版 50 次/天）。

**免费用户限制【已查证，dragonftop.github.io FOFA 使用手册，2026-07】**：仅可见前 60 条、不可导出、不可用 API。免费版视图统计（地区分布、端口分布）是完整的 —— 学习语法够用。

### Hunter（奇安信，鹰图）

**数据来源**：主动全网探测，公网 IP/端口/域名/Web 组件/设备指纹；**整合奇安信本土威胁情报与 ICP 备案信息**；支持 SaaS 云端与**私有化部署**（数据不出网，适合保密单位）。据称高危漏洞筛选规则更新 ≤30 分钟。

**关键局限**：**免费版据称仅支持子域检索、无 API 接口，漏洞详情需企业账号**【社区说法，toutiao 技术文】。这条如果对你成立，等于免费层无法接入任何自动化流程。

**第三方定价普遍不准**（有称"每日免费 10 条"、有称"约 ¥260/月"，均【社区说法】），**未查到官方公开价目页 —— 采购前必须实测**。

**独有维度**：ICP 备案信息关联 + 攻击溯源（IP 历史攻击行为）+ 与奇安信威胁情报中心数据源打通。

这是它相对 FOFA 的差异化：**FOFA 强在指纹识别，Hunter 强在威胁情报与备案维度。**

### Quake（360）

**数据来源与特色**：覆盖 1000+ 网络协议（含工控、区块链、IoT）；提供**城市级资产分布地图**、**等保合规检查模板**、漏洞 POC 验证；支持批量导出与筛选；**对工控协议能解析出从站 ID、寄存器信息等内层信息** —— 这在 IoT/ICS 场景优势明显。

**门槛是所有国内平台里最高的**：需企业邮箱注册审核，**个人用户基本不可用**，企业版据称年费 10 万+【社区说法】。接口设计带明显"工程师味"，数据维度多，适合深挖细节。

### 天眼查 / 企查查（工商与股权）

**核心差异**：企查查关系图谱更清晰（追踪多层控股链的实际受益人更有用），天眼查裁判文书全文检索更强。覆盖约 3 亿～3.2 亿家企业。**95% 的供应商核实工作两者结果相同**【社区说法，chinesecheck.com】。

**免费 vs 付费的真实分界【已查证，chinesecheck.com】**：

**免费（注册后）**：

- 企业名称（含英文名）、统一社会信用代码、法定代表人、注册资本、注册日期与状态、注册地址、经营范围、**第一层股东**
- 诉讼/专利/商标的 **tease 计数**

**付费才有**：

- 完整股东链与实际受益人（UBO）识别
- **年报（含员工数、营收区间、社保数据 —— 对尽调极关键）**
- 完整裁判文书与执行记录、行政处罚
- 异常经营与严重违法清单、历史变更（地址/资本/股东变更）
- **银行账户冻结记录**、股权出质与抵押、完整知识产权组合
- 海关进出口记录、分公司与子公司图谱
- 风险评分与实时监控提醒

**结论：只用免费层无法 meaningfully 完成任何一次供应商核实。**

**企查查价格已获官方侧交叉验证**：石家庄市律师协会 2026-10 官方采购公告明确 VIP 市场原价 **¥388/人/年**、SVIP **¥1,800/人/年**【已查证，sjzlawyer.org.cn】；sensortower App 内购显示 1 年 VIP ¥388、连续包年 ¥358、3 年 ¥768、1 年 SVIP ¥1,799【已查证】。

### 七麦数据 / CHINAZ / 百度必应国内版

**七麦数据【已查证，36dianping.com 第三方定价库】**：免费版 0 元 + 赠 7 天 VIP；**VIP ¥4,680/用户/年、SVIP ¥15,600/年、企业版 ¥34,320/年**。定位是**移动 App 数据与 ASO**，覆盖 iOS App Store + 国内主流安卓市场，提供榜单监控、关键词覆盖扫描、下载量预估、评论情感分析。

⚠️ **两个使用提醒**：

1. **下载量是算法模型估算，不是官方披露数据**，用于尽调或投资判断时必须注明
2. **它只覆盖 App 生态，不涉及主机/网站测绘**，与本报告其他工具不可互相替代

**CHINAZ**：本次未取到当前价目页【存疑】，不臆测数字。

**百度/必应国内版**：**它们不是测绘引擎** —— 无端口、无证书、无指纹维度，唯一的价值是用 `site:` 定位遗留测试页、暴露的管理后台、被遗忘的静态资源目录。作为补充手段可以，不能作为资产盘点依据。

---

## 四、商业情报平台：溢价到底值不值

### Maltego —— 图谱分析到底解决了什么

**先直接回答"数据是不是大半靠第三方 API"：是的。** 官方文档明确其 Graph 通过 **120+ Data Providers、12,000+ 多种检索方法**访问外部数据源【已查证，docs.maltego.com】，分两类机制：

- **Data Pass 模块**：官方预装打包数据（POI、CTI、暗网、加密货币、企业信息），按 credit 消耗
- **Connectors**：100+ 个预置连接器，**用你自己的 API key 直连第三方**（Shodan、VirusTotal、Have I Been Pwned 等），费用由你承担

**图谱分析真正解决的痛点**（这是它不可替代的地方，也是免费工具完全做不到的）：OSINT 的瓶颈从来不是"查不到"，而是**关系链断裂**。手工做这件事是这样的 ——

> 拿到一个域名 → WHOIS 查注册人 → 反查同邮箱的其他域名 → 查这些域名的证书 → 从证书 SAN 交叉 → 得到新的关联 IP → 重复

Maltego 把这个循环**自动化成 Transforms**，并把每次结果沉淀成可复用的图。手工完成一轮可能需要数小时到数天，图谱分析是分钟级。

**Maltego 支持项对金融、法律、调查类用户有实质意义**：Maltego Cases（云端加密案件库 + 文件加密 + 协作）、Maltego Evidence（社交媒体匿名存证 + sock puppet）、Maltego Monitor（实时社媒监控 + 情感分析）。**面向 POI 调查的 Maltego One 只有 Basic+ 及以上才有。**

**定价【已查证，maltego.com/pricing，2026-10-03】**：

| 档位 | 价格 | Credits/月 | 关键能力 |
|---|---|---|---|
| Basic | **€0** | 200 | Maltego Graph CE + 有限商业数据 |
| Basic+ | **€0**（需政府/机构邮箱申请） | 1,000 | + Maltego One / Graph Browser / Search |
| Entry | **€3,000/年** | 10,000 | + Hunchly 证据采集 |
| Professional | **€7,500/年**（≤5 席） | 20,000 / 40,000 | + 全量商业数据 + 无限 Maltego Search |
| Enterprise | 询价 | 按需 | + Monitor / Evidence / 专属数据源 / 培训 |

**真实局限（社区反馈，可信度较高）**：

- **入门成本极高** —— 免费 200 credits 基本只够试手，严肃调查起步 €3,000/年
- **成本相对自建脚本偏高** —— 有观点指出 CT 日志 + DNS 查询自己写脚本能完成同样的工作
- **版本升级破坏集成** —— 4.7 版本曾导致 OpenCorporates、Shodan 等 API 集成断裂，企业用户抱怨明显【社区说法，klover.ai 2026 深度分析引述】
- **学习曲线陡、UI 复杂** —— 这是社区里最一致的两点评价
- 注意定价页多处标注 **"AVAILABLE SOON"** —— 部分功能（含 AI Assistant）尚未完全交付

**支持方的反驳视角**：高阶套餐打包的商业数据访问确实省掉了采购和管理多个独立数据源订阅的成本。

### SpiderFoot HX

**架构**：发布/订阅模型，200+ 数据源模块；一个模块的结果自动触发后续模块，形成级联自动化收集。4.0 引入 YAML 可配置关联引擎，支持预定义规则自动关联数据并识别潜在漏洞。

**双版本**：开源社区版（免费，MIT）+ 云端托管的 SpiderFoot HX。

**定价【社区说法，klover.ai 2026 引述】**：Freelancer **$79/月**、Business **$249/月**、Enterprise **$899/月**，按并发扫描数与用户数分级。称 HX 版本扫描速度约为开源版的 10 倍。⚠️ 这三个价格**未从 spiderfoot.com 官方页面直接核实**。

**与 Maltego 的定位差异**：SpiderFoot 强在**自动化广度覆盖**（一个扫描跑完 200+ 源，输出 HTML/CSV 报告）；Maltego 强在**交互式关系图谱**（人工判断"这个连接是不是真的相关"）。做批量 recon 用 SpiderFoot，做案件调查用 Maltego。

### Intelligence X

**数据来源【已查证，cybervendorguide.com，2026-09 复核】**：泄露数据与已发布内容的搜索引擎与档案库，按 email / domain / IP / CIDR 等 selector 检索。来源包括 **paste 站点、数据泄露、stealer logs、Tor 与 I2P 暗网、WHOIS 记录、Usenet 及公开 Web**，并**保留所索引数据的副本**（archive 模式）。2018 年由 Peter Kleissner 创立，总部布拉格。

**定价【已查证，同上；免费层细节来自 grokipedia】**：

| 档位 | 价格 | 限额 |
|---|---|---|
| Free | €0 | **2 selector 搜索/日、5 phonebook 查询/日**；无下载、无 CSV/ZIP 导出、无告警、**无 API** |
| Researcher | **€2,500/年** | 200 selector 搜索/日、10 告警、有限导出、fair-use API |
| API | **€7,000/年** | 500 搜索/日、100 告警、完整 API |
| Identity Portal | **€10,000/年** | 反向查询、逐行结果、泄露账户导出 |
| Enterprise | **€20,000/年** | ≤5 用户、无限告警、5,000+ 搜索/日 |

⚠️ **关键限制**：**付费前必须知道 —— leaks 和 stealer logs 这两类最有价值的数据桶，仅付费账户可见**，免费层基本用不上。另对新用户有 7 天全功能试用期。

**伦理摩擦点**：因为它做永久归档，用户常在检索中发现自己的泄露数据（明文密码、浏览器 cookie、内部系统路径）而感到受伤害。平台有正式的 takedown 政策，需提供数据所有者身份与对应记录的唯一 System ID。

### SpyCloud / Cortex XMDR / Flashpoint / Intel 471 / Anomali / Rocketlane / Preos

**SpyCloud 的核心认知：它卖的不是数据，是"时间差"。**

SpyCloud 官方文档说得最直白：常规暗网监控扫描的是**可索引的暗网论坛**，而 SpyCloud **"recapture"（重新捕获）** 的是**私有渠道数据** —— 闭源分发的 infostealer 日志、公开分发前就被截获的钓鱼工具输出（phishing kit output）、通过私密 access broker 交易的泄露数据【已查证，spycloud.com/mssp-mdr 官方】。因此数据在犯罪时间线上**比暗网监控早得多**，这是结构性优势，不是数据量差异。

**定价**：

- **不公开定价**。Vendr 合同数据：**中位买家付 $19,920/年**（区间 $10,800–$157,360）【已查证，vendr.com/marketplace/spycloud】。Investigations 版按席位定价，每席位含 200 次 API 查询。**MSSP/MDR 最低参与门槛 $10,000/月**【已查证，spycloud.com/audience/mssp-mdr】
- 提供 **80+ 个 Maltego Transforms** 和预置 Jupyter Notebook —— 说明它明确定位为"Maltego 的数据源"，而非替代品
- 官方宣称平均回本周期 3.5 个月；LendingTree 称节省 60% SOC 时间【厂商自述，未经独立验证】

**暗网监控市场整体价格带【存疑，decryptiondigest.com 第三方整理，非厂商报价】**：中端 $500–3,000/月；Recorded Future Illuminate 轻量版 $1,000–3,000/月；Recorded Future 完整平台 **$12,000–25,000/月**；Flashpoint **$8,000/月起**（面向金融机构、政府、大型企业，深度论坛情报 + 人工采集）；Intel 471 **$10,000–25,000/月**；ZeroFox $5,000–20,000/月。

**Cortex XMDR**：Cortex XDR 定价需联系销售（Custom）。第三方成本估算：实施服务 $5,000–30,000、年存储保留 $5,000–15,000、超量计费 1.2–1.5 倍、**终端数量年增 12–20%**【存疑，costbench.com，非官方报价】。**它本质是 XDR 而非 OSINT 平台**，与本主题关联弱，列出仅为完整性。

### TPRM 类：SecurityScorecard / Black Kite / UpGuard / Panorays

| 平台 | 定价状态【已查证除非标注】 | 免费层 |
|---|---|---|
| **SecurityScorecard** | **完全不公开**。免费层仅自监控 + **20 次搜索查询额度**，Business 版 14 天试用后需联系销售。第三方整理入门约 $5,999/年起，企业级 $50K–500K+【存疑】 | 有（仅自监控） |
| **UpGuard** | **唯一价格相对透明**：免费 5 家供应商；Breach Risk 自助 **$250/月**起（按员工数 $500/$2,000）；Vendor Risk Standard **$1,750/月**（年付，50 家供应商）；Breach Risk Enterprise **$19,999/年起**【已查证，upguard.com，2026-09 核实】 | 有（5 家供应商） |
| **Black Kite** | **不公开**。第三方引用中端市场约 **$29,000/年**【存疑，来源为公开评测站点】 | 一次性小规模评估 |
| **Panorays** | **完全不公开**，必须走销售。分 Continuous 360° / Bi-Annual 360° / Continuous Posture / Smart Questionnaires 几档，第三方整理 $30K–150K/年【存疑】 | 无 |

⚠️ **一个必须提醒的选型陷阱**：SecurityScorecard / UpGuard / Black Kite / Panorays **互相做 SEO 竞品对比页**，那些带 AI 生成标注的对比表明确写着"价格区间为分析师估算，基于公开评测与社区反馈区间"。**这类内容用于选型不可靠。**

同一位评测者还指出，部分厂商在自家站点上宣称"覆盖 350M+ 组织信号""99.1% 验证准确率"，但这些数字标注为 **"厂商自述，未经独立基准验证"**。

**结论：TPRM 类的溢价买的是什么？** 买的是**持续监测 + 自动告警 + 供应链关系图谱 + 董事会级报告**。如果你只是需要一次性评估几个供应商的公开安全状况，SecurityScorecard 的免费层 + 手工查 ICP/裁判文书/海关信用就能覆盖 80%。

---

## 五、代码与密钥泄露

### 5.1 原理分层（这是选型的核心逻辑）

| 层次 | 代表工具 | 检测方式 | 联网验证 | License |
|---|---|---|---|---|
| **规则优先** | Gitleaks、git-secrets、detect-secrets | 正则 + 熵 | 否 | MIT / Apache-2.0 |
| **验证优先** | TruffleHog | 800+ typed detector + **调厂商 API 实测凭据是否存活** | **是** | AGPL-3.0 |
| **流式监听** | shhgit、gitrob | GitHub Events API 实时监听 + 签名匹配 | 否 | MIT |
| **平台侧** | GitHub Secret Scanning | 推送时拦截 + 历史扫描 + 通知厂商吊销 | 是（partner 模式） | 商业 |

### 5.2 TruffleHog 的杀手锏与代价

它是唯一原生支持 **live verification** 的开源工具 —— 扫到疑似 Stripe key 会**真的去调 Stripe API 验证是否存活**。

这把误报模型从"形似"改成"是否可用"，是质的差别：**已验证存活的 AWS key 是五级火情；匹配了模式但三年前就轮换掉的字符串只是噪音。**

**代价有两条**：

1. 全量历史扫描比 Gitleaks **慢 5–10 倍**，且可能触发厂商限流
2. **你的疑似密钥会被发送到外部厂商 API** —— 开源可审计，但企业合规上仍需安全团队签字。有些团队正因为这一点放弃 TruffleHog，改用 Gitleaks + 人工 review

### 5.3 Gitleaks

Go 单二进制，零依赖，pre-commit 友好。v8 后检测引擎从纯正则升级为**正则 + 熵 + allowlist** 组合，规则生态有专门社区仓库（gitleaks-rules）做贡献。

输出 SARIF，有官方 GitHub Action 与 pre-commit hook。`gitleaks detect` 默认遍历**完整 commit 历史**（不只工作区）。

**已知缺口（社区吐槽，实操可信）**：默认规则集覆盖 AWS/GCP/Azure/Stripe/GitHub/Slack 等主流厂商，但**对国内云厂商（阿里云、腾讯云）和细分 SaaS 新版 key 格式覆盖不全**，需自写规则 —— 而写正则"不误报不漏报"实际很折腾。

熵值检测会把 JWT、加密后的随机串、某些 base64 二进制标成疑似 secret，产生需人工 review 的噪音（`--no-banner --redact` 能减少视觉噪音，但熵检测的误报是方法论固有代价）。

### 5.4 其他工具与维护状态

**2026 年生态变化【已查证，freebuf.com 2026-07 横评】**：

- **TruffleHog 的 live verification 从实验特性变成默认推荐路径** —— 它直接改变了 secret scanning 的误报模型
- **Gitleaks v8 引擎升级为正则+熵+allowlist 组合**
- **detect-secrets（Yelp，Apache-2.0）维护放缓** —— GitHub 活跃度从 2024 下半年起明显下降，最近一年 commit 频率比 Gitleaks 低一个数量级。若押注它，要做好长期自己维护 detector 的准备。它的 **baseline 机制（`.secrets.baseline` 存已知误报哈希）比 Gitleaks 的 allowlist 更结构化**，这是它设计上更强的一点
- **git-secrets（AWS）基本停在 AWS 时代** —— 默认规则**只认 AWS key 模式**（AKIA开头 + secret key 长度），其他厂商一概不认。FreeBuf 那篇文章开头就有个真实案例：实习生把 Stripe test key 推进 main 分支，git-secrets 没拦下来。规则语法原始，社区几乎无人贡献非 AWS 规则。**把它当 2015 年的 AWS 专用工具看就好**
- **Semgrep Secrets（LGPL-2.1）**：若团队已用 Semgrep 做 SAST，加 secret scanning 规则是零成本集成，统一规则语法
- **GitGuardian ggshield（MPL-2.0）**：ML+正则+熵，但**社区版砍掉了 live verification 和 dashboard**，只留检测引擎本体

**shhgit / gitrob（流式监听，独特价值）**：

- **shhgit（MIT）**：监听 **GitHub Events API** 实时抓取 push 事件，克隆、扫描、销毁，**近实时**发现密钥。120 个签名 + Shannon 熵检测（默认阈值 5.0，可调；设 0 禁用）。另支持 `--search-query` 直接搜特定内容、Slack webhook 推送、`--local` 模式扫本地目录。GitHub API 硬限速 **5,000 请求/小时/账户**。⚠️ **最后 commit 约 1 年前，已不维护**【社区说法，starlog.is 技术分析】
- **gitrob**：以 GitHub 用户/组织为目标，克隆仓库分析提交历史，用 **100+ 敏感文件签名**（simple signature 匹配文件名/扩展名 + pattern signature 匹配正则）检测，通过本地 Web 界面展示结果，工作池并发处理

**shhgit 的价值不在于"现在用"，而在于它证明了公开面密钥暴露的速度** —— 大多数团队扫描工具跑的是 nightly，而密钥推上去几小时内就已被爬取索引。**这个速度差就是"代码泄露监控成为标配"这个趋势的实证。**

### 5.5 GitHub Secret Scanning 定价

**【已查证，docs.github.com 计费文档 + 微软 Learn + startupstash 2026-09 整理】**

- **公开仓库：secret scanning 免费且默认自动启用**（含历史扫描与 push protection）
- **私有/内部仓库**：需 **Secret Protection，$19/活跃提交者/月**；Code Security 另计 **$30/活跃提交者/月**
- **计费单位定义**："活跃提交者" = 过去 **90 天**内向启用了该功能的仓库有 commit push 的**唯一**用户。GitHub App bot 与机器账号不计入
- 一个提交者只用一个 license，与他贡献多少个仓库无关
- 通过 GitHub Enterprise Importer 迁移的仓库，**只对迁移后的 commit 计费，历史贡献不计入**

⚠️ **命名已变更**：GitHub 现在把 Advanced Security 拆成 **Secret Protection**（secret scanning + push protection + partner patterns + 自定义 pattern + validity checks）和 **Code Security**（CodeQL + Copilot Autofix + 安全 Campaign + 高级 Dependabot）两条独立产品线。2024 年前后流传的 "$49/活跃提交者/月"是旧捆绑口径【已查证 toolradar 指出拆分，startupstash 明确警告不要把 AWS Marketplace 的 $100,000 当作费率】。

### 5.6 历史 URL 挖掘

**waybackurls（TomnomNom）**：只打 Wayback CDX API，最简单。

```bash
waybackurls target.com | grep -E "\.(php|asp|aspx|jsp|json|xml|yaml|env|sql|bak|log|config)$"
```

**gau v2（Get All URLs）【已查证，pkg.go.dev 官方文档】**：多源聚合 —— **Wayback Machine + Common Crawl + AlienVault OTX + URLScan**，覆盖面上 waybackurls 单独使用强得多。

```bash
gau target.com --subs                    # 带子域
gau --providers wayback,commoncrawl       # 指定 provider（可复现、可排障）
gau --from 202201 --to 202212 --fp        # 限定时间窗 + 去重相同端点的不同参数
gau --match-ext sql,bak,zip --mc 200      # 收窄扩展名与状态码
gau --proxy http://proxy:8080             # 走代理
gau --rate-limit-wayback 0.5             # 分别限速各 provider
```

过滤器按 AND 组合，流水线顺序：扩展名白名单 → 正则白名单 → ...

**gospider**：主动爬取 + **JS 端点提取**，与 gau 互补（gau 拿历史 URL，gospider 拿活 URL 与 JS 里的接口）。

**为什么有效（核心洞察）**：应用下线功能时常常不删除后端逻辑。一个 18 个月前"移除"的 `/admin/export` 端点可能仍返回 200 —— URL 只是不再被任何地方链接了。老的 JS 文件在 CDN 上能放很多年。**这些都是活的攻击面。**

⚠️ **合规红线**：历史 URL 挖掘出的已下线端点，**如果现在还返回 200，属于活的攻击面**。用 httpx 之类工具批量验证这些历史 URL，性质上是对第三方目标发起主动探测 —— 必须有明确授权。gau 官方文档自己也强调"仅用于授权域名"【已查证，learn.secbyte.org】。

---

## 六、专项回答

### 6.1 Shodan vs Censys vs FOFA：实际差异与场景选择

| 维度 | Shodan | Censys | FOFA |
|---|---|---|---|
| 扫描广度 | ~1,237 端口 | **全 65,535 端口 + 预测扫描** | 全端口，国内节点 |
| **核心强项** | **ICS/工控/IoT 设备识别**（Modbus/S7/BACnet/摄像头），历史数据最丰富 | **TLS 证书与加密配置**、CPE、学术可复现性、原始数据导出 | **Web 应用/中间件/国产业务系统指纹**、图标哈希、后台管理入口、ICP 备案关联 |
| 发现延迟 | ~76h【社区说法】 | **~12h**（40%+ 服务来自预测扫描） | 官方宣传新漏洞响应快【社区说法】 |
| 全球覆盖 | ★★★★★ | ★★★★☆ | ★★★★☆ |
| **国内资产覆盖** | ★★☆☆☆ | ★★★☆☆ | **★★★★★** |
| 免费额度 | 注册后 50 条结果 | 250 查询/月 | 300 查询 + 3,000 条/月 |
| 入门成本 | $49 一次性 | 免费 | 免费 |
| 国内可用性 | **需代理，慢** | 直连可用但慢 | **直连，快** |

**场景化建议**：

| 场景 | 选择 | 理由 |
|---|---|---|
| **国内政企资产盘点 / 等保检查 / 攻击面梳理** | **FOFA 为主**（+ Hunter 补充威胁情报与备案维度） | 境内节点 + 国产业务系统指纹 |
| **CVE 爆发后评估国内受影响资产** | **FOFA**（国内更新快、语法可组合指纹条件），ZoomEye 的 `vul.cve` 过滤器是第二选择 | — |
| **出海业务 / 全球资产盘点** | **Shodan**（$49 一次性起，API 生态最成熟） | — |
| **证书情报 / SSL 合规 / 子域名资产发现** | **Censys**（证书索引无可替代） | — |
| **工控 / ICS / IoT / 摄像头** | **Shodan**（唯一选择） | — |
| **研究型工作、需要原始数据做时间序列分析** | **Censys**（Raw JSON 可导出，数据可复现） | — |

**为什么 FOFA 在国内资产测绘上被认为更强？** 综合查证与社区口径，三点都有据可查：

**1. 节点与链路优势（最根本的原因）**。国内测绘平台在境内有部署节点和带宽。**从境内节点扫境内 IDC 与从境外扫，路由与回源路径完全不同** —— 境外节点 frequently 被拒绝或拿到不同的 CDN 边缘响应。**结果就是 FOFA 在国内 IP 段的覆盖密度显著更高。**

第三方对比文档说得直接：**"when a target operates in China, Japan, Korea, or Southeast Asia, FOFA often surfaces hosts that Shodan and Censys miss entirely"**，且明确建议"FOFA often shows sparse results for a large org"（对 Shodan 而言）【已查证，bugbounty.info 对比文档】。

这与 Censys 自己的社区说法一致：**"Shodan 每日仅限 10 次搜索，中文支持有限，国内资产更新存在延迟"**。

**2. 指纹库是"中国特色"的**。35 万+ 指纹、13 大类 130+ 子类，其中大量是国产 OA、中间件、小众 CMS、政务/金融系统。Shodan/Censys 的指纹库面向全球主流软件，**这些系统它们认不出来**。

第三方实测记录：某制造业客户测试中，FOFA 通过 SSL 证书关联出 **3 个未在公开文档记载的测试子域名**，而 Shodan 只发现了暴露在公网的 Kubernetes dashboard【社区说法，插件对比评测】。另有实测：FOFA 找国内 CDN 与云服务商、以及**在国际目标上找中文语言管理后台**时优势明显【已查证，bugbounty.info】。

**3. 字段与本地化**。ICP 备案关联、按省份/运营商筛选、证书备案信息 —— 这是合规检查和资产台账的刚需，海外平台完全没有这层数据。Quake 更进一步提供**城市级资产分布地图**与**等保合规报告模板**。

**FOFA 的两个具体技术优势值得单独指出**：

- **模糊图标搜索**（企业版）—— 不必知道精确 hash 即可按图标相似度找同类系统
- **三方 SDK 识别**（商业版）—— 从 JS 指纹反查用了哪些第三方 SDK，对影子资产与供应链梳理有用

**一条务实的实践建议**：**至少用两个**。三者结果集差异巨大且失败模式不同 —— **对同一网段做两次查询取 diff，新出现的资产往往就是配置最粗糙的那批。这是免费获得高价值线索的最便宜方式。**

### 6.2 商业情报平台的溢价到底值不值

**核心判据：数据的时间差是硬价值，数据量的堆叠是软价值。**

**值的情况**：

- **凭据泄露的早期预警**（SpyCloud 的 infostealer 日志 → 账号接管预警）。免费工具完全做不到这个时间差。SMB/初创如果没有这个能力，账号接管和勒索的直接损失可能远超订阅费
- **持续性威胁狩猎 / 供应链尽调 / 案件调查**（Maltego 的关系图谱复利）。做一次性调查，€3,000 起步价不划算 —— 自己手搓 CT 日志 + DNS 查询更便宜

**不值的情况**：

- **只是想"知道我在暗网上有没有被提及"**。这个需求用关键词监控 + 免费泄露库 + 蜜罐能覆盖 80%，不需要 $20K/年
- **TPRM 类**：一次性评估几个供应商的公开安全状况 → SecurityScorecard 免费层 + 手工查 ICP/裁判文书/海关信用足够

**中间地带**：Rocketlane / Preos / Oligo / Searchlight Cyber / Anomali / Recorded Future 均为无公开定价的销售驱动型产品，且被指出"存在被竞品 SEO 站互相刷存在感"的问题 —— **选型时警惕被这类 SEO 内容带节奏**。

**一条务实的路径**：**先用开源组合跑通工作流，量化出"每月真正需要多少次商业数据查询"，再决定买不买。**

```
资产发现：  FOFA 免费层（国内）+ Censys Community（250查询/月，全球）
证书/子域： crt.sh + SecurityTrails 免费层
代码泄露：  grep.app + Gitleaks（防护）+ TruffleHog（验证）
历史 URL：  gau（Wayback + Common Crawl + OTX + URLScan）
图谱：      Maltego Basic（200 credits/月，够试用验证工作流）
工商：      GSXT 官网（免费）+ 天眼查/企查查免费层
```

多数团队会发现**商业查询的实际频次远低于直觉**。

**Maltego 的 €3,000/年起的价格里，有相当部分是这些你本可以自己做的部分** —— CT 日志查询（crt.sh 免费）、被动 DNS、DNS 解析历史、favicon hash（20 行 Python）。

### 6.3 Maltego 图谱分析到底解决了什么

见 **4.1 Maltego** 小节的核心论述。此处只补一句最凝练的：**OSINT 的瓶颈从来不是"查不到"，而是关系链断裂。** 图谱分析把"域名→WHOIS→同邮箱域名→证书→SAN→关联 IP→重复"这个手工数小时的循环自动化成 Transforms，并把每次结果沉淀为可复用的图。**它不可替代的地方不是"查得更全"，而是"把孤立的线索连成可判断的关系网"。**

### 6.4 2026 年 OSINT 与 ASM 融合趋势

**趋势 1：AI/ML 从"辅助"变成"引擎"**

- Censys 的 **Predictive Scanning 已经是主力**：贡献 40%+ 新发现服务，用 ML 从已知服务的当前+历史数据推断新扫描目标
- Censys 上线 **Natural Language Search + AI Assistant**，直接用自然语言提问得到资产级答案
- FOFA 各付费档均带 **FOFA AI+**（专业版起 5 次/天，企业版 50 次/天）
- ZoomEye 内置 **ZoomEyeGPT（AI Search）+ ZoomEye Hub + BugBounty Radar**
- Maltego Graph Browser 版 2.19.0（2026-06）加入 **AI Assistant** —— 但定价页仍标注 **AVAILABLE SOON**，成熟度存疑

**但行业内部并非一致看好。** SecurityWeek 2026 的 EASM 圆桌里，NTT Data 的 Sheetal Mehta 谈 agentic AI 潜力（"映射 IP、供应链、域名、云实例之间的推断关系"）；Barracuda 的 Bekkar 主张"AI 应作为 EASM 的引擎而非助手"；而 Transcend 的 Cardwell 明确说"**AI 不是银弹**，它最有价值的是持续暴露敏感数据在哪，而不是一年一次审计"。CybaVerse CTO Simon Phillips 则指出**防御方与攻击方都能用 AI 找暴露面**，胜负手在于"哪一方对关键暴露有更好的上下文理解"。

**实战建议：把 AI 当噪声削减器（去重、分组、排序），别当发现器。**

**趋势 2：OSINT 与 ASM 深度融合**

Censys 官方定位已从"搜索"转为 **"Internet Map + ASM 平台"**，引入云连接器（AWS/Azure/GCP）、Collections 自动监控、可视化探索面板、EPSS + CISA KEV 驱动的修复优先级排序。

Palo Alto 的 ASM 工具对比（2026）指出核心区分点：**ASM 从外部看，映射的是攻击者能看到什么，而不是你的内部记录声称拥有什么**；三类失败场景最值得投入 —— **并购（继承整套攻击面）、云迁移（新实例先上线后入册）、品牌重命名与域名变更（旧营销子域长期留在 DNS）**。

中国侧研究报告判断：ASM 将从资产发现与漏洞扫描，扩展到 **SaaS 应用、API、第三方依赖、影子 IT、外部身份**的全域数字资产治理；并预计**到 2026 年全球 ASM 市场规模超 30 亿美元，中国市场复合增长率超 40%**【社区说法，renrendoc.com《2026中国网络安全技术演进》】。

**判断：独立 OSINT 搜索平台的形态正在被 ASM 平台吸收。纯搜索（Shodan/Censys 免费层）作为"数据源"存在，价值上升；作为"采购标的"，价值下降。**

**趋势 3：暗网监控成为企业标配，卖点从"提及"转向"凭据有效性"**

这是本轮最重要的变化。传统暗网监控的价值是"我知道有人在论坛提到我" —— 价值可疑。新一代（SpyCloud 为代表）的价值是"**我员工的 infostealer 日志里有这条 session cookie，现在还活着**" —— 这是可直接触发动作的（强制下线会话、强制改密、阻断 C2），而不是报告里的一行字。

SpyCloud 官方还区分了 session hijacking 检测与 credential exposure：前者对应用域名告警以便会话失效，后者针对员工域名。Anomali、Flashpoint、Intel 471、Rocketlane、Preos 的产品线都在往这个方向收敛。

**趋势 4：代码泄露监控从"加分项"变成"标配"**

三个信号叠加：GitHub 把 Secret Protection 独立成产品线（$19/活跃提交者/月）；TruffleHog 的 live verification 成为默认推荐路径；detect-secrets 维护放缓、git-secrets 实质停滞。

**结论：企业级 CI 里没有 secret scanning 已经是合规缺陷，不是技术欠债。** 而 shhgit 这类"监听 GitHub Events API 实时抓公开仓库密钥"的工具从攻击者视角证明了公开面密钥暴露的速度。

---

## 七、合规与法律边界

> ⚠️ 以下为一般性合规提示，不构成法律意见。涉及具体业务请咨询执业律师。

### 7.1 核心分界线：查询 ≠ 使用

**查询公开索引数据本身**（Shodan/FOFA 上检索已收录的 banner、证书、工商信息）通常不构成违法。**但对查询结果采取行动 —— 主动探测、尝试登录、获取数据 —— 性质立刻改变。**

### 7.2 《刑法》第 285 条：核心刑事风险

**第 2 款（非法获取计算机信息系统数据、非法控制计算机信息系统罪）**：违反国家规定侵入计算机信息系统或采用其他技术手段获取其存储、处理、传输的数据，**情节严重的，处 3 年以下有期徒刑或拘役，并处或单处罚金；情节特别严重的，处 3 年以上 7 年以下有期徒刑，并处罚金**。

"情节严重"的司法认定标准【已查证，吴莉律师 legal 解读 + 判例引用】：

1. 获取支付结算、证券交易、期货交易等网络金融服务的身份认证信息 **10 组以上**
2. 获取第(1)项以外的身份认证信息 **500 组以上**
3. 非法控制计算机信息系统 **20 台以上**
4. 违法所得 5,000 元以上或造成经济损失 1 万元以上
5. 其他情节严重的情形

**第 3 款（提供侵入、非法控制计算机信息系统程序、工具罪）**：**开发或销售"用于"扫描/攻击的工具，即使未实际攻击也可能构成犯罪。**

### 7.3 三个真实判例（B 级踩线警示）

| 案例 | 行为 | 结果 |
|---|---|---|
| **青虎浏览器案**（广州黄埔区市监局） | 爬取淘宝/天猫/京东商品数据 **6,731 万条**，存储平台 Cookie（绕过登录安保机制），进行"商品采集/整店采集/搬家上货"并收费会员，**导致平台被实质性替代** | 违反《反不正当竞争法》第 12 条第 2 款第 4 项，**罚款 10 万元** |
| **潘某某案**（常州） | 公司 AI 互动平台爬取小红书数据，销售获客功能并获利（公司未获授权） | 《网络安全法》第 27 条 + 第 63 条，**行政拘留 3 日 + 罚款 5 万元** |
| **"企某"案**（杭州中院 (2020)浙01民终4847号） | 从 GSXT、裁判文书网、执行信息公开网等政府公开网站爬取企业数据形成商业报告，因发布某金融集团"清算信息"有误致其商誉受损 | 认定构成**商业诋损 / 不正当竞争** |

**"企某"案确立的重要边界**：法院明确认定 —— **数据虽来源于公共数据（政府机关依法履职采集制作），但信息的发布和推送行为应当保持与数据原始主体信息的一致性，不得损害数据原始主体的合法权益**。

这意味着：这类平台需承担**信息准确性义务**；同时也提示使用者 —— **你从这类平台获取的数据用于决策时，准确性由平台负责，但你的使用方式（商业诋毁、批量导出、跨主体关联分析）仍可能独立产生法律责任。**

### 7.4 三个更重的刑事风险

**提供侵入工具案（任城区检察院）**：某通信营业厅经营者以 7,500 元购买定制爬虫程序，用于获取其他工号权限内的宽带工单信息 **70 余万组**。提供程序的两名被告人各获**有期徒刑六个月 + 罚金 1 万元**。

**侵犯公民个人信息罪（第 253 条之一）**：使用爬虫窃取快递公司客户信息并出售，法院认定情节特别严重，判处**有期徒刑五年 + 罚金 100 万元**。**非法获取/出售个人信息 50 条以上即可入刑。**

**非法使用爬虫插件案（泰州姜堰）**：某人在网站和 GitHub 发布"秒传链接提取"及"推特媒体爬虫"插件并获利 13,421.59 元，被认定构成"提供专门用于从事危害网络安全活动的程序、工具"，**没收违法所得 + 行政拘留三日**。

### 7.5 行政违法与刑事犯罪的界限

有一起案例的裁量思路值得注意：某行为人**利用系统漏洞获取他人设备数据，造成服务器网络堵塞、无法正常访问**，已有现实危害。公安机关认定其违反《网络安全法》第 29 条，**适用《治安管理处罚法》第 33 条给予行政拘留** —— 理由是：虽造成现实危害，但**尚未达到刑事追诉的裁量标准**（未达"情节严重"）。

**这条给出了重要的裁量参照：行政拘留 → 判刑之间看是否达到"情节严重"。**

### 7.6 数据源合规：工商数据平台的风险已在司法层面确认

天眼查/企查查的数据来源是 GSXT、中国裁判文书网、中国执行信息公开网等政府公开渠道。**但"企某"案确立了重要边界**（见 7.3）。

另需注意《征信业管理条例》第 23 条：**征信机构应当采取合理措施保障所提供信息的准确性**；配合《信息技术大数据术语》(GB/T35295-2017) 与《信息技术数据质量评价指标》(GB/T36344-2018) 两项国家标准 —— 数据产品和服务提供中负有基本注意义务。

### 7.7 涉及个人信息时的硬约束

- 《**个人信息保护法**》第 10 条：禁止非法处理个人信息；第 13 条：处理需取得个人同意（法律另有规定除外）；第 23 条：向第三方提供需**单独同意**
- 《**数据安全法**》第 21 条：数据处理活动应符合社会公德和伦理；第 32 条：任何组织个人收集数据应采取**合法、正当方式**，不得窃取或以其他非法方式获取；第 51 条：境外执法机构调取境内数据需经主管机关批准
- 《**网络安全法**》第 27 条：禁止非法侵入他人网络、干扰网络正常功能、窃取网络数据；第 41 条：网络运营者收集个人信息应遵循合法、正当、必要原则；第 44 条：不得窃取或以其他非法方式获取个人信息

**实操边界**：OSINT 从业者在天眼查/企查查查到的**法人信息**基本可用；但**股东穿透到自然人、实际控制人身份证号、员工联系方式**就进入了个人信息范畴。

### 7.8 AI 不会给你免责

已有明确案例：行为人利用 AI 工具编写自动化攻击脚本。公安机关办案时明确认定 **"AI 作为工具，不改变违法行为的法律性质"** —— 无论攻击脚本是 AI 生成、自主编写、下载还是购买，只要行为人明知或应知其用途而实施，就必须承担责任。

试图以"**代码系 AI 生成**""**不了解技术原理**""**仅作测试**"为由推诿，**均无法规避法律制裁**。公安机关会"固定攻击脚本、网络日志、API 调用记录、目标 IP 清单及数据提取痕迹"作为证据。

### 7.9 给安全从业者的合规操作清单

1. **只查自己或已获书面授权的资产** —— 授权范围应明确包含"主动探测"
2. **保留查询审计记录** —— 注明时间、目的、授权来源。**企业法务可能对员工查询竞品 IP 段有异议**，即使查询本身合法
3. **发现暴露资产走规范披露渠道** —— 走 security.txt、厂商 SRC 或本国 CSIRT，**不要直接"顺手测一下"**
4. **发现泄露凭据立即上报，不使用** —— **拿到了不等于可以用**；使用泄露凭据访问系统是最容易被认定为"情节严重"的行为
5. **漏洞奖金项目也要守边界** —— HackerOne/Bugcrowd 上活跃的赏金项目**明确禁止超出"横幅读取范围"的测试**，违反会被除名
6. **国内 SaaS 版付费前实测免费层** —— 免费层限额与功能表变化很快，本文数字只代表 2026-10-03 状态
7. **涉个人信息的工商数据查询遵守最小必要** —— 不要批量导出自然人信息
8. **不以"AI 生成的""开源工具""仅供学习"为抗辩理由**

---

## 八、来源链接清单

### 8.1 厂商官方（定价与原理的一手来源）

| 平台 | URL | 抓取日期 |
|---|---|---|
| Shodan 定价 | `account.shodan.io/billing` | 2026-10-03 |
| Shodan 原理 | `book.shodan.io` / `about.censys.io` | 2026-10-03 |
| Shodan favicon哈希 | `blog.shodan.io/deep-dive-http-favicon` | 2026-10-03 |
| Shodan 官网 | `shodan.io` | 2026-10-03 |
| Censys 定价（旧版） | `censys.com/pricing` | 2026-10-03 |
| Censys 定价（分层） | `censys.com?p=2780` | 2026-10-03 |
| Censys 扫描文档 | `docs.censys.com/docs` | 2026-10-03 |
| Censys 平台介绍 | `censys.com?p=2706` | 2026-10-03 |
| FOFA 会员与价格 | `fofa.info/vip` / `en.fofa.info/vip` / `fofa.so/vip` | 2026-10-03 |
| ZoomEye 定价 | `zoomeye.ai/pricing` | 2026-10-03 |
| ZoomEye 帮助 | `zoomeye.ai/help` | 2026-10-03 |
| Netlas 定价 | `netlas.io/pricing/` | 2026-10-03 |
| LeakIX 定价 | `leakix.net/plans` | 2026-10-03 |
| Maltego 定价 | `maltego.com/pricing/` | 2026-10-03 |
| Maltego 数据源机制 | `docs.maltego.com/en/support/solutions/articles/15000058711-data-pass-and-connectors-for-maltego-graph` | 2026-10-03 |
| SpyCloud 定价 | `spycloud.com/pricing/` | 2026-10-03 |
| SpyCloud MSSP | `spycloud.com/audience/mssp-mdr/` | 2026-10-03 |
| GitHub 计费文档 | `docs.github.com/en/enterprise-server@3.14/billing/concepts/product-billing/github-advanced-security` | 2026-10-03 |
| 微软 Learn 秘密扫描可用性 | `learn.microsoft.com/zh-hk/training/modules/resolve-github-secret-scanning-alerts-github-copilot-agent/` | 2026-10-03 |
| 企查查价格官方佐证 | `szlawyer.org.cn/news.php?id=3180`（石家庄律协官方采购公告） | 2026-10-03 |
| 企查查 App 内购价 | `app.sensortower.com/overview/878075397` | 2026-10-03 |
| 绿盟产品目录（核实 Quake 归属） | `nsfocus.com.cn` | 2026-10-03 |
| 知道创宇免费试用区 | `yunaq.com/activity/mfsv2022` | 2026-10-03 |

### 8.2 第三方评估（需交叉验证）

| 来源 | URL |
|---|---|
| 三引擎实战对比（bugbounty.info） | `bugbounty.info/Recon/Shodan-Censys-Fofa` |
| 2026 攻击面测绘流程 | `ransomnews.com/?p=586` |
| 攻击者实际使用 Shodan/FOFA | `vectra.ai/blog/how-attackers-use-shodan-fofa` |
| Shodan 中文详解（含端口数、延迟） | `plisio.net/zh/cybersecurity/shodan` |
| Onyphe 评测 | `osintbench.com/tools/onyphe` |
| Onyphe 价格（冲突来源） | `alternativeto.net/software/onyphe/about/` |
| Intelligence X 定价 | `cybervendorguide.com/tools/intelligence-x` |
| Intelligence X 免费层细节 | `grokipedia.com/page/Intelligence_X` |
| searchcode 描述 A | `staquest.com/tools/searchcode` |
| searchcode 描述 B（冲突） | `itechguides.com/products/searchcode` |
| searchcode 状态页 | `saashub.com/searchcode-status` |
| grep.app 评测 | `searchcompared.com/code` |
| SpyCloud 合同价格 | `vendr.com/marketplace/spycloud` |
| 泄露凭据平台横评 | `startupstash.com/top-leaked-credential-detection-platforms` |
| GHAS 定价拆分核实 | `toolradar.com/tools/github-advanced-security` |
| GHAS $49 旧口径（含引用） | `aicodereview.cc/blog/snyk-vs-github-advanced-security` |
| BinaryEdge 国内覆盖评估 | `51dns.com/tool/217.html` |
| Hunter 介绍 | `51dns.com/tool/221.html` |
| 七麦定价 | `36dianping.com/space/8176` / `36dianping.com/price/4182300101` |
| 天眼查/企查查对比 | `chinesecheck.com/blog/qichacha-tianyancha-english-alternative` |
| 国内平台价格参考 | `cloud.kd.cn/ask/178917.html` |
| 暗网监控价格带 | `decryptiondigest.com/blog/dark-web-monitoring-service-cost-pricing-guide` |
| TPRM 定价交叉对比 | `origin.upguard.com/competitors/panorays` / `upguard.com/competitors/black-kite` |
| SecurityScorecard 定价核实 | `toolradar.com/tools/securityscorecard/pricing` |
| UpGuard 定价 | `itechguides.com/products/upguard/pricing` |
| Cortex XDR 成本估算（存疑） | `costbench.com/software/endpoint-security/cortex-xdr` |
| Censys ASM 定位 | `securitystack.app/products/censys` |

### 8.3 开源工具与技术文档

| 工具 | URL |
|---|---|
| gau 官方文档 | `pkg.go.dev/github.com/mr-pmillz/gau/v2` |
| shhgit README | `github.com/lxrdyu/shhgit/blob/master/README.md` |
| shhgit 架构分析（不维护状态） | `starlog.is/articles/cybersecurity/eth0izzle-shhgit/` |
| detect-secrets | `github.com/Yelp/detect-secrets` |
| Gitleaks vs TruffleHog 实操 | `bigiron.cc/guides/detecting-leaked-secrets-in-git-with-gitleaks-and-trufflehog` |
| Secret scanning 工具对比 | `rafter.so/blog/secrets/secret-scanning-tools-comparison` |
| Gitleaks vs TruffleHog | `appsecsanta.com/gitleaks-vs-trufflehog` |
| Wayback Mining 方法论 | `bugbounty.info/Recon/Wayback-Mining` |
| gau 合规用法 | `learn.secbyte.org/tools/gau` |
| QuakeAPI（确认 Quake 归属） | `github.com/icecliffs/QuakeAPI` |
| JARM 原理（Salesforce 原始论文） | `research.salesforce.com` / 多篇技术解读 |
| favicon hash 算法与 preimage | `jorianwoltjer.com/blog/p/coding/shodan-favicon-preimage` |
| favicon hash 生成器 | `favicon-hash.kmsec.uk` |

### 8.4 中文社区实操（社区说法，需自行验证）

- `freebuf.com/articles/others-articles/489209.html`（2026 secret scanning 六工具横评）
- `dragonftop.github.io/2026/07/19/tools/FOFA使用手册`
- `juejin.cn/post/7685302724012376091`（FOFA 语法与指纹库）
- `blog.csdn.net/quiet/article/details/150660724`（四平台差异化应用）
- `blog.csdn.net/eee77/article/details/155130794`（五引擎对比）
- `m.pinggu.org/bbs/thread-16340334-1-1.html`（ZoomEye 与同类对比）
- `blog.csdn.net/2302_82189125/article/details/135906275`（Shodan 需挂代理）
- `m.toutiao.com/article/7543539614154375689`（国内引擎技术参数，**可信度一般**）
- `www.cnblogs.com/Llyn/articles/21504064`（FOFA 实战与合规声明）

### 8.5 合规与法律来源

- `everbrightlaw.com/CN/10800/4b3df8779a975b22.aspx`（光大律所爬虫合法性分析，含青虎浏览器案、"企某"案判决）
- `toutiao.com/article/7687543993760006666`（昆明警方AI脚本案专家解读）
- `m.toutiao.com/article/7678631130555269659`（提供侵入工具刑事案例）
- `xh.shzfzz.net/node2/xuhui/node1338/jcfy/u1ai1613902.html`（爬虫法律风险）
- `lvshi.sogou.com/article/detail/DP4STJ7ED44G.html`（刑法 285 条"情节严重"认定标准）
- 中国裁判文书网（(2024)苏0923刑初294号、(2020)浙01民终4847号）
- 《网络安全法》第 27/29/41/44/63 条 · 《数据安全法》第 21/32/51 条 · 《个人信息保护法》第 10/13/23 条 · 《刑法》第 253 条之一、第 285 条第 2/3 款 · 《反不正当竞争法》第 12 条 · 《征信业管理条例》第 23 条 · GB/T35295-2017、GB/T36344-2018

### 8.6 趋势类来源

- `paloaltonetworks.com/cyberpedia/asm-tools-comparison`（2026 ASM 工具对比）
- `securityweek.com/?p=44927`（Cyber Insights 2026: EASM 圆桌）
- `bitsight.com/learn/osint-framework`
- `b2bdaily.com/it/trend-analysis-integrated-attack-surface-intelligence/`
- `renrendoc.com/paper/527107801.html`（《2026中国网络安全技术演进与行业应用前景研究报告》，**第三方研究，可信度一般**）
- `klover.ai/open_source_intelligence_platforms_capabilities_integration_compliance_ai_indepth_analysis_2026/`（OSINT 平台深度分析，引用 Maltego 4.7 集成断裂等问题）

---

*报告完。所有定价数字核验于 **2026-10-03**；标注【存疑】的条目请在采购前直接联系厂商核实。本报告的合规章节为一般性提示，不构成法律意见。*
