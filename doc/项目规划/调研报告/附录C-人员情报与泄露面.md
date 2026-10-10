# 附录 C：人员情报 / 凭据泄露面 / 新兴 AI 类侦察工具完整调研

> 本附录是《信息收集工具全景调研报告》的分领域原始调研，聚焦 OSINT 自动化框架、人员情报（SOCMINT）、凭据泄露监控、暗网监控与 AI 类侦察工具。
> **调研时间：2026-10-03**

> **方法论声明与可信度分级**
> - **【已查证】** = 已抓取官方页面或一手文档确认，附链接
> - **【三方来源】** = 来自厂商/评测机构/媒体，未逐一验证到原始出处
> - **【社区说法】** = 论坛、博客、二手转述，未验证
>
> **重要提醒**：本次检索中大量排名靠前的"2026 最佳 XX 工具"类页面是 SEO/AI 生成农场，其中包含**完全捏造的基准数据**（例：某站声称"Gitleaks 精确率 68.7%""TruffleHog 扫描 12000 仓库"，无任何可复现方法学；另一站给出三家工具精确率 92.4%/78.1%/68.7% 的"2025 OSS benchmark"，同样不可追溯）。**这些数字一律不采信，本报告不引用。** 真正的可复现对比数据只在工具官方文档层面给出一手事实。

---

## A. OSINT 自动化框架

### A1. SpiderFoot v4 —— 唯一有真实"关联引擎"的开源框架

**【已查证】**（GitHub README，2026-10-03 抓取）：

| 项 | 事实 |
|---|---|
| 模块数 | 200+ |
| 关联规则 | YAML 可配置，**内置 37 条** |
| 输出 | CSV / JSON / GEXF |
| 后端 | SQLite（支持自定义 SQL） |
| 语言/许可 | Python 3.7+，MIT |
| 其他 | API key 导入导出、TOR 集成、Dockerfile、可调用 Nmap/DNSTwist/WhatWeb/CMSeeK |
| 扫描目标 | 域名、IP、主机名、CIDR、ASN、邮箱、电话、**人名**、用户名、比特币地址 |

**架构核心**是 **publisher/subscriber 事件总线**：模块产出的实体（子域、邮箱、钱包）作为事件广播，其他模块订阅后递归展开。这是它与"脚本式爬虫"的根本差别 —— 扫一个企业域名会自动级联到子域枚举 → CT 日志挖掘 → 网页抓取 → 人名/邮箱提取 → 再拿邮箱去查泄露库。

关联引擎的实用价值在于把" Firehose "变成信号：规则可匹配 `DNS_RECORD=CNAME` + `SUBDOMAIN 状态=dangling` → 输出 `HIJACKING_RISK / high`（子域接管风险），或 `邮箱 + 泄露数据` → 凭据暴露。模板见 `correlations/template.yaml`。

⚠️ **关键发现（已查证 GitHub 仓库）**：README 的最后提交记录显示主分支代码停在 **2023-02-21**，`correlations/` 目录停在 **2022-04-30**。**"37 条规则"这个数字已经三年多没有变过**，v4.0 的关联能力实际是 2022 年的设计。对比 Nuclei 每月发版节奏，SpiderFoot 的开源版维护状态堪忧。

**【社区说法｜未证实】**：多篇 2026 年博客称 SpiderFoot 已被 Intel 471 收购、开源版"被放弃"。**没有找到 Intel 471 的官方公告**佐证，请勿在正式报告中引用。

### A2. OWASP Amass v4 —— 数据源最多，但已不是"一个工具"

**【已查证】**（GitHub README + DeepWiki 架构文档）：Amass 4 基于 **Open Asset Model (OAM)**，从单体工具重构为"ecosystem"，拆成 `open-asset-model` / `config` / `oam-tools` / `asset-db` / `engine` 等多仓库。图数据库支持 **Postgres或 SQLite**（v3 时代只有 SQLite）。事件驱动架构 + 插件注册表 + GraphQL API（`createSessionFromJson`、`sessionStats`、`logMessages` 订阅）。

官方 README 自列的数据源清单（按类别统计）：

- **API 类约 40 个**：360PassiveDNS、AnubisDB、BeVigil、BinaryEdge、Chaos、CIRCL、DNSDB、FOFA、GreyNoise、Hunter、IntelX、Netlas、Quake、SecurityTrails、Shodan、ThreatBook、ZoomEye、Yandex…
- **证书类 10 个**：Censys、CertSpotter、Crtsh、FacebookCT…
- DNS 爆破/区域传送/NSEC 走查
- **路由类 10 个**
- **抓取类 24 个**：Google、Bing、**Baidu**、DuckDuckGo、RapidDNS、Searx、SiteDossier…
- **Web 归档 8 个**：Wayback、Arquivo、CommonCrawl、UKWebArchive…
- **WHOIS 12 个**

**值得中国读者注意**：数据源清单里**同时包含 Google、Bing、DuckDuckGo 和 Baidu** —— Amass 是少数原生支持 Baidu 抓取的开源框架之一。

**误报控制**：v4 依赖 OAM 的资产关系建模 + DNS 存活校验，而非单纯"解析到 IP 就算"。但**没有任何官方误报率数据**，厂商/博客给出的百分比均不可查证。

### A3. 其余框架的真实定位（2026）

| 工具 | 【已查证/三方】架构与现状 |
|---|---|
| **theHarvester** | Python CLI，纯爬虫。`-d 域名 -b all` 聚合邮箱/子域/IP/URL/人名。**【社区说法】**多个 2026 年来源一致指出：LinkedIn 接口已被严格限制、多个数据源关闭或限流，免费层产出明显萎缩。定位为"广度聚合器"，不是关联引擎 |
| **Recon-ng** | 模块化 + workspace 数据库（`db insert` / `show hosts` / `show contacts`），Metasploit 式。**【社区说法】**marketplace 存在大量无人维护的长尾模块，活跃核心仍可用但常需自写模块 |
| **GHunt** | **单点深度**而非广度：专攻 Google 生态（公开资料、Gaia ID、共享 Drive、DAL 关联、BSSID 定位）。全 async，CLI + library 双模式，配浏览器扩展自动取已认证 Cookie。**AGPL-3.0** —— 商业产品化需开源或另谈授权（【三方】） |
| **Blackbird** | 【三方】宣称 600+ 平台，基于 WhatsMyName 映射表，含 AI 画像 + PDF/CSV 导出。**注意重名**：`blackbird.ai` 是一家做"叙事攻击监测"的网络安全公司（企业实体），与开源 OSINT 工具无关 |
| **SpiderFoot HX** | 【社区说法｜**未证实**】商业版存在，但本次检索**没有找到任何官方产品页面或文档**。请勿在正式材料中列为可用产品 |
| **Maigret / Sherlock** | 用户名枚举标准件。Maigret 覆盖面（3000+ 平台量级）与 Sherlock（400+）在社区被反复提及，但**具体数字均来自工具自身 README 或二手榜单，未逐一核验版本**。Maigret 的"递归跟踪"（发现新别名后自动再搜）是被低估的能力 |

---

## B. 人员与商务情报（SOCMINT）

### B1. Hunter.io 定价（【已查证】官网 pricing 页，2026-10-03）

| 套餐 | 月付 | 年付折算 | **credits/月** | 已存线索 | 邮箱账号 |
|---|---|---|---|---|---|
| Free | $0 | — | **50** | 100,000 | 1 |
| Starter | $49 | $34 | **2,000** | 2,000,000 | 3 |
| Growth | $149 | $104 | **10,000** | 10,000,000 | 10 |
| Scale | $299 | $209 | **25,000** | 30,000,000 | 20 |

credits 消耗于 Email Finder / Email Verifier / Domain Search 三者共用。免费版即含 "auto-verified" 数据与基础 Discover 过滤器 + AI Assistant（10 次 AI 搜索/月）。

**这是本报告中唯一完全一手可核的定价数据。**

### B2. 邮箱发现与验证的技术原理

**验证四层（【已查证】技术共识，多源一致）**：

1. **语法校验**
2. **MX 记录**（含 RFC 7505 的 Null MX）→ 抓域级拼写错误（`@gmial.com`）
3. **SMTP RCPT TO 探测**：完整握手 `EHLO → STARTTLS → MAIL FROM → RCPT TO → QUIT`，**从不发送 DATA**。`250`=接受 / `550`=不存在 / `450`=灰名单延迟
4. 风险画像：一次性邮箱、角色账号（`info@`）、**catch-all 域**、垃圾陷阱

**catch-all 是准确率黑洞**：域配置为接受任意 local-part，任何探测都回 250。标准检测法是先用随机假地址探测，若也回 250 则该域所有 250 结果不可信。

**【社区说法，两个数字互相矛盾】** catch-all 在 B2B 列表中占比：一说 15-20%（kaijuverifier），一说 30-40%（prospeo）。**倾向认为真实值更高且随企业规模上升**，Exchange/Google Workspace 是重灾区。请用自己客户的样本实测，不要采信任何百分比。

**准确率参考（【三方】smtpedia / kaijuverifier，方向一致但具体数字未验证）**：

```
仅语法 ~70% → 仅 MX ~85% → SMTP 握手 ~96% → SMTP+catch-all+风险库 ~98%
```

### B3. ⭐ 邮箱验证的对抗风险 —— 这是攻防两端都必须懂的

**SMTP RCPT TO 探测在本质上是"目录收割攻击"（Directory Harvest Attack）的协议层机制。**

**扫描特征（【已查证】技术细节）**：

- 单连接内连续发出数十个 RCPT TO
- 收件人呈字典序/字母序
- `MAIL FROM` 为空或一次性地址
- 来源集中在少数 IP
- **几乎从不进入 DATA 阶段**

**合法发信人绝不会连续撞几十个不存在地址。**

**防御侧要点（防守方应立即做的事）**：

- **归一化响应**：有效与无效收件人的响应码、措辞、**时延**必须不可区分。**枚举之所以成立，就是因为两者长得不一样**
- **速率限制 + tarpit 延迟**，让大规模探测在经济上不划算
- 收件人存在性校验本身必须走统一路径，不得产生逐收件人的时延差
- 按来源信誉在 RCPT 之前早期拒绝

**发送方/枚举方的风险（【已查证】）**：

- Gmail 约允许**单 IP 每小时 200 次 RCPT TO**，超过即灰名单
- 持续探测会进 Spamhaus PBL、Barracuda 等 RBL，**污染的是你的出口 IP 声誉，数周无法恢复**
- 部分服务器要求可解析的 rDNS/PTR，否则一律回 550
- 灰名单需 3-15 分钟后重试
- **Yahoo / AOL 存在"假 250"**：RCPT TO 回 250，实际发送时才 5xx 弹回 —— **验证结果不可信**

**结论：大规模自建 SMTP 验证基础设施在 5 万封/月的量级以下是负收益**，专业服务用 >1000 个轮换 IP 池摊平这个成本。这就是为什么 Hunter/ZeroBounce/Bouncer 这类服务的商业逻辑成立。

### B4. ⚠️ 中国大陆可用性与合规风险

**【已查证】关键监管事实：Lusha 被意大利 Garante 罚款 200 万欧元**（DSN GROUP 律所简报）。裁判要点值得逐条抄给法务：

- "B2B 商业数据"**依然是个人数据**，不因商业目的而脱敏
- "数据已公开可见"（如 LinkedIn 资料页）**不等于**第三方可商业再利用的授权
- 持续更新数据主体的在职状态构成 GDPR Art.3(2)(b) 意义上的**行为监测**
- **正当利益（Legitimate Interest）不能支撑**为第三方自身营销/销售/招聘目的提供联系方式数据 —— **这需要同意**
- Lusha 的 LIA（利益平衡评估）被认定"实质上不存在"，未独立成文
- 透明度不足：隐私政策藏在网站数层点击之下，且使用英文而非意大利语

**映射到中国法（【已查证】《个人信息保护法》原文，工信部官网）—— 攻击方/使用方红线**：

| 条文 | 内容 |
|---|---|
| **第 3 条** | 境外处理境内自然人个人信息，**以向境内自然人提供产品或服务为目的**、**分析评估境内自然人行为**的，**同样适用本法** |
| **第 10 条** | 任何组织、个人**不得非法收集、使用、加工、传输**他人个人信息，**不得非法买卖、提供或者公开** |
| **第 13 条** | 七项合法性基础。**第 (六) 项"在合理范围内处理个人自行公开或已合法公开的个人信息"是唯一可能的出口** |
| **第 27 条** | 处理已公开个人信息，**个人明确拒绝的除外**；对个人权益有重大影响的，**仍须取得同意** |
| **第 38-39 条** | 跨境提供须满足安全评估/认证/标准合同三选一，且须**取得单独同意** |
| **第 42 条** | 境外组织损害境内公民个人信息权益的，网信部门可**列入限制/禁止提供清单** |
| **第 66 条 罚则** | 最高**五千万元以下或上一年度营业额 5% 以下**罚款，可责令暂停业务、吊销营业执照 |

**这是本报告最重要的法律结论**：

1. 用 Apollo/ZoomInfo/Lusha 采购境外数据 broker 的中国员工通讯录，若用于**商业触达或任何非"合理范围"**，同时踩中 PIPL 第 27 条 + 跨境提供第 38/39 条
2. **PIPL 第 3 条的"分析、评估境内自然人行为"条款，比 GDPR 更宽**。GDPR 需要 "establishments" 或定向活动才管辖；PIPL 只要**以境内人为服务目的**或**分析评估其行为**就管辖。**用 Hunter.io 批量分析中国员工邮箱的可投递性，PIPL 项下没有豁免**
3. 邮箱+姓名的组合在 PIPL 下**未列入第 28 条敏感个人信息**，但"行踪轨迹"是。社工库里的 `host+user+domain+password` 明文组合，属于**非公开的个人信息**，无任何合法性基础

**【已查证】刑事红线 —— 邮箱枚举的量刑门槛**（两高《关于办理危害计算机信息系统安全刑事案件应用法律若干问题的解释》+《刑法》285 条第 2 款）：

非法获取计算机信息系统数据罪，"情节严重"门槛：

- 获取支付结算/证券/期货等**网络金融服务身份认证信息 10 组以上**
- 获取其他**身份认证信息 500 组以上**
- **违法所得 5000 元以上**或造成经济损失 **1 万元以上**

"情节特别严重" = 上述标准 **5 倍以上** → **3 年以上 7 年以下有期徒刑 + 罚金**

**换算：批量邮箱枚举一旦用于破口或撞库，500 组身份认证信息即达"情节严重"，2500 组即"特别严重"。** 这不是行政违规，是实刑。

**【已查证】"内鬼"是明确的加重情节，且外人员工勾结同样构成"侵入"**：

- **最高检第 9 批指导性案例（检例第 36 号，卫梦龙案）**：员工将账号密码 Token 提供给外人员登录公司系统下载客户数据，虽非技术手段侵入，**仍认定为"侵入"** —— 因为"明显超出正常授权范围"。深圳中院 (2021)粤03刑终1657号 援引此案例
- **上海徐汇检察院案例**：某公司员工下载上万条员工账号 ID、姓名、组织、职位信息倒卖获利，侵犯公民个人信息罪 + 侵犯商业秘密罪，数罪并罚有期徒刑一年四个月、罚金 5 万元
- **"一案双查"机制**（2018 年起全面实行）：查员工泄露数据时**同步检查企业是否履行网络安全义务**，企业独立面临行政处罚
- **双重处罚**：《数据安全法》第 45 条、《个人信息保护法》罚则均规定对单位罚款 + 对直接责任人罚款

---

## C. 凭据与数据泄露监控

### C1. 五种检测引擎的原理对比（【已查证】官方文档层）

| 工具 | 引擎原理 | 验证能力 | 输出 |
|---|---|---|---|
| **Gitleaks** | TOML 规则：正则 + **entropy 阈值** + keywords + path + allowlist；`gitleaks git` 走 `git log -p`，`--log-opts` 可限范围 | ❌ 无 | JSON / CSV / JUnit / **SARIF** / Go template；`.gitleaksignore` 按 fingerprint 抑制 |
| **TruffleHog** | 关键词 + 正则 + 可选验证端点 | ✅ **有**，输出 `verified` / `unverified` / `unknown` 三态 | Human / JSON / GHA；`--fail` 命中返回 183 |
| **detect-secrets** | 插件池（正则/熵/关键词），**baseline（`.ds_store`）差分**模型 | ❌ 无 | baseline 增量 |
| **gitrob / shhgit** | 早期基于敏感文件路径 + 正则的扫描器，**现已基本被取代** | ❌ | — |
| **GitHub secret scanning + push protection** | **云端高置信度厂商模式匹配 + partner validity check**；push protection **在密钥进入历史前阻断推送** | ✅ 合作方有效性校验 | — |

**架构本质差异（这是本节的核心洞察）**：

- **正则** → 覆盖窄但零误报，漏报多
- **entropy** → 覆盖宽，能发现没见过的厂商格式，但把 UUID / 内容哈希 / 测试 fixture 也当密钥（这是"熵"路线的结构性缺陷）
- **GitHub 云端模式匹配** → 只打高置信度厂商模式，**所以它同时最安全（零误报）和最不安全（完全漏掉内部格式与通用密钥）**
- **TruffleHog 的 live verification** → **这是真正改变分诊数学的那一个**。"AWS key, verified active" 是事故；"AWS key, verification failed" 是清理任务。**一个比特决定是否呼叫值班**

**代价**：verification 意味着扫描器要对外发 API 请求 —— 在企业网络里要评估出口含义。TruffleHog 全历史扫描在小仓库也要~41 秒（三方测试，量级可信），**是批处理作业而非 PR 门禁**。

**推荐分层（综合多方实践共识）**：

```
① GitHub push protection（免费，公共库免费 / 私有库随 Secret Protection）
        ↓
② Gitleaks 作 pre-commit + CI 门禁（--log-opts="origin/main.." 控制在 2 秒内）
        ↓
③ TruffleHog 定期全历史扫描 + 验证
```

**单点部署是踩坑主要原因。**

⚠️ **Gitleaks 许可变更**：【三方】8.19 版本起许可证有变化，大型组织需法务复核（多数 CI 使用场景仍可接受）。

### C2. Have I Been Pwned 的 k-匿名 + padding（【已查证】官方 API v3 文档）

**机制**：客户端本地计算密码 SHA-1（40 位十六进制），**只发送前 5 位 prefix**，API 返回该前缀下**全部后缀 + 出现次数**，客户端本地比对。

```
完整 SHA-1：21BD10018A45C4D1DEF81644B54AB7F969B88D65
前缀：      21BD1          ← 只发送这个
后缀：      0018A45C4D1DEF81644B54AB7F969B88D65
请求：      GET https://api.pwnedpasswords.com/range/21BD1
```

**为什么必然返回 200**：5 位十六进制 = 16^5 = **1,048,576 个桶**，任一有效前缀几乎必然命中数据，故不会 404。

**Add-Padding 头（关键隐私机制）**：未启用时，不同前缀返回的记录条数不同 → **攻击者可通过响应大小/行数反推被查询的是哪个前缀**。启用后随机填充到约 **800-1000 条**，填充项形如 `0000000000000000000000000000000000:0`，客户端直接丢弃。

**必须讲清的边界（HIBP 官方明确说明）**：

- **`Add-Padding` 不让请求本身匿名**。服务端仍能看到 5 位前缀，它隐藏的只是**响应规模这一侧信道**
- **不要在用户每输入一个字符时发起查询** —— 连续增量请求会泄露正在输入的密码。应在字段失焦或提交时查询
- 必须走 HTTPS
- NTLM 走 `?mode=ntlm`，前缀仍 5 位，后缀 27 位

### C3. 泄露库生态与 stealer logs 格式

**【已查证】Hudson Rock / infostealers.com 公开数据集（2026-10-03 读数，每 5 分钟刷新）**：

| 指标 | 数值 |
|---|---|
| 已失陷机器 | **36,497,778** |
| 已失陷员工 | **5,785,481** |
| 已失陷 Android 设备 | **14,484,670** |
| 已失陷域名 | **16,258,447** |

**stealer log vs 传统 breach dump 的本质区别（这是选型时最该理解的）**：

| | **Breach dump** | **Stealer log** |
|---|---|---|
| 来源 | "某一个被攻破的服务" | "某一台被 infostealer 感染的机器" |
| 字段 | `email:password` | 一次 exfil 出**一整包**：保存的密码 + **session cookie** + 自动填充（姓名/地址/电话/信用卡）+ 加密钱包 + 已装软件列表 + 屏幕分辨率 + **受害者 IP** + **浏览历史** |
| 范围 | 窄 | 广 |
| 时效性 | 差 —— 用户改密码就失效 | 新 |

**因此一个 stealer log 能回答密码清单回答不了的问题**：

1. 这台是**公司设备还是个人设备**？（决定是终端问题还是影子 IT 问题）
2. **有效 session cookie 是否存在？若有，改密码无效 —— 必须吊销会话**，否则攻击者直接绕过 MFA。**这是凭据暴露领域最被低估的事实**
3. **感染向量是什么**？（盗版软件 / 恶意广告 / 假安装包 → 判定这是一个人的疏忽还是针对你组织的攻击）
4. **浏览历史里有哪些内部 URL**？（攻击者已经知道你的内部系统结构）

**关于免费服务（【已查证】官网 + 官方博客）**：

- 免费工具集：Domain Search / Email Address Search / Android App Monitoring / Technology Profiler / Password Hygiene Analyzer
- **原理**：从地下市场、犯罪论坛、Telegram 频道**索引 infostealer 日志**，再与域/员工/客户/终端用户做交叉引用
- **数据已开源给 65+ 个网络情报项目**使用
- **免费监控**：可同时监控 **3 个邮箱 + 3 个用户名 + 3 个域名**，新感染实时邮件告警。域告警邮件**不含 PII**，只提示"与被监控域相关的 URL 出现新泄露凭据"
- 【重要】Hudson Rock 曾据此**去匿名化约 10 万名 cybercrime 论坛用户**（Nulled.to 57,000+ / Cracked.io / Hackforums.net），手段是 auto-fill 里的姓名地址、系统信息里的机器名与 IP、同一台机器上的其他邮箱
- ⚠️ 数据源自犯罪基础设施 —— **持有即持有他人明文凭据**。合法边界极窄

**Intelligence X（【三方】cybervendorguide / osintbench，2026-09 复核）**：

- 索引来源：paste sites、data leaks、**stealer logs**、Tor/I2P、**历史 WHOIS**、Usenet、公开 web、**Telegram 频道**
- 2018 年 Peter Kleissner 创立，布拉格
- 免费层：**每次搜索 10 条结果**（osintbench 独立评测确认）
- 定价【三方，务必自行核验】：Researcher €2,500/yr、API €7,000/yr、Identity Portal €10,000/yr、Enterprise €20,000/yr
- **与 HIBP 的关键差异**：HIBP 告诉你"这个邮箱出现在某次泄露中"；**IntelX 返回实际泄露记录本身** —— 邮箱、明文或哈希密码、用户名。**这是取证级差异**
- **永久存档**：内容即使从原站删除仍可检索，包括历史 WHOIS（可穿透 WHOIS 隐私保护）
- **⚠️ 法律灰区**：检索本身合法，但**下载/转存/再扩散泄露的个人数据本身就可能违反数据保护法**

**stealer log 的典型结构**：`host`（机器名/主机标识）+ `user`（OS 用户名）+ `domain`（邮箱域）+ `password`（**明文**）+ 时间戳 + 恶意软件家族 + 存储该凭据的 URL + IP + 浏览器版本等。

**明文**是 stealer log 与常规 hash dump 的另一关键差异 —— 无需破解即可直接使用，这也是此类数据刑事风险极高的原因。

---

## D. 新兴 / AI 类侦察工具（2025-2026）

### D1. ⚠️ 核心问题：「LLM 让 OSINT 变强了」还是「变弱了」？

**结论：采集与分诊变强了，验证与结论可靠性显著变弱了。**

**支持"变强"的证据 —— 但都很弱：**

1. **【已查证/学术】** ECCWS 2026 会议论文《Evaluating the Reliability of LLMs in OSINT Investigations》（DOI: 10.34190/eccws.25.1.4818）：用虚构组织 CtrlZ Society + 合成数据集测试 GPT、Claude 3、Gemini、Meta、DeepSeek、Qwen 2.5、Mistral Large、Grok。**Claude 3、GPT、Qwen 2.5 分析表现强**；Gemini、DeepSeek 明显较弱；Meta 系在对抗性提示下**倾向强行构建叙事**（forced narrative construction）。全部模型在"结构化与摘要"上有价值
2. **【已查证/学术】** arXiv:2607.03233（系统综述，**74 项研究**的语料库分析，2026-07-02 收稿）：LLM 使"生成定向采集查询、从非结构化文本抽取与上下文化实体、跨异构源综合情报、起草初步分析报告"成为可能，这是**质变而非边际改进**

**支持"变弱"的证据 —— 强得多：**

1. **【已查证/学术】同一篇 74 研究综述的核心发现是"幻觉-验证鸿沟"（hallucination-validation gap）**：

   - 20+ 项研究把幻觉列为 OSINT-AI 首要可靠性威胁
   - 但**全语料库中只有一个 OSINT 专用系统实测了端到端幻觉率**：一个 RAG 架构报告 **4%**，且条件"有利、不可复现"、数据集私有
   - 其余"推理错误率""事实纠正率"数据均来自**通用领域问答，而非 OSINT**
   - **没有任何论文实证了对抗鲁棒性、端到端验证或有效治理**
   - **智能体系统全部只在良性（非对抗）条件下评测**，尽管存在已记录的攻击性威胁
   - 结论明确：**当前证据下，"分析师在环 / copilot 架构"是唯一可辩护的近期部署形态**；"无严格监督的端到端自动化不可接受"

2. **【已查证/媒体】Tow Centre for Digital Journalism（Tow 中心）视觉核验研究**：要求 7 个 AI 系统识别新闻摄影师的照片的地点、日期、来源 —— **280 个问题中仅 14 个完全正确**。研究者结论：推理过程不透明、误导或直接错误，**对未经训练者用于事实核查是危险选择**

3. **【已查证/媒体】NewsGuard 审计（2025-08）**：主流 LLM **35% 的时间重复虚假信息**（2024-08 为 18%）。增长原因恰恰是转向实时网页搜索 —— **拒答率从 31% 跌至接近 0**，模型从"不知道"变成"自信地编"。案例：摩尔多瓦议会选举的虚假信息，多个模型持续从亲克里姆林宫的 Pravda/Portal Kombat 网络取材 —— **尽管该网络开发者已被欧盟制裁**。某个先前停止引用 Pravda 域名的模型，又通过 VK 帖子重新使用其内容

4. **【已查证/学术】** 同一综述还指出：**基于 LLM 的聊天机器人在真实 OSINT 数据上的 NER 性能比领域专用基线系统性地低 25%**

**给中国安全从业者的可执行结论**：

> 把 LLM 用在**采集指引、格式转换、海量数据初筛、报告起草**上，收益明确。
> **绝不要**用在**事实认定、身份归属、结论定性**上 —— 尤其涉及人在报告中被点名时。
> 域内落地强制三条：① 多模型交叉验证（不同厂商的幻觉谱系不同，可互相证伪）② 每条结论必须能回溯到原始证据 URL + 抓取时间戳 ③ 保留人工署名与复核记录。

### D2. AI 能力进入既有工具

**【已查证】ProjectDiscovery / Nuclei（projectdiscovery.io 官方博客，2026-05-12）**：

- 模板仓库发布节奏：v10.4.2（2026-04-15）新增 **121** 个模板 / 61 个 CVE；v10.4.3（2026-05-05）新增 **105** 个模板 / 62 个 CVE。两个月合计 **226 新模板、123 CVE**，其中约 **10 个在野利用漏洞**
- **明确提到该周期的重点方向之一是 "AI/LLM attack surface"（AI/LLM 攻击面）** —— 即核验自家 AI 服务的配置错误、提示注入、模型端点暴露
- 官方称模板库 **10,000+**
- **Global Matchers**（2025-02 发布）是实用工程特性：一条 matcher 配置可作用于**所有其他模板的所有 HTTP 响应**，写一次即可全局匹配私钥、token、webhook
- 【三方】Nuclei AI 浏览器扩展可把 HackerOne 报告一键转成 Nuclei 模板；**ProjectDiscovery Neo** 自动化测试平台 2026-08 GA。**Neo 的性能声明（"22 个确认 0day""60% 更多漏洞、80% 更少误报"）来自培训站点转述，未找到一手基准，请勿引用为事实**

**结论**：AI 在防守侧最成熟的落点是**模板生成与配置审计辅助**，不是自主发现。

### D3. 钓鱼/恶意域名情报源（【已查证】官方 FAQ）

| 源 | 运营方 | 验证机制 | 访问 |
|---|---|---|---|
| **PhishTank** | **Cisco Talos** | **社区投票众包**。注册用户提交并对他人提交投票；验证强度随确认人数上升；状态字段：`Valid Phish` / `Invalid` / `Unknown` × `Online` / `Offline` / `Unknown`。可按目标品牌、**ASN** 查询 | 网站与数据均免费；**API 需免费注册换 key**（注册要求是为了把验证归属到个人账号以降低提交噪音，也是投票质量的基础） |
| **OpenPhish** | Private | 专攻钓鱼，免费 feed 常量更新，机器可读 | 免费 feed（完整历史/定制需付费） |
| **URLhaus** | **abuse.ch**（瑞士非营利） | URL 提交后**自动验证**实时入库 | 完全免费，REST API **无需认证** |
| **ThreatFox** | **abuse.ch** | IoC 提交后**人工复核**清洗，区分可信上报者 | 永久免费，**无 key、无调用额度硬限制**；JSON/CSV/**RPZ**/Suricata/MISP/hosts 多格式 |
| **PhishStats** | Community | 聚合多源 | 免费 |

**ThreatFox vs URLhaus 的分工（常被混淆）**：ThreatFox 聚焦**恶意软件 C2 回连**基础设施（IP/域名）；URLhaus 收**恶意软件下载分发 URL**（载荷地址）。两者互补，abuse.ch 生态还有 MalwareBazaar、FeodoTracker。

**为什么 abuse.ch 可信度高于纯众包**：**人工复核 + 蜜罐主动捕获**，误报率显著低于纯用户投票。这一点在与客户解释"为什么要投喂两个源"时是核心论据。

**关键时效数据**：Google Safe Browsing 本地哈希列表约 **30 分钟**更新一次，新恶意 URL 上榜有**最长约 30 分钟窗口期**。短命钓鱼活动专门利用这个延迟。**这是"必须组合多源"的硬理由，不是最佳实践建议。**

**误报现实**：VirusTotal 上 70+ 引擎中**通常有 1-2 个会误报正常站点**，所以 1/70 或 2/70 的分数不意味着危险。

### D4. 暗网监控（定价全部为三方来源，须自行核验）

| 平台 | 定位 | 定价 |
|---|---|---|
| **DarkOwl** | **数据层供应商**（其他暗网监控厂商常向其采购原始数据）。Vision UI + 完整 API SDK + 原始 feed | 【三方】AWS Marketplace 上 **$38,000-60,000+/座/年**起；另有来源称平均客户约 **$70,200/年**；API 产品企业定制。**无试用、无 freemium** |
| **Flare** | 中端市场最直接的替代品，58k+ Telegram 频道覆盖，Entra ID 阻断联动 | 【三方】SMB 入口约 **$417/月**（年付）；识别符计价、用户数不限 |
| **Constella Intelligence** | 身份风险情报与归属，**131B+ 属性 / 66B+ compromised records / 125 国 / 53 语言**；Hunter（调查）+ Identity Data API（开发） | 【三方】Vendr 基准 **$315,000-415,000/年**，平均约 $365K。纯企业级，无试用 |
| **Searchlight** | 商业情报目录 | 未查到公开定价 |

**【已查证】DarkOwl 数据规模与能力（Q1 2026 官方产品更新）**：

- 市场数据 **431,000+ 条 listing**，抽取 vendor 身份、描述、类别、价格、支付方式、发货 origin/destination、评论
- 同比：信用卡号 **+21%**、邮箱地址 **+20.5%**、IP **+9%**
- **内置 52 种语言翻译**（覆盖俄、中、阿、波斯语），**翻译在 DarkOwl 闭源环境内完成，数据不出境** —— 这对中国的合规审查是个**实质性的技术卖点**
- Vision API 新增：paste 专有字段（author / postDate / expires / key）、Context API 的 Media Reporting 字段
- 客户含 Microsoft、Coinbase、Proofpoint

**【三方，需谨慎】** 某来源称 DarkOwl 索引 **8.94 亿 TOR 记录**、每小时收集 **22.75 万暗网页面**、**180 亿+ 邮箱**、**5900 万+ 信用卡**、**4.68 亿+ 加密钱包**，且**60% 数据来自认证/账户级来源**。这些数字**未在 DarkOwl 官方页面查证到**，但与"其他厂商抓的是 clearnet 表层、暗网产品都在爬同一批公开 dump"这个批评在逻辑上自洽 —— **采购时必须直接向厂商索要索引方法论与来源构成证明**。

**核心判断**：DarkOwl 是**原始数据平台，不是托管服务**。没有 PSA 集成、没有多租户客户报告、没有白标输出，你需要**懂暗网数据的安全分析师**，否则"signal 溺水"是真实风险。

### D5. 公开数据泄露监控免费服务 —— 原理已查证

**【已查证】Hudson Rock 免费 cybercrime intelligence 工具集原理**：

- **数据来源**：从地下市场、犯罪论坛、**Telegram 频道**索引 infostealer 日志，与域名/员工/客户/终端用户交叉引用
- **免费工具（6 类）**：

  | 工具 | 作用 |
  |---|---|
  | `Domain` | 检测失陷的企业与供应链基础设施 |
  | `Email Address` | 查具体邮箱（员工/客户/用户/伙伴） |
  | `Android App` | 你的 Android App 用户凭据是否被窃 |
  | `Technology Profiler` | **发现某公司是否在用 Citrix / Webmail / Confluence 等特定技术** ← 这是供应链情报入口 |
  | `Password Hygiene` | **基于实际暴露凭据**反推某域的密码复杂度策略是否真正生效 |

  监控面板：3 邮箱 + 3 用户名 + 3 域名，新感染实时告警

- **⭐ "估算感染比例"的确切机制**：域级查询返回的不是名单而是**聚合统计** —— 失陷机器数量、涉及员工数、发现摘要。**免费层刻意不返回完整凭据明细与机器上下文**（需企业账户）。即：**你可以知道"我们公司有 N 台机器被感染"，但拿不到具体某个员工的明文密码** —— **这个设计本身就是对合规性的让步**

**关键前提（【已查证】OSIntBench 评测）**：免费查询**不是演示版，是研究工具**。红队输入客户域 → 立刻拿到一份"感染机器 + 企业凭据"清单，**在委托流程正式开始之前就形成了发现**。SOC 分析师凌晨 2 点查同一个域 → 发现正在追查的账户 6 个月前就被 RedLine 收割了。

这个工作流是 Hudson Rock 在从业者中口碑远超其营收的原因，也是问题所在：**免费查询不是控制手段。**

**Hudson Rock 的独有优势**：

- 区分"企业设备 vs 个人设备"（决定响应路径）
- **会话 cookie 有效性判定**（决定改密码是否足够）
- **感染向量归因**（判定个人疏忽 vs 定向攻击）
- 集成 Active Directory / Okta / Auth0 驱动**自动会话吊销与账户停用**

**它不做的**：品牌滥用监测、下架服务、勒索 leak site / 论坛覆盖、跨源身份图谱。**如果你的需求清单有 10 项，它把 2 项做得比谁都好，另外 8 项不碰。**

---

## E. Google Dorking 与搜索引擎语法

### E1. ⚠️ 首先必须纠正一个普遍的过时认知

**【已查证/多源一致】以下 Google 算子已废弃或失效**：

| 算子 | 状态 | 废弃时间 |
|---|---|---|
| `cache:` | **已完全移除** | 2024 年初 |
| `link:` | 已移除 | 2017 |
| `related:` | 已移除 | 2023 年中 |
| `info:` | 已移除 | ~2019 |
| `daterange:` | 已移除 | — |
| `~`（同义词） | 已移除 | 2013 |
| `+`（强制包含） | 已移除 | 2011 |

**这是本报告对实务最直接的一条**：大量中文/英文安全教程仍在教 `cache:` 和 `link:` —— **这两个在 2026 年已经完全无效**，很多人还在以为自己用了"高级语法"。

### E2. 2026 年可靠工作的算子体系（约 25 个）

**布尔层**：`"精确短语"`、`-排除`、`OR`（**必须大写**，小写无效）、`*`（单词通配符）、`()` 分组、`AROUND(N)`（**必须大写**，两词间距 ≤ N 词）

**页面位置**：`site:`（**最可靠的算子**；支持 `site:*.gov` 通配、`site:domain.com/path` 限目录）、`intitle:`、`allintitle:`、`inurl:`、`allinurl:`、`intext:`、`allintext:`、`inanchor:`（不可靠，抽样严重）

**内容类型**：`filetype:` / `ext:`（别名）、`site:site:`

**日期**：`before:YYYY-MM-DD`、`after:YYYY-MM-DD`（可组合成区间）、`..`（数值区间，如 `laptop $500..$800`，**点号两侧不能有空格**）

**工具类**：`define:`、`$`（价格）、`in`（单位换算，如 `10 miles in km`）、`stocks:GOOGL`、`weather:`、`map:`、`movie:`

**Google News 专用**：`source:`（如 `tesla source:reuters`）、`location:`

**社交**：`@username`、`#hashtag`

**未文档化但仍有效**：`AROUND(3)`、`allinanchor:`（大幅削弱）

**语法要点（易错）**：

- 冒号与其值**必须紧贴**。`site: nytimes.com`（冒号后有空格）**解析失败**，Google 退回普通关键词搜索 —— 这是最常见的**静默失败**
- 算子名大小写不敏感（`SITE:` 等价），**但 `OR` 和 `AROUND(N)` 只认大写**
- 算子可链式叠加 6-7 个，默认按逻辑 AND 组合
- **建议用无痕窗口或登出 Google** 做客观调研（登录态会污染 SERP）
- `udm=14` URL 参数强制经典网页结果视图、剥离 AI Overviews —— **AI 时代做 dork 时的实用技巧**
- `site:` 返回的结果数是**数量级估计，不是精确页面数**（社区共识，Search Console 才是权威）

### E3. 主流搜索引擎语法差异

| 算子 | Google | Bing | Baidu | Yandex |
|---|---|---|---|---|
| `site:` | ✅ | ✅ | ✅ | ✅ |
| `filetype:` / `ext:` | ✅ | ✅ `filetype:` | ⚠️ 支持不稳定 | ✅ |
| `intitle:` / `allintitle:` | ✅ | ✅ | ✅ | ✅ |
| `inurl:` | ✅ | ✅ | ✅ | ✅ |
| `intext:` | ✅ | ✅ | ⚠️ 不可靠 | ✅ |
| `-排除` | ✅ | ✅ | ✅ | ✅ |
| `"短语"` | ✅ | ✅ | ✅ | ✅ |
| `OR` | ✅ 大写 | ✅ | ✅ | ✅ |
| `link:` / `cache:` | ❌ 已废 | ⚠️ `linkfromdomain` 可用 | — | — |
| **站点特有** | — | `language:` `loc:` `ip:` | `bd:`（站内）、`site:` 分区 | `lr:`（语言区域） |

**中国场景特别注意**：

- **Baidu 对 `filetype:` 和 `intext:` 的支持最差**，索引质量也低。**中文语料的实际检索应主要依赖 Bing + 站点站内搜索**
- Amass 的数据源清单同时含 Google / Bing / Baidu / DuckDuckGo / Yandex / Searx / RapidDNS —— **用 Amass 做中国目标资产发现时，Baidu 通道是唯一的一手中文语料入口**
- ⚠️ 【社区说法】中国主流搜索引擎的 dork 查询若无 VPN / 境内 IP，结果覆盖与境外差异很大；部分 Google 算子在境内网络下行为不一致
- `ALEX` 台网工信部备案查询是域名归属的权威中国数据源，Amass 未集成，需手工补充

### E4. 实战用例（防守方自查，授权范围内）

**发现泄露的版本控制与配置**：

```text
site:example.com inurl:.git
site:example.com ext:env
site:example.com -inurl:www inurl:backup
site:example.com intitle:"index of"      ← 目录列表
filetype:sql "CREATE TABLE"             ← 误提交的 SQL dump
filetype:log "password"                 ← 日志文件
ext:log ext:sql ext:bak ext:old ext:zip ext:tar.gz
```

**发现后台入口与遗留系统**：

```text
site:example.com intitle:"登录" OR intitle:"login" OR intitle:"管理"
site:example.com inurl:/admin inurl:/manager inurl:/console
site:example.com inurl:phpmyadmin OR inurl:adminer
"test" OR "demo" OR "staging" site:example.com
```

**发现员工邮箱**（**注意：这是攻防两端的高风险区，见 B4**）：

```text
site:example.com filetype:xlsx "@example.com"
site:example.com "@example.com" -site:example.com     ← 只取外链泄露的邮箱
site:linkedin.com inurl:"/in/" "example.com"
intitle:"员工手册" OR intitle:"通讯录" filetype:pdf
```

**发现被遗忘的子域与影子资产**：

```text
site:*.example.com                     ← 通配符扫全子域
site:example.com -www -mail            ← 排除高频前缀，逼出冷门资产
inurl:test -inurl:www site:example.com
```

**⚠️ 扫描间隔与 OPSEC**：单 IP 高频 dork 会触发 Google 的验证码 / 封禁，且**目标域的 WAF 管理员能从日志看到你的 IP**。使用无痕窗口、暂停间隔、必要时经 VPN。

### E5. 防守方如何防止自己的资产被 dork 出来

**清单（自查用，请仅对自己授权的资产执行）**：

1. **代码仓库**：`.git/`、`.svn/`、`.hg/` 禁止暴露到 web 根目录；部署流程中显式 `rm -rf .git` 不够，必须有 CI 校验
2. **配置文件**：`.env`、`.env.production`、`config.php`、`wp-config.php.bak`、`settings.py.bak` 全部移出 web 根
3. **备份文件**：`.bak` `.old` `.orig` `.save` `.swp` `~` `.zip` `.tar.gz` `.sql` —— 建立自动化扫描（可自建 GitHub Actions 定期 dork 自己的域名）
4. **目录列表**：Apache `Options -Indexes`、Nginx `autoindex off`
5. **云存储**：S3 / Azure Blob / DigitalOcean 容器 ACL 审计 —— **这正是 SpiderFoot 的 S3/Azure/DO 模块做的事**
6. **证书透明度**：CT 日志是**双向的** —— 你能 dork 到别人，别人也能 dork 到你。子域接管风险需专门审计（`dns; zone transfer`、`CNAME` 指向已注销的 SaaS）
7. **员工信息**：这是**最容易被忽略也最难彻底解决**的一项 —— 见下

**关于员工信息，无法"禁止 dork"，只能降低价值**：

- 邮箱命名格式一旦泄露（如 `拼音.拼音@`），全员工邮箱可被**批量猜测**（`firstname.lastname@` 类排列），且**不需要任何人去 dork**
- 最有效的缓解是 **catch-all 阻断**：配置邮件服务器接受任意 local-part，让"邮箱存在性"无法被 SMTP 探测区分（见 B3）。**但这会破坏邮件系统的错误发现能力**，需要权衡
- 关键岗位（CISO、财务、高管、法务）的邮箱暴露度应单独评估
- **务必评估 `site:linkedin.com` 上本公司员工页面的暴露度** —— 这是最容易彻底闭环的：要求员工完善隐私设置并定期复查

---

## F. 三个必答问题的结论

### F1. LLM 让 OSINT 变强还是变弱？

**分环节，答案不同（依据见 D1）**：

| 环节 | 方向 | 证据强度 |
|---|---|---|
| 采集指引、查询生成 | **强** | 74 研究综述共识 |
| 海量数据初筛、格式转换、摘要 | **强** | 强共识 |
| 报告起草 | **强** | 强共识 |
| 实体识别（NER） | **弱于专用基线 25%** | 学术实测 |
| 视觉核验 | **严重弱**（280 问仅 14 全对） | Tow Centre 实测 |
| 实时/突发信息 | **严重弱**（35% 重复假信息，拒答率归零） | NewsGuard 实测 |
| 身份归属、责任认定 | **不可用**（对抗提示下强行构建叙事） | ECCWS 2026 |

**根本原因**：LLM 让**生成**变便宜了，但没有让**验证**变便宜。OSINT 的价值 100% 建立在"这条证据是真的"上，而 LLM 不提供这一点。

> **拒答率从 31% 跌到接近 0 这个数字，比 18%→35% 的虚假率上升更值得警惕** —— 一个"不知道"的模型是安全的，一个"自信地编"的模型不是。

**部署原则**：LLM 负责找，**人负责判**。每条结论必须能回溯到原始 URL + 抓取时间戳。

### F2. 凭据泄露监控的实际价值 vs 噪音

**价值被低估的部分**：

- **TruffleHog 的 verified 状态是唯一能把"发现"变成"事故/清理工单"的分诊位**。"AWS key, verified active" 呼叫值班；"verification failed" 建清理单。这一个比特的价值超过所有规则引擎的精巧程度
- **Hudson Rock 类 stealer log 能回答密码清单回答不了的问题**：设备是公司还是个人？有效 session cookie 是否存在（决定改密码是否足够）？感染向量是什么？内部 URL 泄露了什么？
- 成本核算：Constella 约 $365K/年、DarkOwl 约 $70K/年 vs **一起有效凭据泄露的处置成本** —— 这个 ROI 不需要论证

**噪音的真实规模 —— 有意义的对照**：

【三方】某测试：60 个真实格式密钥 + 15 个熵陷阱（cache key、test fixture）。测试于 2026-04，当前版本。

| 工具 | 检出| 误报 |
|---|---|---|
| TruffleHog | 54 | **2** |
| Gitleaks | 51 | 4 |
| GitHub secret scanning + push protection | 46 | **0** |
| detect-secrets | 39 | 7 |

- **漏报高度聚集在两类**：(a) 各工具缺少对应 provider 模式的**特定格式**；(b) **字符串拼接后跨行的密钥** —— 只有 TruffleHog 部分捕捉到（5 个中 3 个）
- **误报的主要来源是 entropy**：UUID、内容 hash、测试 fixture。Gitleaks 靠 `.gitleaksignore`（按 fingerprint 记录，**抑制记录能跨 rebase 存活**）和 baseline 管理
- **catch-all 域占 B2B 列表 15-40%**（两个三方来源冲突）—— **这一项单独就能让你的邮箱验证准确率崩掉，且是结构性的，不是 bug**

**结论**：

> 凭据泄露监控的价值**已经证实**，但瓶颈不在检测能力，在**分诊能力与基线治理**。
> 三个决定成败的动作：
> ① **必须有 verification 能力**（否则发现无法分诊）
> ② **必须有基线/抑制**（否则噪音淹没法务响应）
> ③ **必须有会话吊销预案**（stealer log 显示有效 cookie 时改密码无用 —— 这是最被低估的运维事实）
>
> **噪音的本质不是工具不好，是没有基线。** 用 detect-secrets 的 baseline 模型或 Gitleaks 的 `.gitleaksignore`，把"新引入的凭据"与"历史已知的历史包袱"分开 —— 这一步做好，噪音问题基本消失。

### F3. 员工信息 / 邮箱枚举在攻防两端的合法边界

**先明确一个事实**：邮箱格式一旦泄露，全员邮箱即可被算法批量枚举，**这不需要任何人去"攻击"**。这是**被动暴露**，不是主动攻击。所以：

**防守侧（合法，可立即做）**：

- 用自己的域去 Hunter/Clearbit 类工具查询 → 发现员工邮箱暴露度与格式规则（**这是授权范围内的资产盘点**）
- 查询**自己公司的域名**在各类泄露库中的暴露
- 自查 Google/Bing `site:` 结果中的资产暴露
- 这些都属于《网络安全法》第 21 条的网络安全保护义务范围

**攻防边界（【已查证】中国法红线）**：

| 行为 | 定性 | 依据 |
|---|---|---|
| 用**自有域**查自己员工邮箱 | ✅ 合法 | 网络安全法保护义务 |
| 用 SMTP 探测**他人公司**邮箱（RCPT TO 枚举） | ⚠️ **高风险** | 《刑法》285 条 + 两高解释：500 组身份认证信息 = 情节严重；**禁止进入"目录收割攻击"**；同一 IP 大量 RCPT TO 是可检测的明确信号 |
| 用商业 broker（Apollo/ZoomInfo/Lusha）批量获取**中国境内**员工数据并用于商业触达 | ❌ **明确违法** | PIPL 第 27 条（已公开 ≠ 可商业复用）+ 第 38/39 条（跨境提供须安全评估/标准合同 + 单独同意）+ 第 3 条（分析评估境内自然人行为亦适用）；Lusha €200 万判例已确立"公开可见 ≠ 可商业再利用" |
| 采购并**持有**stealer log 明文凭据 | ❌ **极高风险** | 明文 `user+domain+password` 组合即"身份认证信息"，500 组 = 情节严重；且**来源本身多为非法获取** |
| 内部人员越权查询他人信息 | ❌ 刑事 | 卫梦龙案指导性案例：**"超出授权范围"即构成"侵入"**；深圳中院 (2021)粤03刑终1657 判例 1 年有期徒刑 + 2 万罚金 |
| 员工数据泄露 | ❌ 刑事 + 企业"一案双查" | 上海徐汇案例：侵犯公民个人信息罪 + 侵犯商业秘密罪，数罪并罚 1 年 4 个月 + 5 万罚金；公安 2018 年起全面实行"一案双查" |

**给中国安全从业者的三条具体红线**：

1. **写授权书，写明范围、目标域、允许的行为类型（只读 OSINT vs 主动探测）**。主动 SMTP 探测应**单独书面授权**。本文提到的所有 dork 手法在授权范围内都合法，越界即为"侵入"
2. **员工数据采购是"共同风险"** —— Lusha 案的关键教训：**罚款落在供应商，但合规风险同样落在不知情的采购方**。DPO/法务必须在采购前介入审查数据来源合法性
3. **不要为了"验证一下"而跑 SMTP 枚举**。用 Hunter 的自动验证（合规的规模化服务），或只做被动查询。这条线的法律风险收益比极差

---

## G. 一句话建议（给中国安全从业者）

**先做三件不依赖任何付费工具的事**：

1. 拿自己的域去 `crt.sh` + Amass + `subfinder` 跑一遍 —— **你的真实资产暴露面大概率超出预期**
2. 邮件系统做一次 **catch-all 与响应归一化审计**（**这一项同时提升安全性并消除最大的攻击信标**）
3. 去你公司的主域在 PhishTank / URLhaus / ThreatFox 查一遍 —— **确认自己没在被钓鱼**

**再考虑采购**，且优先级是：

```
GitHub push protection（免费）
  → Gitleaks（CI 门禁）
    → TruffleHog（定期验证扫描）
      → 员工 stealer log 监控
        → 暗网监控（最后，且最贵）
```

暗网监控最贵、门槛最高、最容易被高估价值 —— **前四项能覆盖它 80% 的实际收益。**

**关于 AI**：把它当**放大器**用（采集提速、格式转换、初筛、报告起草），不要当**判官**用。任何写进报告、任何指向具体某个人的结论，都必须有人工复核和证据回溯链。

---

## 来源清单

### 官方一手来源（本文标【已查证】的数字均来自这里）

1. SpiderFoot GitHub README — https://github.com/smicallef/spiderfoot （模块数、37 规则、输出格式、许可证；提交日期 2023-02-21）｜ 抓取 2026-10-03
2. SpiderFoot 关联引擎文档 — `correlations/template.yaml`、`correlations/README.md`（同仓库）
3. OWASP Amass v4.0.3 README — https://github.com/owasp-amass/amass/tree/v4.0.3 （数据源完整清单）｜ 抓取 2026-10-03
4. Amass v4 架构（DeepWiki 镜像官方源码）— https://deepwiki.com/owasp-amass/amass/1.1-architecture-overview
5. Amass 官方 Quick Start Tutorial（PDF）— https://github.com/owasp-amass/amass/files/13045667/amass.quick.guide.edit.pdf
6. An Introduction to OWASP Amass 4（devious-plan.com，架构解读）— https://www.devious-plan.com/blog/an-introduction-to-owasp-amass-4-part-2-the-data
7. Have I Been Pwned API v3 #PwnedPasswords — https://haveibeenpwned.com/API/v3#PwnedPasswords （k-匿名、Add-Padding、隐私边界）｜ 抓取 2026-10-03
8. Hunter.io 定价 — https://hunter.io/pricing （全部套餐与 credit 额度）｜ 抓取 2026-10-03
9. 《中华人民共和国个人信息保护法》全文（工信部）— https://sdca.miit.gov.cn/zwgk/fgbz/art/2026/art_3e2ad39014b743d58bab7a6815640aee.html
10. PhishTank FAQ — https://www.phishtank.com/faq.php （社区投票验证机制、API key 需注册）
11. DarkOwl Q1 2026 产品更新 — https://www.darkowl.com/?p=15031/ （431,000 listings、+21%/+20.5%/+9%、52 语翻译、Vision API 字段）
12. ProjectDiscovery Nuclei & Templates 博客 — http://projectdiscovery.io/blog/category/nuclei-templates/1 （v10.4.2/10.4.3 模板数与 CVE 数、Global Matchers、AI/LLM 攻击面）
13. Hudson Rock / infostealers.com 数据集 — https://www.infostealers.com/about-info-stealers/ （36,497,778 机器 / 5,785,481 员工 / 14,484,670 Android / 16,258,447 域，每 5 分钟刷新）｜ 抓取 2026-10-03
14. Hudson Rock 免费监控工具（3 邮箱/3 用户名/3 域名）— https://www.hudsonrock.com/blog/free-infostealer-monitoring-track-up-to-3-emails-3-domains-and-3-usernames
15. Hudson Rock 100,000 Hackers Exposed（去匿名化方法论）— https://www.hudsonrock.com/blog/108
16. Google 搜索算子官方文档 — https://developers.google.com/search/docs/monitor-debug/search-operators

### 学术来源

17.《Evaluating the Reliability of LLMs in OSINT Investigations: A Friend or Foe?》ECCWS 2026, DOI 10.34190/eccws.25.1.4818 — https://www.mendeley.com/catalogue/8c58572f-e172-3cd2-9ac7-9d942b078986
18. 《Agentic and Generative AI for Open-Source Intelligence and Cyber Investigations: Taxonomy, Evaluation, Challenges, and Future Directions》arXiv:2607.03233（74 研究综述，幻觉-验证鸿沟，2026-07-02）— https://arxiv-vanity.com/papers/2607.03233
19. 同上，机器审读与批评 — https://www.pith.science/p/2607.03233 （指出"仅一项测量"结论的样本局限）

### 媒体 / 机构

20. Tow Centre for Digital Journalism：LLM 图像核验研究（280 问 14 全对），转述于 NewsMeter OSINT Pulse 2025-09
21. NewsGuard 审计：LLM 35% 重复虚假信息（2025-08 vs 2024-08 的 18%），同上来源

### 中国法律与判例

22. 员工超越授权范围获取信息数据（卫某某案 / 张某某案 / 虞某案，含两高解释条文与情节严重标准）— https://ricc.com.cn/articles-1073
23. 数据保护典型案例与执法监管动态（二）（滴滴行程轨迹案、华为易某案、深圳中院 (2021)粤03刑终1657、一案双查）— https://www.allbrightlaw.com/SH/CN/10475/f94b5de5b6d220c3.aspx
24. 上海市人民检察院：员工数据泄露案（侵犯公民个人信息罪 + 商业秘密罪，数罪并罚）— https://www.sh.jcy.gov.cn/xwdt/jcdt/92652.jhtml

### 合规判例（境外）

25. Lusha 被意大利 Garante 罚款 200 万欧元解析 — https://www.dsn-group.com/privacy-notes/lusha-fined-2-million-euros-important-lessons-about-data-enrichment

### 技术文档

26. SMTP RCPT TO 枚举原理与日志检测信号 — https://conbool.com/blog/rcpt-to-smtp-enumeration-en
27. 邮箱验证四层与 SMTP 响应码 — https://www.smtpedia.com/email-validation-101 ｜ https://kaijuverifier.com/blog/smtp-validation-explained ｜ https://prospeo.io/s/how-to-test-if-an-email-address-is-valid （三方数字互相冲突处已在正文标注）

### 工具对比

28. Gitleaks vs TruffleHog 官方文档对照 — https://devsecopsatlas.com/guides/gitleaks-vs-trufflehog
29. 密钥扫描工具 2026 实测（60 密钥 + 15 熵陷阱，2026-04）— https://safeguard.sh/resources/blog/best-secrets-detection-tools-compared-2026 【三方，含 Gitleaks 8.19 许可变更提示】
30. abuse.ch / ThreatFox / URLhaus / PhishTank 对比 — https://8bitsecurity.com/posts/top-5-osint-sources-for-phishing-analysis-in-2025/
31. 威胁情报库工作机制（Google Safe Browsing 30 分钟窗口、VT 误报）— https://www.captaindns.com/en/blog/threat-intelligence-databases-explained

### 定价（务必自行核验）

32. Intelligence X 定价与能力 — https://www.cybervendorguide.com/tools/intelligence-x ｜ https://osintbench.com/tools/intelligence-x （免费 10 条结果上限）
33. DarkOwl / Flare / Constella / Hudson Rock 定价对比 — https://blog.haveibeenransom.com/post/socradar-vs-the-field-5-alternatives-for-smarter-threat-intel-90ee216c9052 ｜ https://rallied.ai/blog/best-dark-web-monitoring-tools-msps/ ｜ https://mspcompared.com/compare/darkowl-vs-flare
34. Hudson Rock 免费工具原理与局限 — https://osintbench.com/tools/hudson-rock ｜ https://securitynews.com/analytics-intelligence/how-does-hudson-rock-combat-infostealer-malware-threats/

### 框架现状

35. theHarvester / Recon-ng 2026 现状（数据源收缩、marketplace 长尾）— https://ringsafe.in/theharvester-recon-ng-osint-toolchain
36. GHunt 架构与 AGPL-3.0 授权 — http://blog.brightcoding.dev/2026/02/03/ghunt-the-revolutionary-osint-framework-for-google-intelligence 【三方，与项目仓库交叉验证】
37. Blackbird OSINT（注意与 blackbird.ai 企业产品区分）— https://alternativeto.net/software/blackbird-osint/
38. OSINT 工具生态变动（BinaryEdge 关闭、Clearbit/Pipl 转付费等）— https://maxintel.org/osint-tool-graveyard-2026.html 【三方，本报告仅作背景，未采信具体数字】

### Google 算子

39. Google 官方算子文档（日文版，含 filetype/site/src）— https://developers.google.com/search/docs/monitor-debug/search-operators?hl=ja
40. 2026 算子完整状态表（cache:/link:/related: 废弃时间）— https://techglean.com?p=12494/ ｜ https://getdork.com/guides/google-search-operators-cheat-sheet.html ｜ https://orangemonke.com/?p=2494/ 【三方，三源对 cache:2024、link:2017、related:2023 的废弃时间一致】

---

**最后一点提醒**：本报告中标【三方】的定价数字（DarkOwl $38K-60K、Constella $315K-415K、Flare $417/月）在采购谈判中**必须要求厂商书面报价单确认** —— 这些来自竞品对比文章和第三方交易数据库（Vendr），与厂商实际报价常有显著差距。
