# HouseRecon 后续开发路线图

> **用途**：换机开发交接 + 后续规划
> **生成时间**：2026-10-10
> **对应提交**：`bee7a89`（main 分支）
> **仓库**：https://github.com/xiabai2008/HouseRecon

---

## 0. 换机交接：新电脑上怎么跑起来（最先读）

### 0.1 环境要求

| 项 | 要求 | 本机实测 |
|---|---|---|
| Go | **1.24+**（go.mod 声明） | go1.27.1 windows/amd64 |
| git | 任意近期版本 | — |
| 操作系统 | Windows / Linux / macOS 均可 | Windows 11 |
| 第三方依赖 | **无**（这是项目的核心约束之一） | — |

### 0.2 五步验证

```bash
# ① 克隆
git clone https://github.com/xiabai2008/HouseRecon.git
cd HouseRecon

# ② 编译（Windows 上 Go 若不在 PATH 里需先加）
export PATH="/c/Program Files/Go/bin:$PATH"
cd prototype/wukan-go
go build -o wukan.exe ./cmd/wukan

# ③ 冒烟测试：应看到 ASCII 启动页
./wukan.exe help

# ④ 单元测试：应 39 项全过
go test ./...
# 期望输出：ok  github.com/wukan/wukan/internal/httpprobe
#           ok  github.com/wukan/wukan/internal/ipinfo
#           ok  github.com/wukan/wukan/internal/recon

# ⑤ 端到端：跑一个真实目标
./wukan.exe recon github.com
```

**四步全过 = 环境就绪。**

### 0.3 缓存目录（不在仓库里，换机后是空的）

| 缓存 | 路径 | TTL | 首次运行会自动创建 |
|---|---|---|---|
| IP 归属 | `~/.wukan/ipinfo-cache.json` | 7 天 | ✅ |
| CT 证书 | `~/.wukan/ct-cache.json` | 7 天 | ✅ |
| 被动 DNS | `~/.wukan/passive-cache.json` | 14 天 | ✅ |
| HTTP 指纹 | `~/.wukan/tech-cache.json` | 1 天 | ✅ |

> 换机后缓存为空 = 首次运行会慢一些（要在线查），**这是正常的**，跑第二次就快了。
> 清缓存：`wukan recon --tech-cache-clear`；看统计：`wukan recon --tech-cache-stats`

### 0.4 ⚠️ Windows 环境坑（都踩过）

| 坑 | 现象 | 解法 |
|---|---|---|
| `gofmt` 后 python 替换静默失败 | 改了代码但没生效，或编译报 `unknown field` | **改 Go 结构体字段时别用脚本按文本替换**，用编辑器精确改；或先 gofmt 再改 |
| `net.Resolver` 无 `Lookup` 方法 | 编译报 `has no field or method Lookup` | Go 只导出 `LookupHost/LookupIP/LookupNetIP`，按记录类型查询必须走 DoH |
| 后台进程在工具调用间被杀 | 本地靶场"莫名消失"，扫描全报 closed | 起靶场 + 扫描放**同一次** shell 调用内；判别：RTT 全 <1ms 且一致 = 靶场已死 |
| CRLF 混乱 | git 大量 warning | 仓库已加 `.gitattributes` 统一 LF |

### 0.5 本地靶场（验证扫描器用）

```bash
cd prototype/wukan-go/internal/portscan/testdata
python range_server.py     # 起 7 个端口：18080/18081/18443/13306/14422/19999/19998
#
# 另开一个终端：
cd prototype/wukan-go
./wukan.exe ports 127.0.0.1 -p 18080,18081,18443,13306,14422,19999,19998,22999 --timeout 2 -a
# 期望：7 个 open、22999 closed、banner 正确识别 nginx/Apache/MySQL/SSH
```

---

## 1. 项目现状（截至 `bee7a89`）

### 1.1 代码规模

**13279 行 Go，21 个文件，零第三方依赖，单文件 exe（11MB）**

| 模块 | 行数 | 职责 |
|---|---|---|
| `internal/recon` | 4831 | 目标信息卡（DNS/RDAP/CT/被动DNS/rDNS/端口/指纹编排 + 发现分析） |
| `internal/httpprobe` | 2730 | HTTP 指纹采集 + ⭐冲突检测 + 缓存 + favicon 哈希表 |
| `internal/ipinfo` | 1930 | IP 归属查询 + rDNS 反查 + 缓存 |
| `internal/portscan` | 953 | TCP connect 扫描 + 端口白名单 + 限速 |
| `internal/quic` | 880 | QUIC/UDP-443 探活 |
| `cmd/wukan` | 1955 | CLI（4 个子命令 + 启动页） |

### 1.2 能力矩阵

| 子命令 | 性质 | 默认 | 核心能力 |
|---|---|---|---|
| `recon` | 以被动为主 | ✅ 开 | DNS / RDAP / 证书透明度 / 被动 DNS / rDNS / 34 类可行动发现 |
| `recon --ports` | 🔴 主动 | ⛔ 关 | 对解析 IP 扫指定端口，4 类端口风险发现 |
| `recon --tech` | 🔴 主动 | ⛔ 关 | 5 路指纹交叉校验，⭐默认连带探测存活子域 |
| `recon --quic` | 🔴 主动 | ⛔ 关 | UDP/443 探活，找"只开 HTTP/3"的资产 |
| `tech` | 🔴 主动 | — | 独立指纹冲突检测 |
| `ports` | 🔴 主动 | — | 独立端口扫描 |
| `ipinfo` | 纯被动 | — | IP 归属 + `--rdns` 反查 |

### 1.3 ⭐ 三大差异化（改代码时别破坏）

1. **可行动发现**：不是打印数据，而是给"哪里有问题 + 该做什么"。34 类，带严重程度/证据链/判读。
2. **指纹冲突矩阵**：5 路独立指纹交叉校验，检测来源间自相矛盾。**现有工具只拼接不校验。**
3. **TCP connect 免 SYN Proxy 误报**：半开扫描会被 SYN Proxy 骗出大量假开放端口。

---

## 2. ⭐⭐ 必须遵守的开发原则（血泪教训）

> 这些是开发过程中真实踩过的坑。**违反其中任何一条都会引入难查的 bug。**

### 2.1 数据不能凭记忆填 —— 必须实测

**教训**：favicon 哈希表初版 9 条凭印象填，实测后发现**几乎全错**（Jenkins 实际 `1928290`，初版写 `1989169301`，差三个数量级）。

填错的数据**不会让程序崩溃，只会静默失效**（favicon 永远匹配不上，无任何报错）。

**规则**：任何硬编码的映射表（favicon 哈希、端口-服务映射、CDN 特征头）都必须由**实测**或**独立实现交叉验证**产出，并记录来源（md5/URL/日期）。

### 2.2 每步实跑验证，禁止"看起来合理"

- 编译通过 ≠ 功能正确
- 单元测试过 ≠ 端到端正确（favicon 表测通了算法，但表内容是错的）
- 必须用**真实目标**或**本地靶场**验证，并保留可复现的数据

### 2.3 给 `Options` 加字段后必须同步 `DefaultOptions()`

**教训**：`TechSubdomains` 加了字段但漏了初始化 → 零值 `false` → 子域一个不探，**且无任何报错**（根域探测仍正常，看起来"没问题"）。

**规则**：改 `Options` 后搜一遍 `DefaultOptions()`，确认新字段有显式默认值。**布尔字段尤其危险**（零值 = false，语义往往是"关闭"）。

### 2.4 Go 里别对含多字节字符的字符串做固定偏移切分

**教训**：用 `strings.Index(s, " → ")` + `idx+3` 切分，但 `→` 是 **3 字节 UTF-8**，`idx+3` 落在箭头第 2 字节上，切出 `"\x92 GITHUB.COM"` → 所有归属比较失效。

**规则**：用 `strings.SplitN(s, sep, 2)`，不要手算偏移。

### 2.5 报出问题必须同时给出"这意味着什么"

发现（Finding）必须有 `Detail`（判读），否则用户看到告警却不知道该做什么 = 等于没报。

**已有测试固化**：`TestConflicts_HaveImplication`。

### 2.6 冲突检测器自身不能产生假阳性

已修的两个真实假阳性（都有测试防护）：

| 假阳性 | 根因 | 防护 |
|---|---|---|
| CDN 声称 + `Server: Tengine` 泄露 | 同一行证据既当"声称"又当"反证" | CDN 判定必须来自**独立头**（CF-RAY/X-Cache） |
| IP 直连报证书 SAN 不匹配 | 用 IP 访问时 SAN 天然不匹配 | 判断访问形式后再决定是否报 |

**规则**：新增冲突规则时，先问"这两条证据是否真的互相独立"。

### 2.7 缓存失败结果要用短 TTL

**教训**：不缓存失败 → 4 个超时子域每次重试吃掉 16 秒；缓存过长 → 一次抖动被固化成"该站点无指纹"。

**现方案**：正缓存 1 天 / 负缓存 10 分钟。

---

## 3. 后续开发路线图

### 🔴 P0 —— 近期该做（低成本高收益）

| # | 任务 | 价值 | 预估 |
|---|---|---|---|
| P0-1 | **端口扫描结果缓存** | 同 tech 思路。端口状态变化比指纹快，TTL 建议 **6 小时**（非 1 天） | 小 |
| P0-2 | **favicon 表支持外部加载** | 现在改一条哈希就要重编译。支持 `~/.wukan/favicon-extra.json` 覆盖/扩充 | 小 |
| P0-3 | **tech 失败子域重试** | 实测有 4 个子域重定向后超时；失败时改试 http:// 或跳过重定向 | 小 |
| P0-4 | **给 hackertarget 加 key 支持** | 免费层仅 50 次/天，批量场景根本不够 | 小 |

### 🟡 P1 —— 功能增强

| # | 任务 | 说明 |
|---|---|---|
| P1-1 | **多目标 diff（变化监控）** | 保存上次结果，对比报告"新增/消失的子域、端口、指纹变化"。配合定时任务做资产监控 |
| P1-2 | **子域批量端口扫描** | 现在 `--ports` 只扫根域 IP；应对存活子域也扫（注意量级控制） |
| P1-3 | **指纹源扩充** | 现有 5 路。可加：JARM 指纹、HTTP/2 SETTINGS 指纹、TLS 扩展顺序（JA3） |
| P1-4 | **报告导出（Markdown/HTML）** | 现在只有 table/json/hosts/subs。加一个适合直接交付/存档的格式 |

### 🟢 P2 —— 探索性

| # | 任务 | 说明 |
|---|---|---|
| P2-1 | **被动 DNS 完整时间线** | 现在只取快照。完整时间线能看出"何时迁移、迁移到哪" |
| P2-2 | **CDN 真实源站探测** | 现在检测到 CDN 只提示"结果反映边缘节点"，不自动找源站。可加：历史 DNS + rDNS + 证书历史交叉推断 |
| P2-3 | **favicon 表规模化采集** | 现在 23 条手工实测。可写个采集脚本批量抓取 + 自动生成表（**仍需人工校验**） |
| P2-4 | **QUIC 与其他模块联动** | QUIC 探活目前独立，可把结果并入 recon 的发现分析 |

### 优先级建议

```
先做 P0-1 + P0-2  （都是小活，一个下午能完）
再 P0-3 + P0-4     （补齐数据源短板）
然后 P1-1          （diff 是最有产品价值的一步）
```

---

## 4. 已知技术债 / 待解决

| # | 问题 | 影响 |
|---|---|---|
| 1 | **CT 源配额紧**（certspotter 100 次/小时） | 大量目标需分批或自备 key |
| 2 | **被动 DNS 配额 50 次/天**（hackertarget） | 批量场景严重受限 → P0-4 |
| 3 | **favicon 表仅 23 条** | 命中率有限，且图标天然易碰撞 |
| 4 | **子域"存活"只验 DNS 解析** | 有泛域名时几乎全"存活"，需 HTTP 确认 |
| 5 | **端口扫描无法区分 filtered 与 closed-for-open** | TCP connect 的固有代价，已在输出中说明 |
| 6 | **`--tech` 单次最多 20 目标**（含子域） | 大目标需调 `--tech-max`，但请求量会上去 |
| 7 | 部分文档标题含"人员情报"等敏感词 | 内容为合规预警，但分享时注意语境 |

---

## 5. 数据源备忘（配额与特性）

| 源 | 用途 | 配额 | 备注 |
|---|---|---|---|
| `dns.alidns.com` (DoH) | DNS 解析 | 无明确限制 | ⚠️ 返回的 `Question` 是**对象**不是数组 |
| `rdap.org` | 注册信息 | 宽松 | 自动跳转到各注册局 |
| `api.certspotter.com` | 证书透明度 | **100 次/小时** | 主源，3.1s 稳定 |
| `crt.sh` | 证书透明度 | 宽松 | 备源，**常 502**，重试 2 次 |
| `api.hackertarget.com` | 被动 DNS / IP 反查 | **50 次/天** | 无 key 可用 |
| `ipwho.is` | IP 归属（主） | 10000 次/月 | — |
| `ip-api.com` | IP 归属（补 hosting/proxy） | 45 次/分钟 | 判定可能误报，已分开归类 |

**降级链路**：缓存 → certspotter → crt.sh。全失败时**不崩溃不静默**，明确报告原因。

---

## 6. 开发与提交规范

### 6.1 提交前自检

```bash
cd prototype/wukan-go
gofmt -l .                  # 应为空
go vet ./...                # 应无输出
go test ./...               # 应 39 项全过（新增功能需补测试）
go build -o wukan.exe ./cmd/wukan
```

### 6.2 提交信息格式

```
<type>(<scope>): <简短描述>

<正文：为什么这么改、踩了什么坑>
```

type 用 `feat` / `fix` / `docs` / `refactor` / `perf` / `test`。

⭐ **踩坑发现的 bug，在 commit 正文里写清根因** —— 这是项目最重要的知识沉淀。

### 6.3 新增功能的验收标准

1. 有单元测试（尤其是**边界情况**与**假阳性防护**）
2. 用真实目标或本地靶场端到端跑通
3. 如果引入硬编码数据 → 附实测来源
4. 如果新增"发现"类型 → 必须有判读（`Detail`）
5. 如果改了 `Options` → 检查 `DefaultOptions()`

### 6.4 推送

```bash
git add -A
git status              # ⭐ 确认没混入 .workbuddy/ 或 *.exe
git commit -m "..."
git push
```

---

## 7. 相关文档索引

| 文档 | 内容 |
|---|---|
| [README](../../README.md) | 项目门面、特性、实测数据 |
| [技术方案与实施计划](HouseRecon-技术方案与实施计划.md) | 总体设计 |
| [信息收集方法全景分类](信息收集方法全景分类.md) | 方法论与合法性边界 |
| [可创新扫描手法评估](可创新扫描手法评估.md) | 差异化机会 |
| [实用功能清单与开发优先级](实用功能清单与开发优先级.md) | 早期功能取舍 |
| [QUIC 探活原型验证报告](QUIC探活原型验证报告.md) | QUIC 实测报告 |
| [调研报告/](调研报告/) | 工具生态全景 + 三个附录 |

---

*本文档随开发推进持续更新。换机后先跑完 §0.2 的五步验证再动手。*
