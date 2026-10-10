# wukan recon — 目标信息卡

**一个命令摸清一个域的全貌。全部被动采集，不向目标发送任何探测包。**

## 编译

```bash
export PATH="/c/Program Files/Go/bin:$PATH"   # Windows
go build -o wukan.exe ./cmd/wukan
```

## 用法

```bash
wukan recon example.com
wukan recon example.com -o recon.json
wukan recon -f domains.txt -p              # 多目标并行
```

## 采集什么

| 段 | 内容 | 数据源 |
|---|---|---|
| **DNS** | A / AAAA / CNAME / NS / MX / TXT / SOA + **泛域名检测** | 阿里 DoH（可切换） |
| **注册信息** | 注册商 / 注册时间 / 过期时间 / NS / DNSSEC / 锁状态 | rdap.org → 注册局 |
| **证书透明度** | 子域域名 + 首次/最后出现时间 + 证书数 | certspotter（备源 crt.sh） |
| **IP 归属** | 归属 / ASN / ISP + CDN·云·代理识别 | ipwho.is + ip-api.com |
| **可行动发现** | 见下 | 分析层 |

## ⭐ 可行动发现（这是本命令的价值所在）

不是"打印一堆记录"，而是告诉使用者**哪里需要注意**：

| 类型 | 级别 | 说明 |
|---|---|---|
| `very_new_domain` | 🔴 | 域名注册不足 30 天 —— 已知钓鱼/仿冒前置动作 |
| `nxdomain` | 🔴 | 域名不存在 |
| `expired` | 🔴 | 域名已过期，可能被释放 |
| `no_spf` / `no_dmarc` | 🟡 | 有 MX 但缺 SPF/DMARC → 可被邮件仿冒 |
| `new_domain` | 🟡 | 域名注册不足 180 天 |
| `expiring` | 🟡 | 90 天内过期 |
| `shadow_asset` | 🟡 | 历史证书里的子域当前不解析 → 疑似遗留资产 |
| `single_ns` | 🟡 | 只有 1 个 NS |
| `cdn_detected` | 🟡 | ⭐ CDN 边缘节点会干扰端口扫描结果 |
| `wildcard` | ℹ️ | ⭐ 检测到泛域名 → **子域能解析不能证明存活** |
| `txt_tokens` | 🔵 | ⭐ TXT 暴露第三方平台验证 token（Shopify/Stripe/Facebook…） |
| `no_dnssec` | 🔵 | 未启用 DNSSEC |
| `cloud_detected` | 🔵 | IP 属云服务商（org 匹配，可靠） |
| `hosting_detected` | ℹ️ | IP 是数据中心（**上游 API 判定，可能误报**） |
| `active_subdomains` | ℹ️ | 证书记录中仍在有效期内的子域清单 |
| `revoked_certs` | ℹ️ | 证书被全部吊销的子域 |
| `ct_unavailable` | 🔵 | CT 源全挂（会明确列出失败原因） |

### ⭐ 三个实测发现的亮点

**1. TXT 里的第三方 token**（实测 github.com 有 9 个）
```
shopify-verification-code=xxx
stripe-verification=xxx
facebook-domain-verification=xxx
google-site-verification=xxx
atlassian-domain-verification=xxx
apple-domain-verification=xxx
```
这些是**域名所有权验证凭据**，正常情况不该在公开 DNS 里。可用于品牌冒充、钓鱼站点搭建。工具会列出平台名但**隐藏 token 值**。

**2. 泛域名检测联动影子资产判定**
```
🔵 [wildcard] 检测到泛域名解析 *.taobao.com
     泛域名会让任意子域都解析成功，因此**子域能解析不能作为资产存活的证据**。
🟡 [shadow_asset] 发现 N 个历史证书中的子域当前不解析
     ⚠ 注意：该域有泛域名解析，所以「能解析」也不能证明资产存活。
```
两个发现互相印证，避免误判。

**3. 证书时间线**
```
子域                          状态       首次出现    最后出现    证书数
f.cloud.github.com          ✓ 存活     2026-02-27  2027-03-31  2
classroom.github.com ★      ✓ 存活     2026-07-27  2026-12-31  11
```
★ = 出现在 3+ 张证书（更可能是真实在用的资产）。这是**现有子域收集工具全都丢掉的维度**。

## 输出格式

```bash
wukan recon example.com                    # 表格
wukan recon example.com -o r.json          # JSON（扩展名自动推断）
wukan recon example.com --hosts            # hosts 格式
wukan recon example.com --subs             # 子域列表（一行一个）

# 串进下游
wukan recon example.com --subs > subs.txt
wukan recon example.com --hosts >> /etc/hosts
```

## 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-o`, `--output` | stdout | 输出文件 |
| `--format` | table | table / json / hosts / subs |
| `-d`, `--dns` | alidns | alidns / cloudflare / google / quad9 / 360 / dnspod，或直接给 DoH URL |
| `-n` | 30 | 表格最多显示多少子域 |
| `-p`, `--parallel` | — | 多目标并行 |
| `--no-rdap` | — | 跳过注册信息 |
| `--no-ct` | — | 跳过证书透明度 |
| `--no-ipinfo` | — | 跳过 IP 归属 |
| `--no-verify` | — | 跳过子域 DNS 验证（快 ~25s） |
| `--all-domains` | — | 含平行域（如 `example-int.com`） |
| `--no-cache` | — | 不用缓存 |

---

## 数据源实测结论（2026-10-04）

| 源 | 状态 | 备注 |
|---|---|---|
| `dns.alidns.com` | ✅ 0.1s 最快 | **默认**。⚠️ `Question` 返回**对象** |
| `cloudflare-dns.com` | ❌ SSL 失败 | 本环境 `UNEXPECTED_EOF` |
| `rdap.org` | ✅ 完整 | 注册/过期/NS/DNSSEC 全有 |
| `api.certspotter.com` | ✅ 3.1s | ⚠️ **免费层 100 次/小时** |
| `crt.sh` | ❌ 502 | 常挂，做备源并重试 2 次 |

### ⭐ 单源依赖不可靠 —— 实测教训

开发过程中连续遇到：

| 时间 | 现象 |
|---|---|
| 第 1 次 | crt.sh 502 → 换 certspotter，成功 |
| 第 20+ 次 | certspotter 429 限流 + crt.sh 502 → **CT 整段失效** |
| 之后 | 只能靠缓存继续工作 |

所以实现了**三层降级**：
```
缓存 → certspotter → crt.sh
```
全部失败时**不崩溃、不静默**，而是明确报告：
```
🔵 [ct_unavailable] 证书透明度数据源全部不可用
     ├ certspotter: 限流（免费层 100 次/小时）
     └ crt.sh: 返回 502
```

这正是调研报告那句"**至少用两个引擎取 diff**"的现实意义 —— 不是理论最佳实践，是不这么做工具就会挂。

## 缓存

| 缓存 | 路径 | TTL | 为什么需要 |
|---|---|---|---|
| IP 归属 | `~/.wukan/ipinfo-cache.json` | 7 天 | ipwho.is 10000 次/月 |
| **CT 证书** | `~/.wukan/ct-cache.json` | 7 天 | ⭐ certspotter **100 次/小时** |
| 端口扫描 | `~/.wukan/ports-cache.json` | 6 小时（filtered/error 10 分钟） | ⭐ 复核阶段不必重新连接目标（`--ports` / `ports` 共用） |

**空结果不写缓存** —— 否则一次限流会被缓存成"该域无子域"，污染后续所有查询。

## 实测数据

| 目标 | 耗时 | CT 条目 | 去重子域 | 备注 |
|---|---|---|---|---|
| github.com | 7.2s | 79 | 42 | 发现 9 个 TXT token、SPF/DMARC 缺失 |
| baidu.com | — | 100 | 145 | 27 年老域，4 个 A 记录 |
| qq.com | — | 100 | 194 | 31 年老域 |
| taobao.com | — | 100 | 426 | ⭐ 检出泛域名 `*.taobao.com` |
| 三目标并行 | 20.8s | — | — | 全部成功 |

## 修过的坑（都是实测发现的）

| # | 问题 | 根因 |
|---|---|---|
| 1 | **DNS 段整体失效** | 阿里 DoH 的 `Question` 是**对象**，我固定声明成数组 → 7 种记录类型全报解析失败。用自定义 `UnmarshalJSON` 兼容两种 |
| 2 | `www.github.com` 被误判"不解析" | 它是 CNAME → `github.com`，我只查 A 记录。**手写查询不会自动跟随 CNAME**（`net.LookupHost` 会）。实现 `resolveWithCNAME` |
| 3 | 根域自身被标"不解析" | `github.com` 在 CT 结果里也被走 verify 流程，与 DNS 段结论矛盾。显式标记根域 |
| 4 | 影子资产大量误报 | Bug 2 + 3 叠加。修复后 github.com 从"33 个不解析"降到正常 |
| 5 | 同一 IP 在报告里出现两次 | `cloud` 与 `hosting` 是两个标签但同一 IP。证据列表去重 |
| 6 | 假阳性 `cloud` 标签 | 上游 API 的 hosting 被当成 org 匹配。改为按 `FlagSources` 分开归类 |

## 已知局限

1. **CT 源配额很紧**（100/小时），大量目标需分批或配 key
2. **子域"存活"只验证 DNS 解析**。有泛域名时几乎全部"存活"，需 HTTP 探测确认
3. **不查 rDNS / BGP**，ASN 来自 API
4. **不查历史解析**（被动 DNS）—— 这是重要的补充数据源（能发现已下线但仍可注册的资产）
5. **TXT 里的 token 清单是硬编码前缀表**，可能漏新平台
6. **RDAP 联系人通常被注册局脱敏**（`REDACTED FOR PRIVACY`），这是上游限制

## 代码结构

```
wukan-go/
├── cmd/wukan/main.go              CLI
└── internal/
    ├── ipinfo/                    IP 归属（已实现）
    └── recon/
        ├── dns.go                 记录类型、DNS 编排、泛域名检测
        ├── doh.go                 DoH 解析器 + 兼容性处理
        ├── rdap.go                RDAP 客户端
        ├── ct.go                  CT 源 + 聚合 + 缓存
        ├── recon.go               编排 + ⭐ 可行动发现分析
        └── output.go              table / json / hosts / subs
```

## 下一步

- [ ] 接 `wukan ports`（端口扫描，需白名单约束）
- [ ] 接 QUIC 探活（`--quic` 开关）
- [ ] 被动 DNS 历史解析（补上局限 4）
- [ ] 指纹冲突矩阵
