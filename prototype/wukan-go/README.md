# wukan ipinfo — IP 归属批量查询

屋勘 HouseRecon 的第一个功能模块。**零第三方依赖**，单 exe。

## 编译

```bash
export PATH="/c/Program Files/Go/bin:$PATH"   # Windows
go build -o wukan.exe ./cmd/wukan
```

## 用法

```bash
# 单个/多个
wukan ipinfo 8.8.8.8 1.1.1.1
wukan ipinfo 1.1.1.1 --geo                # 带经纬度与时区

# 从文件（格式很宽松）
wukan ipinfo -f iplist.txt
```

### 输入格式容错

渗透测试的 IP 列表几乎从不是"纯 IP 一行一个"。以下形式都能直接用：

```
1.2.3.4                          # 纯 IP
1.2.3.4:8080                     # 带端口
https://5.6.7.8/admin            # URL
52.84.180.67 (cloudfront)        # 带注释
1.1.1.1, 8.8.8.8                 # 逗号分隔（一行多个）
2001:db8::1                      # IPv6
# 注释行会跳过
```

### 输出

```bash
# 表格（默认，给人看）
wukan ipinfo -f iplist.txt

# ⭐ 格式可从扩展名自动推断
wukan ipinfo -f iplist.txt -o result.json    # → JSON
wukan ipinfo -f iplist.txt -o result.csv     # → CSV（Excel 可开）
wukan ipinfo -f iplist.txt -o clean.txt      # → 纯 IP 列表

# 显式指定格式
wukan ipinfo -f iplist.txt --csv -o out.csv
wukan ipinfo -f iplist.txt --json -o out.json

# ⭐ 喂给下游工具
wukan ipinfo -f iplist.txt --ips-only -o clean.txt
wukan ipinfo -f iplist.txt --ips-only -o clean.txt | nmap -iL - -p 80,443
```

### 其他参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-w`, `--workers` | 8 | 并发数（上限 64） |
| `-r`, `--rate` | 8 | 每秒请求上限 |
| `--timeout` | 15 | 单次请求超时（秒） |
| `-q`, `--quiet` | — | 只输出结果不打摘要 |
| `--geo` | — | 表格增加经纬度与时区列 |
| `--no-cache` | — | 强制重新查询，不用缓存 |
| `--no-secondary` | — | 不查补充源（省一半请求） |
| `--cache-stats` | — | 查看缓存统计 |
| `--clear-cache` | — | 清空缓存 |

## 数据源与字段可信度

**两个源互补**：

| 源 | 协议 | 额度 | 独有字段 |
|---|---|---|---|
| **ipwho.is**（主） | HTTPS | 免费 10000 次/月 | 经纬度、时区、国家/省/城市、ASN、ISP、域名 |
| **ip-api.com**（补充） | HTTP | 免费 45 req/min | ⭐ `hosting` / `proxy` / `mobile` |

⚠️ **补充源是明文 HTTP**，所以只用于取"非敏感的分类标识"，位置/归属一律以主源为准。

### ⭐ 类型标签的可信度分层

输出里的"类型标签"分两档，**表格的"标签依据"列会标明**：

| 依据 | 标签 | 可信度 |
|---|---|---|
| `(org)` | `cdn` / `cloud` / `cn` | ⭐ 高（org/isp 关键字匹配） |
| `(api待核)` | `hosting` / `mobile` / `proxy?` | ⚠️ 较低（上游判定，实测会误报） |

**`proxy?` 带问号是刻意的** —— 实测发现 ip-api.com 把 `114.114.114.114`（114 公共 DNS，AS137702 中国电信江苏）也标成了 `proxy: true`。所以这个标签不能直接当结论用。

**`cdn` 标签最可靠**（关键字匹配），而且它是渗透测试里最值钱的标签：

> CDN 边缘 IP 会让端口扫描结果失真 —— 你以为扫的是源站，其实扫的是 CDN。
> 工具会在发现 CDN 节点时直接给出提示。

## 缓存

- 位置：`~/.wukan/ipinfo-cache.json`
- 有效期 **7 天**（IP 归属是基础设施级信息，变更极罕见）
- 格式：JSON Lines（容忍末行截断），落盘先去重，不会无限膨胀
- 写入用临时文件 + rename，避免中途崩溃留半截文件

⭐ **为什么必须做缓存**：数据源**不支持批量接口**（实测 `GET /ipwho.is/1.1.1.1,8.8.8.8` 返回 404），只能逐个查。渗透测试中同一批 IP 常被反复查（扫一次、复核一次、写报告一次）—— 缓存让重复查询零消耗。

实测：10 个 IP 首次 1.5s，二次 **0.66s 全部命中，零 API 请求**。

私有/环回/链路本地地址会被直接标注为无效，**不消耗配额**。

## 实测数据

### 三类 IP 识别（`test_ips.txt`）

| IP | 归属 | 标签 | 判断是否正确 |
|---|---|---|---|
| `1.1.1.1` | AU/AS13335 Cloudflare | `cdn/cloud/hosting` | ✅ |
| `104.16.123.96` | US/AS13335 Cloudflare | `cdn/cloud/hosting` | ✅ |
| `23.225.22.1` | US/AS40065 CNSERVERS | `cdn/cloud/hosting` | ✅ 国内最大 CDN 之一 |
| `120.232.99.80` | CN/AS9808 中国移动 | `cn/mobile` | ✅ |
| `114.114.114.114` | CN/AS137702 中国电信 | `cn/hosting/proxy?` | ✅（proxy 已标疑） |
| `192.168.1.1` | — | 无效 | ✅ 不消耗配额 |

### 压测

100 个随机公网 IP，并发 16、限速 12/s：

```
有效 100 / 100，耗时 28.5s
国家分布：US=41 CN=9 BR=6 FR=5 DE=4 JP=3 GB=3 CH=2 …（共 31 个国家/地区）
标签分布：cn=9 cloud=8 mobile=4 hosting=2
```

## 已知局限

1. **proxy 标签会误报**（上游问题，已用 `proxy?` 标注）
2. **CDN 判定是关键字匹配**，会有漏报（CDN 厂商用未收录的 ASN 名）与误报（ISP 名含关键词但非 CDN）
3. **免费额度有限**：ipwho.is 10000 次/月。批量任务建议先过一遍缓存
4. **不查 rDNS / BGP**，ASN 来自 API 而非权威路由数据
5. **IPv6 提取是启发式**，复杂形式（如带 zone id 的 `fe80::1%eth0`）可能漏

## 代码结构

```
wukan-go/
├── go.mod
├── cmd/wukan/main.go          CLI 入口、参数解析、IP 提取
└── internal/ipinfo/
    ├── ipinfo.go              客户端、双数据源、类型分类
    ├── cache.go               JSON Lines 文件缓存
    └── output.go              table / csv / json / ips 输出 + 统计摘要
```

## 下一步

- [ ] 接入 `wukan recon`（一个域名 → 自动提取 IP → 查归属）
- [ ] 加 rDNS 反查（发现同源资产）
- [ ] 加 IP 段批量展开（`1.2.3.0/24` → 256 个 IP）
