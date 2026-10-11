# 定时资产监控（wukan monitor）

把 `recon --snapshot` + `diff --exit-code` 封装成**可挂到系统调度器**的一键脚本，
让「资产监控」真正跑成闭环：每次运行存快照 → 与上次对比 → 有变化时告警。

| 文件 | 平台 | 调度器 |
|---|---|---|
| [`monitor.ps1`](monitor.ps1) | Windows | 任务计划程序（Task Scheduler） |
| [`monitor.sh`](monitor.sh) | Linux / macOS | cron / systemd timer |

## 它每次运行做什么

```
对每个目标：
  ① wukan recon <目标> --snapshot --exit-code …
     # 侦察 + 存快照 + 变化判定（对比"上次存储 vs 本次实测"，去重也正确）
     # 退出码：0=无变化（含首次建立基线）/ 1=有变化 / 2=失败
  有变化（rc=1）→ 用 wukan diff 生成告警正文
          → 写 changes.txt + <目标>-latest-changes.txt
          + stdout 输出（cron 可配 MAILTO 收邮件）
          + 执行 WUKAN_NOTIFY_CMD 通知钩子
```

**退出码**：`0` = 无变化；`1` = 有变化；`2` = 出错。
（Windows 任务计划里"上次运行结果 `0x1`"即代表发现变化，可据此配置告警动作。）

> 为什么用 `recon --exit-code` 判定而不是 `diff --exit-code`：
> recon 对比的是"上次存储 vs 本次实测"——快照内容去重时也正确；
> 而 `diff` 对比"最近两份已存快照"，在去重场景下会重复报同一个变化。
> `diff --exit-code`（0/1/2）仍可用于手动复查与自定义脚本。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `WUKAN_TARGETS` | —（必填） | 空格分隔的目标域名 |
| `WUKAN_BIN` | `wukan` | 可执行文件路径（不在 PATH 时指定） |
| `WUKAN_RECON_ARGS` | `--no-rdap` | recon 附加参数；要主动探测可加 `--ports 80,443 --tech`（⚠️ 需授权） |
| `WUKAN_LOG_DIR` | `~/.wukan/monitor` | 日志目录 |
| `WUKAN_NOTIFY_CMD` | 空 | 有变化时执行的命令，diff 文本经 **stdin** 传入 |

## Windows：任务计划程序

```powershell
# 每天 08:30 运行（先按需修改路径与目标）
$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument '-NoProfile -ExecutionPolicy Bypass -File "D:\tools\HouseRecon\scripts\monitor\monitor.ps1"'
$trigger = New-ScheduledTaskTrigger -Daily -At 08:30
Register-ScheduledTask -TaskName "wukan-monitor" -Action $action -Trigger $trigger

# 环境变量通过脚本参数或系统环境变量提供；也可直接：
#   schtasks /Create /TN wukan-monitor /SC DAILY /ST 08:30 ^
#     /TR "powershell -NoProfile -ExecutionPolicy Bypass -File D:\tools\HouseRecon\scripts\monitor\monitor.ps1"
```

手动先跑一次确认（含首次基线）：

```powershell
$env:WUKAN_BIN = "D:\tools\HouseRecon\wukan.exe"
$env:WUKAN_TARGETS = "example.com"
.\monitor.ps1
```

## Linux / macOS：cron

```bash
chmod +x monitor.sh
crontab -e
# 每天 08:30（有变化时 stdout 非空；配合 MAILTO 可收邮件）
MAILTO=me@example.com
30 8 * * * WUKAN_BIN=/usr/local/bin/wukan WUKAN_TARGETS="example.com" /opt/wukan/monitor.sh
```

## Linux：systemd timer（更稳的替代）

```ini
# ~/.config/systemd/user/wukan-monitor.service
[Service]
Type=oneshot
Environment=WUKAN_TARGETS=example.com
ExecStart=/usr/local/bin/wukan-monitor.sh
# 有变化时（exit 1）系统会标记 failed，可用 OnFailure= 挂告警单元
```

```ini
# ~/.config/systemd/user/wukan-monitor.timer
[Timer]
OnCalendar=*-*-* 08:30:00
Persistent=true
[Install]
WantedBy=timers.target
```

## 通知钩子示例

```bash
# 企业微信/钉钉/飞书 webhook（diff 文本作为 body）
WUKAN_NOTIFY_CMD="curl -s -X POST -H 'Content-Type: text/plain' --data-binary @- https://your-webhook"

# 只写文件（默认行为已包含；这里是自定义示例）
WUKAN_NOTIFY_CMD="tee -a /var/log/wukan-alerts.txt"

# macOS 桌面通知
WUKAN_NOTIFY_CMD="xargs -0 -I{} osascript -e 'display notification \"{}\" with title \"wukan 资产变化\"'"
```

## 日志目录结构

```
~/.wukan/monitor/
├── monitor.lock               # 运行锁（防重叠；脚本自动管理）
├── cron.log                   # （cron 重定向产生，可选）
├── changes.txt                # 所有变化的历史追加
├── <目标>.log                 # 每个目标的运行日志
└── <目标>-latest-changes.txt  # 最近一次变化详情（告警内容）
```

## 注意

- 首次运行只建立基线（`diff` 报"只有一个快照"，脚本按"无变化"处理，不告警）。
- 主动探测参数（`--ports` / `--tech` / `--quic`）会真实发包，**只对已授权资产使用**。
- 快照默认保留每目标最近 30 份（内容相同 24 小时内去重），足够覆盖一个月以上的每日监控。
