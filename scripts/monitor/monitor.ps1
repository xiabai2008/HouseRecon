# wukan monitor — 资产变化监控（Windows 任务计划程序用）
#
# 每次运行：对每个目标跑 recon --snapshot --exit-code（存快照 + 变化判定）。
# 有变化时：用 diff 生成告警正文 → 写变更文件 + 输出到 stdout + 执行通知钩子。
#
# ⭐ 为什么用 recon --exit-code 判定而不是 diff：
#   recon 对比的是"上次存储 vs 本次实测"——快照内容去重时也正确；
#   而 diff 对比"最近两份已存快照"，在去重场景下会重复报同一个变化。
#
# 退出码：0 = 无变化；1 = 有变化；2 = 出错
#   （任务计划程序里可在"上次运行结果"看到 0x1 即代表发现变化，可据此触发告警）
#
# 环境变量（也可用同名参数覆盖）：
#   WUKAN_BIN         wukan 可执行文件路径（默认：PATH 里的 wukan）
#   WUKAN_TARGETS     空格分隔的目标域名（必填）
#   WUKAN_RECON_ARGS  recon 附加参数（默认 --no-rdap；要主动探测可加 --ports 80,443 --tech）
#   WUKAN_LOG_DIR     日志目录（默认 ~/.wukan/monitor）
#   WUKAN_NOTIFY_CMD  有变化时执行的命令（diff 文本经 stdin 传入；如 curl webhook）
#
# 用法：
#   $env:WUKAN_TARGETS="example.com example.org"; .\monitor.ps1
param(
    [string]$Targets = $env:WUKAN_TARGETS,
    [string]$WukanBin = $(if ($env:WUKAN_BIN) { $env:WUKAN_BIN } else { "wukan" }),
    [string]$ReconArgs = $(if ($env:WUKAN_RECON_ARGS) { $env:WUKAN_RECON_ARGS } else { "--no-rdap" }),
    [string]$LogDir = $(if ($env:WUKAN_LOG_DIR) { $env:WUKAN_LOG_DIR } else { Join-Path $env:USERPROFILE ".wukan\monitor" }),
    [string]$NotifyCmd = $env:WUKAN_NOTIFY_CMD
)
$ErrorActionPreference = "Continue"

# ⭐ PowerShell 5.1 对原生命令输出默认按控制台代码页（中文系统为 GBK）解码，
#   而 wukan 输出 UTF-8 —— 不声明会把捕获的中文变成乱码（变更文件不可读）
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

if (-not $Targets) {
    Write-Error "请设置 WUKAN_TARGETS（空格分隔的域名）"
    exit 2
}
if (-not (Get-Command $WukanBin -ErrorAction SilentlyContinue)) {
    Write-Error "找不到 wukan（$WukanBin）；用 WUKAN_BIN 指定路径"
    exit 2
}
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

$hadChange = $false
$hadError = $false
$date = Get-Date -Format "yyyy-MM-dd"
$reconArgList = @($ReconArgs -split '\s+' | Where-Object { $_ })

foreach ($t in ($Targets -split '\s+' | Where-Object { $_ })) {
    $tlog = Join-Path $LogDir "${t}.log"

    # ① 侦察 + 存快照 + 变化判定（0=无 / 1=有 / 2=失败）
    $reconOut = & $WukanBin recon $t --snapshot @reconArgList --exit-code -q 2>&1 | Out-String
    $rc = $LASTEXITCODE
    Add-Content -Path $tlog -Encoding UTF8 -Value $reconOut

    switch ($rc) {
        0 { } # 无告警变化（含首次建立基线）
        1 {
            $hadChange = $true
            # 变化详情：此时最近两份快照正是"变化前 → 变化后"，diff 即告警正文
            $diffOut = & $WukanBin diff $t 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) { $diffOut = "（diff 正文生成失败，但 recon 已确认有变化）`r`n$reconOut" }
            Add-Content -Path (Join-Path $LogDir "changes.txt") -Encoding UTF8 `
                -Value "════════ $date ${t} 发现变化 ════════`r`n$diffOut`r`n"
            Set-Content -Path (Join-Path $LogDir "${t}-latest-changes.txt") -Value $diffOut -Encoding UTF8
            Write-Output "===== $date ${t} ====="
            Write-Output $diffOut
            if ($NotifyCmd) {
                $diffOut | & cmd.exe /c $NotifyCmd
                if ($LASTEXITCODE -ne 0) { Write-Warning "通知钩子执行失败（exit=$LASTEXITCODE）" }
            }
        }
        2 {
            Write-Warning "${t}: recon/快照失败（详见 $tlog）"
            $hadError = $true
        }
    }
}

if ($hadError) { exit 2 }
if ($hadChange) { exit 1 }
exit 0
