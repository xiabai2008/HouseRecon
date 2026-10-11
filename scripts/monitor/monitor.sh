#!/usr/bin/env bash
# wukan monitor — 资产变化监控（Linux / macOS 定时任务用）
#
# 每次运行：对每个目标跑 recon --snapshot --exit-code（存快照 + 变化判定）。
# 有变化时：用 diff 生成告警正文 → 写变更文件 + 输出到 stdout + 执行通知钩子。
#
# ⭐ 为什么用 recon --exit-code 判定而不是 diff：
#   recon 对比的是"上次存储 vs 本次实测"——快照内容去重时也正确；
#   而 diff 对比"最近两份已存快照"，在去重场景下会重复报同一个变化。
#
# 退出码：0 = 无变化；1 = 有变化；2 = 出错
#   （cron 场景：有变化时 stdout 非空，配合 MAILTO 即可收到邮件）
#
# 环境变量：
#   WUKAN_BIN         wukan 可执行文件路径（默认：PATH 里的 wukan）
#   WUKAN_TARGETS     空格分隔的目标域名（必填）
#   WUKAN_RECON_ARGS  recon 附加参数（默认 --no-rdap；要主动探测可加 --ports 80,443 --tech）
#   WUKAN_LOG_DIR     日志目录（默认 ~/.wukan/monitor）
#   WUKAN_NOTIFY_CMD  有变化时执行的命令（diff 文本经 stdin 传入；如 curl webhook）
#
# 用法：
#   WUKAN_TARGETS="example.com example.org" ./monitor.sh
#
# crontab 示例（每天 08:30）：
#   30 8 * * * WUKAN_TARGETS="example.com" /path/to/monitor.sh >> ~/.wukan/monitor/cron.log 2>&1
set -u

WUKAN_BIN="${WUKAN_BIN:-wukan}"
TARGETS="${WUKAN_TARGETS:-}"
RECON_ARGS="${WUKAN_RECON_ARGS:---no-rdap}"
LOG_DIR="${WUKAN_LOG_DIR:-$HOME/.wukan/monitor}"
NOTIFY_CMD="${WUKAN_NOTIFY_CMD:-}"

if [ -z "$TARGETS" ]; then
    echo "错误: 请设置 WUKAN_TARGETS（空格分隔的域名）" >&2
    exit 2
fi
if ! command -v "$WUKAN_BIN" >/dev/null 2>&1; then
    echo "错误: 找不到 wukan（$WUKAN_BIN）；用 WUKAN_BIN 指定路径" >&2
    exit 2
fi

mkdir -p "$LOG_DIR"
LOCK="$LOG_DIR/monitor.lock"

# 防重叠运行：上一次还没跑完就直接退出（定时任务偶发重叠）
if [ -e "$LOCK" ]; then
    OLD_PID=$(cat "$LOCK" 2>/dev/null || true)
    if [ -n "${OLD_PID:-}" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        echo "上一次监控仍在运行（PID $OLD_PID），本次跳过" >&2
        exit 0
    fi
fi
echo $$ >"$LOCK"
trap 'rm -f "$LOCK"' EXIT

DATE=$(date +%Y-%m-%d)
HAD_CHANGE=0
HAD_ERROR=0

for T in $TARGETS; do
    TLOG="$LOG_DIR/$T.log"

    # ① 侦察 + 存快照 + 变化判定（0=无 / 1=有 / 2=失败）
    # shellcheck disable=SC2086
    RECON_OUT=$("$WUKAN_BIN" recon "$T" --snapshot $RECON_ARGS --exit-code -q 2>&1)
    RC=$?
    printf '%s\n' "$RECON_OUT" >>"$TLOG"

    case $RC in
    0) : ;; # 无告警变化（含首次建立基线）
    1)
        HAD_CHANGE=1
        # 变化详情：此时最近两份快照正是"变化前 → 变化后"，diff 即告警正文
        DIFF_OUT=$("$WUKAN_BIN" diff "$T" 2>&1)
        if [ $? -ne 0 ]; then
            DIFF_OUT="（diff 正文生成失败，但 recon 已确认有变化）
$RECON_OUT"
        fi
        {
            echo "════════ $DATE $T 发现变化 ════════"
            printf '%s\n' "$DIFF_OUT"
            echo
        } >>"$LOG_DIR/changes.txt"
        printf '%s\n' "$DIFF_OUT" >"$LOG_DIR/$T-latest-changes.txt"
        printf '===== %s %s =====\n%s\n' "$DATE" "$T" "$DIFF_OUT"
        if [ -n "$NOTIFY_CMD" ]; then
            printf '%s\n' "$DIFF_OUT" | $NOTIFY_CMD || echo "⚠ 通知钩子执行失败" >&2
        fi
        ;;
    2)
        echo "⚠ $T: recon/快照失败（详见 $TLOG）" >&2
        HAD_ERROR=1
        ;;
    esac
done

# 退出码：出错 → 2；有变化 → 1；否则 0（供调度器判断）
if [ "$HAD_ERROR" -eq 1 ]; then exit 2; fi
if [ "$HAD_CHANGE" -eq 1 ]; then exit 1; fi
exit 0
