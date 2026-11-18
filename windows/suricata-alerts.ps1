# suricata-alerts.ps1
# Всплывающие уведомления Windows о тревогах Suricata.
# Подключается к Debian по SSH под ограниченным пользователем "alerts",
# который умеет только отдавать поток тревог (forced command на сервере).
#
# Защита от зависания:
#  - сервер присылает heartbeat раз в минуту; если 3 минуты нет вообще никаких данных,
#    SSH принудительно закрывается и переподключается;
#  - любая ошибка внутри цикла пишется в лог и не останавливает скрипт;
#  - пока связи нет, напоминание всплывает каждые 30 минут;
#  - каждое утро (после 9:00) всплывает сводка "монитор работает" -
#    если её нет, значит с монитором что-то не так.

$Server           = "10.0.0.5"          # адрес сенсора Suricata
$User             = "alerts"
$Key              = "$env:USERPROFILE\.ssh\alerts_ed25519"
$LogFile          = "$env:USERPROFILE\Documents\suricata-alerts.log"
$SshExe           = "ssh.exe"
$DedupSeconds     = 3600  # одинаковая тревога (сигнатура + источник) всплывает не чаще раза в час
# --- Что всплывает (остальное только в лог и EveBox) ---
# 1) КРИТИЧЕСКОЕ: заражение, управление ботом (C2), эксплойты, повышение прав, веб-атаки,
#    а также всё, что сама сигнатура помечает как Critical.
$CriticalCategories = @(
    "A Network Trojan was Detected",
    "Malware Command and Control Activity Detected",
    "Domain Observed Used for C2 Detected",
    "Exploit Kit Activity Detected",
    "Successful Administrator Privilege Gain",
    "Successful User Privilege Gain",
    "Attempted Administrator Privilege Gain",
    "Attempted User Privilege Gain",
    "Web Application Attack",
    "Executable code was detected",
    "Targeted Malicious Activity was Detected"
)
# 2) АТАКИ НА RDP: внешний адрес -> RDP (3389) или RD Web; сводкой не чаще раза в $RdpToastMinutes минут.
$RdpWebHosts     = @("10.0.0.101")   # куда проброшен RD Web (порт 80)
$RdpToastMinutes = 60
$MaxLogSeverity   = 2     # в лог пишутся уровни 1-2 (+ все атаки на RDP); остальное смотрите в EveBox
$SilenceSeconds   = 180   # нет данных дольше - считаем соединение зависшим
$DownRemindMin    = 30    # напоминание "связи всё ещё нет"
$SummaryHour      = 9     # час утренней сводки

# Известные тревоги: НЕ всплывают, но по-прежнему пишутся в лог (с пометкой "заглушено").
# На сервере (eve.json, EveBox) они хранятся как обычно - этот список влияет только на всплывающие окна.
# Формат: "sid|IP-источника" или "sid|*" (любой источник).
$Muted = @(
    "2012247|10.0.0.44"        # пример: торрент-клиент на известном ПК
)

# --- Toast-уведомления через встроенный WinRT, без сторонних модулей ---
$ToastOK = $true
try {
    [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
    [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
} catch { $ToastOK = $false }
$AppId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'

function Show-Toast([string]$Title, [string]$Text) {
    if (-not $ToastOK) { return }
    try {
        $t = [System.Security.SecurityElement]::Escape($Title)
        $b = [System.Security.SecurityElement]::Escape($Text)
        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$b</text></binding></visual></toast>")
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Show($toast)
    } catch { }
}

function Write-Log([string]$Line) {
    try {
        Add-Content -Path $LogFile -Value ("{0}  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Line) -Encoding UTF8
    } catch { }
}

# --- Состояние ---
$script:lastSeen    = @{}
$script:rdpPending  = 0
$script:rdpIPs      = @{}
$script:rdpLast     = ""
$script:rdpToastAt  = [datetime]::MinValue
$script:down        = $false
$script:downSince   = $null
$script:lastRemind  = $null
$script:stats       = @{ critical = 0; rdp = 0; alerts = 0; muted = 0; server = 0; outages = 0 }
$script:summaryDay  = (Get-Date).Date
if ((Get-Date).Hour -lt $SummaryHour) { $script:summaryDay = (Get-Date).Date.AddDays(-1) }

function Set-Up {
    if ($script:down) {
        $mins = [int]((Get-Date) - $script:downSince).TotalMinutes
        $script:down = $false
        Show-Toast "Suricata: связь восстановлена" "Сервер $Server снова на связи (не было $mins мин.)."
        Write-Log "Связь восстановлена (не было $mins мин.)"
    }
}

function Set-Down([string]$Reason) {
    if (-not $script:down) {
        $script:down       = $true
        $script:downSince  = Get-Date
        $script:lastRemind = Get-Date
        $script:stats.outages++
        Show-Toast "Suricata: нет связи с сервером" "$Reason Повтор каждые 30 секунд."
        Write-Log "Связь потеряна: $Reason"
    } elseif (((Get-Date) - $script:lastRemind).TotalMinutes -ge $DownRemindMin) {
        $script:lastRemind = Get-Date
        $mins = [int]((Get-Date) - $script:downSince).TotalMinutes
        Show-Toast "Suricata: связи всё ещё нет" "Уже $mins мин. нет связи с $Server. Тревоги копятся на сервере (EveBox)."
        Write-Log "Связи всё ещё нет ($mins мин.)"
    }
}

function Test-Summary {
    $now = Get-Date
    if ($now.Hour -ge $SummaryHour -and $script:summaryDay -lt $now.Date) {
        $s = $script:stats
        $state = if ($script:down) { "СЕЙЧАС НЕТ СВЯЗИ с сервером" } else { "связь в порядке" }
        $text = "За сутки: КРИТИЧЕСКИХ - $($s.critical), попыток атак на RDP - $($s.rdp), прочих тревог в логе - $($s.alerts), заглушено - $($s.muted), событий сервера - $($s.server), обрывов связи - $($s.outages). Сейчас $state."
        Show-Toast "Suricata: монитор работает" $text
        Write-Log "Утренняя сводка: $text"
        $script:stats = @{ critical = 0; rdp = 0; alerts = 0; muted = 0; server = 0; outages = 0 }
        $script:summaryDay = $now.Date
    }
}

function Invoke-Line([string]$Line) {
    $a = $null
    try { $a = $Line | ConvertFrom-Json } catch { return }
    if ($null -eq $a -or $a.hb) { return }   # heartbeat от сервера раз в минуту

    # События сервера: ресурсы, входы по SSH, баны fail2ban, падение Suricata
    if ($a.kind) {
        $title = switch ($a.level) {
            "ok"    { "Сервер: норма" }
            "info"  { "Сервер: информация" }
            default { "Сервер: ВНИМАНИЕ" }
        }
        $script:stats.server++
        Write-Log "[$($a.kind)/$($a.level)] $($a.msg)"
        Show-Toast $title $a.msg
        return
    }

    # --- Классификация ---
    $extSrc = -not ("$($a.src)" -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)')
    $class = "other"
    if ([string]$a.sid -eq "9000001" -or $CriticalCategories -contains $a.cat -or $a.ss -eq "Critical") {
        $class = "critical"
    } elseif ($extSrc -and [string]$a.sid -ne "2001330" -and (
                ([string]$a.dp -eq "3389") -or
                ($RdpWebHosts -contains $a.dst -and [string]$a.dp -eq "80") -or
                ("$($a.sig)" -match 'RDP|Terminal Server|BlueKeep|CredSSP'))) {
        $class = "rdp"
    }

    $isMuted = ($Muted -contains "$($a.sid)|$($a.src)") -or ($Muted -contains "$($a.sid)|*")
    if ($class -eq "other" -and [int]$a.sev -gt $MaxLogSeverity) { return }

    $tag  = switch ($class) { "critical" { " [КРИТИЧНО]" } "rdp" { " [RDP-атака]" } default { "" } }
    $mark = if ($isMuted) { " (заглушено)" } else { "" }
    Write-Log "[sev $($a.sev)] $($a.sig) | $($a.src):$($a.sp) -> $($a.dst):$($a.dp) $($a.proto) | sid $($a.sid)$tag$mark"

    if ($isMuted) { $script:stats.muted++; return }

    switch ($class) {
        "critical" {
            $script:stats.critical++
            $k = "$($a.sid)|$($a.src)"
            $now = Get-Date
            if ($script:lastSeen.ContainsKey($k) -and ($now - $script:lastSeen[$k]).TotalSeconds -lt $DedupSeconds) { return }
            $script:lastSeen[$k] = $now
            Show-Toast "КРИТИЧНО: $($a.sig)" "$($a.src):$($a.sp) -> $($a.dst):$($a.dp) ($($a.proto)) | $($a.cat)"
        }
        "rdp" {
            $script:stats.rdp++
            $script:rdpPending++
            $script:rdpIPs["$($a.src)"] = 1
            $script:rdpLast = "$($a.src) -> $($a.dst):$($a.dp)"
            Send-RdpSummary
        }
        default { $script:stats.alerts++ }
    }
}

function Send-RdpSummary {
    if ($script:rdpPending -le 0) { return }
    if (((Get-Date) - $script:rdpToastAt).TotalMinutes -lt $RdpToastMinutes) { return }
    $n = $script:rdpPending; $ips = $script:rdpIPs.Count
    Show-Toast "Атака на RDP: $n попыт. с $ips адрес." "Последняя: $($script:rdpLast). Подробности в логе и EveBox."
    Write-Log "Уведомление RDP: $n попыток с $ips адресов"
    $script:rdpPending = 0; $script:rdpIPs = @{}; $script:rdpToastAt = Get-Date
}

Write-Log "Монитор запущен, сервер $Server"

while ($true) {
    $p = $null
    $reason = "Соединение с $Server оборвалось."
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName  = $SshExe
        $psi.Arguments = "-T -i `"$Key`" -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=30 -o ServerAliveCountMax=3 $User@$Server"
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $p = [System.Diagnostics.Process]::Start($psi)
        $errTask  = $p.StandardError.ReadToEndAsync()
        $lastData = Get-Date
        $readTask = $p.StandardOutput.ReadLineAsync()

        while ($true) {
            if ($readTask.Wait(5000)) {
                $line = $readTask.Result
                if ($null -eq $line) { break }          # ssh завершился
                $lastData = Get-Date
                Set-Up
                Invoke-Line $line
                $readTask = $p.StandardOutput.ReadLineAsync()
            } elseif (((Get-Date) - $lastData).TotalSeconds -gt $SilenceSeconds) {
                $reason = "Нет данных от $Server больше $SilenceSeconds сек. (зависание)."
                break
            }
            Test-Summary
            Send-RdpSummary
        }

        if ($p -and -not $p.HasExited) { try { $p.Kill() } catch { } }
        if ($errTask.Wait(2000)) {
            $err = ($errTask.Result -replace '\s+', ' ').Trim()
            if ($err) { $reason = "$reason SSH: $err" }
        }
    } catch {
        $reason = "Ошибка монитора: $($_.Exception.Message)"
        if ($p -and -not $p.HasExited) { try { $p.Kill() } catch { } }
    } finally {
        if ($p) { try { $p.Dispose() } catch { } }
    }

    Set-Down $reason
    Test-Summary
    Start-Sleep -Seconds 30
}
