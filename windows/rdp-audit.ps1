# rdp-audit.ps1 - кто и откуда входил на этот компьютер по RDP
# Запуск: PowerShell ОТ ИМЕНИ АДМИНИСТРАТОРА
#   powershell -ExecutionPolicy Bypass -File .\rdp-audit.ps1
# Результат: на экран и в файл rdp-audit-<ИМЯ_ПК>.txt на рабочем столе.

$Days  = 60
$since = (Get-Date).AddDays(-$Days)
$local = '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80|-)'
$out   = "$env:USERPROFILE\Desktop\rdp-audit-$env:COMPUTERNAME.txt"

function Get-Data($evt) {
    $d = @{}
    ([xml]$evt.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    $d
}

$report = & {
    "=== Компьютер: $env:COMPUTERNAME   Отчёт: $(Get-Date)   Период: $Days дней"

    $oldest = Get-WinEvent -LogName Security -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue
    $cfg    = Get-WinEvent -ListLog Security
    "Журнал 'Безопасность' хранит события с: $($oldest.TimeCreated)   (размер: {0:N0} МБ из {1:N0} МБ)" -f ($cfg.FileSize/1MB), ($cfg.MaximumSizeInBytes/1MB)
    ""

    # 1) Успешные входы с внешних адресов (4624: тип 10 = RDP, тип 3 = сеть/NLA, тип 7 = разблокировка)
    "=== 1. УСПЕШНЫЕ входы с ВНЕШНИХ адресов (Безопасность, 4624)"
    $ok = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$since} -ErrorAction SilentlyContinue |
        ForEach-Object {
            $d = Get-Data $_
            if ($d.LogonType -in '3','7','10' -and $d.IpAddress -and $d.IpAddress -notmatch $local) {
                [pscustomobject]@{ Время=$_.TimeCreated; Пользователь="$($d.TargetDomainName)\$($d.TargetUserName)"; IP=$d.IpAddress; Тип=$d.LogonType }
            }
        }
    if ($ok) {
        "--- сводка: IP / пользователь / сколько раз / первый и последний вход"
        $ok | Group-Object IP, Пользователь | ForEach-Object {
            $t = $_.Group.Время | Sort-Object
            [pscustomobject]@{ IP=$_.Group[0].IP; Пользователь=$_.Group[0].Пользователь; Входов=$_.Count; Первый=$t[0]; Последний=$t[-1] }
        } | Sort-Object Входов -Descending | Format-Table -AutoSize | Out-String -Width 220
    } else { "  нет (или журнал уже перезаписан)"; "" }

    # 2) Успешная проверка подлинности RDP - отдельный журнал, хранится дольше
    "=== 2. Успешная аутентификация RDP с внешних адресов (RemoteConnectionManager, 1149)"
    $rcm = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149; StartTime=$since} -ErrorAction SilentlyContinue |
        ForEach-Object {
            $ip = [string]$_.Properties[2].Value
            if ($ip -and $ip -notmatch $local) {
                [pscustomobject]@{ Время=$_.TimeCreated; Пользователь="$($_.Properties[1].Value)\$($_.Properties[0].Value)"; IP=$ip }
            }
        }
    if ($rcm) {
        $rcm | Group-Object IP, Пользователь | ForEach-Object {
            $t = $_.Group.Время | Sort-Object
            [pscustomobject]@{ IP=$_.Group[0].IP; Пользователь=$_.Group[0].Пользователь; Раз=$_.Count; Первый=$t[0]; Последний=$t[-1] }
        } | Sort-Object Раз -Descending | Format-Table -AutoSize | Out-String -Width 220
    } else { "  нет"; "" }

    # 3) Неудачные попытки (4625)
    "=== 3. НЕУДАЧНЫЕ попытки входа (Безопасность, 4625)"
    $bad = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$since} -ErrorAction SilentlyContinue |
        ForEach-Object { $d = Get-Data $_; [pscustomobject]@{ Время=$_.TimeCreated; Пользователь=$d.TargetUserName; IP=$d.IpAddress } }
    "Всего неудачных попыток: $(@($bad).Count)"
    if ($bad) {
        "--- по дням"
        $bad | Group-Object { $_.Время.ToString('yyyy-MM-dd') } | Sort-Object Name | ForEach-Object { "  $($_.Name)  $($_.Count)" }
        "--- топ-15 логинов, которые подбирали"
        $bad | Group-Object Пользователь | Sort-Object Count -Descending | Select-Object -First 15 -Property Count, Name | Format-Table -AutoSize | Out-String -Width 200
        "--- топ-15 адресов"
        $bad | Group-Object IP | Sort-Object Count -Descending | Select-Object -First 15 -Property Count, Name | Format-Table -AutoSize | Out-String -Width 200
    }

    # 4) Логины, которые подбирали И под которыми потом был успешный вход снаружи
    "=== 4. ВНИМАНИЕ: успешные внешние входы под логинами, которые подбирали"
    if ($ok -and $bad) {
        $brutedUsers = $bad | Group-Object Пользователь | Where-Object Count -ge 20 | ForEach-Object Name
        $hit = $ok | Where-Object { ($_.Пользователь -split '\\')[-1] -in $brutedUsers }
        if ($hit) { $hit | Sort-Object Время | Format-Table -AutoSize | Out-String -Width 220 } else { "  совпадений нет" }
    } else { "  нет данных для сравнения" }
}

$report | Tee-Object -FilePath $out
""
"Отчёт сохранён: $out"
