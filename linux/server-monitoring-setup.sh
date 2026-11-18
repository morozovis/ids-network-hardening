#!/bin/bash
# Настройка оповещений о состоянии сервера.
# Запускать под root: bash server-monitoring-setup.sh
set -e

EV=/var/log/sec-events.jsonl

echo "== Файл событий"
touch "$EV"
chown root:alerts "$EV"
chmod 640 "$EV"

echo "== Проверка ресурсов (/usr/local/bin/sysmon-check)"
cat > /usr/local/bin/sysmon-check <<'EOF'
#!/bin/bash
# Пишет событие только при смене состояния: проблема -> норма и обратно.
EV=/var/log/sec-events.jsonl
ST=/var/lib/sysmon
mkdir -p "$ST"

CPU_LIMIT=90      # % загрузки процессора
CPU_MINUTES=5     # сколько минут подряд
MEM_LIMIT=10      # % доступной памяти, ниже - тревога
SWAP_LIMIT=50     # % занятого swap, выше - тревога
DISK_LIMIT=90     # % заполнения диска, выше - тревога

emit() { printf '{"kind":"%s","level":"%s","msg":"%s","t":"%s"}\n' "$1" "$2" "$3" "$(date -Is)" >> "$EV"; }

check() { # имя  плохо(0/1)  сообщение_проблема  сообщение_норма
  local f="$ST/$1" prev=0
  [ -f "$f" ] && prev=$(cat "$f")
  if [ "$2" = 1 ] && [ "$prev" = 0 ]; then emit "$1" warn "$3"; echo 1 > "$f"
  elif [ "$2" = 0 ] && [ "$prev" = 1 ]; then emit "$1" ok "$4"; echo 0 > "$f"
  elif [ ! -f "$f" ]; then echo 0 > "$f"; fi
}

# --- CPU: замер за 5 секунд
read -r _ a b c d e f g h _ < /proc/stat; i1=$((d+e)); t1=$((a+b+c+d+e+f+g+h))
sleep 5
read -r _ a b c d e f g h _ < /proc/stat; i2=$((d+e)); t2=$((a+b+c+d+e+f+g+h))
dt=$((t2-t1)); di=$((i2-i1)); cpu=0
[ "$dt" -gt 0 ] && cpu=$(( 100*(dt-di)/dt ))
cnt=0; [ -f "$ST/cpu_count" ] && cnt=$(cat "$ST/cpu_count")
if [ "$cpu" -ge "$CPU_LIMIT" ]; then cnt=$((cnt+1)); else cnt=0; fi
echo "$cnt" > "$ST/cpu_count"
top_cpu=$(ps -eo comm,%cpu --sort=-%cpu --no-headers | head -1 | awk '{print $1" "$2"%"}')
bad=0; [ "$cnt" -ge "$CPU_MINUTES" ] && bad=1
check cpu "$bad" "Процессор загружен на ${cpu}% уже ${cnt} мин. Больше всех: ${top_cpu}" "Загрузка процессора в норме (${cpu}%)"

# --- Память
mt=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
ma=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
mem=$(( 100*ma/mt ))
top_mem=$(ps -eo comm,%mem --sort=-%mem --no-headers | head -1 | awk '{print $1" "$2"%"}')
bad=0; [ "$mem" -lt "$MEM_LIMIT" ] && bad=1
check mem "$bad" "Мало памяти: доступно ${mem}%. Больше всех: ${top_mem}" "Память в норме: доступно ${mem}%"

# --- Swap
st=$(awk '/^SwapTotal:/{print $2}' /proc/meminfo)
if [ "$st" -gt 0 ]; then
  sf=$(awk '/^SwapFree:/{print $2}' /proc/meminfo)
  swap=$(( 100*(st-sf)/st ))
  bad=0; [ "$swap" -gt "$SWAP_LIMIT" ] && bad=1
  check swap "$bad" "Swap занят на ${swap}%" "Swap в норме (${swap}%)"
fi

# --- OOM killer за последнюю минуту
oom=$(journalctl -k --since "-65s" --no-pager -q 2>/dev/null | grep -oE 'Killed process [0-9]+ \([^)]+\)' | head -1)
[ -n "$oom" ] && emit oom warn "Нехватка памяти, ядро убило процесс: ${oom#Killed process }"

# --- Диск
disk=$(df --output=pcent / | tail -1 | tr -dc '0-9')
bad=0; [ "$disk" -gt "$DISK_LIMIT" ] && bad=1
check disk "$bad" "Диск / заполнен на ${disk}%" "Диск / в норме (${disk}%)"

# --- Suricata
bad=0; systemctl is-active --quiet suricata || bad=1
check suricata "$bad" "Suricata НЕ работает! Проверьте: systemctl status suricata" "Suricata снова работает"

exit 0
EOF
chmod 755 /usr/local/bin/sysmon-check

cat > /etc/systemd/system/sysmon.service <<'EOF'
[Unit]
Description=Проверка ресурсов сервера

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sysmon-check
EOF

cat > /etc/systemd/system/sysmon.timer <<'EOF'
[Unit]
Description=Проверка ресурсов сервера раз в минуту

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF

echo "== Уведомление о входе по SSH (PAM)"
cat > /usr/local/bin/ssh-login-notify <<'EOF'
#!/bin/sh
[ "$PAM_TYPE" = "open_session" ] || exit 0
[ "$PAM_USER" = "alerts" ] && exit 0
printf '{"kind":"ssh-login","level":"info","msg":"Вход по SSH: %s с адреса %s","t":"%s"}\n' \
  "$PAM_USER" "${PAM_RHOST:-локально}" "$(date -Is)" >> /var/log/sec-events.jsonl
exit 0
EOF
chmod 755 /usr/local/bin/ssh-login-notify
grep -q ssh-login-notify /etc/pam.d/sshd || \
  echo "session optional pam_exec.so /usr/local/bin/ssh-login-notify" >> /etc/pam.d/sshd

echo "== Уведомление о банах fail2ban"
cat > /etc/fail2ban/action.d/notify-file.conf <<'EOF'
[Definition]
actionban = printf '{"kind":"f2b-ban","level":"warn","msg":"fail2ban забанил <ip> (jail <name>)","t":"%%s"}\n' "$(date -Is)" >> /var/log/sec-events.jsonl
actionunban =
EOF

cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
backend = systemd
banaction = nftables-multiport
bantime = 1h
findtime = 10m
maxretry = 3
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
action = %(action_)s
         notify-file
EOF

echo "== Поток событий для пользователя alerts"
cat > /usr/local/bin/suricata-alert-stream <<'EOF'
#!/bin/sh
( while :; do echo '{"hb":1}'; sleep 60; done ) &
trap 'kill $! 2>/dev/null' EXIT
tail -q -n0 -F /var/log/suricata/eve.json /var/log/sec-events.jsonl 2>/dev/null | jq -c --unbuffered -R '
  fromjson? |
  if .event_type == "alert" then
    {t:.timestamp, sev:.alert.severity, sig:.alert.signature, sid:.alert.signature_id,
     cat:.alert.category, ss:((.alert.metadata.signature_severity // [""])[0]),
     src:.src_ip, sp:.src_port, dst:.dest_ip, dp:.dest_port, proto:.proto}
  elif .kind then .
  else empty end'
EOF
chmod 755 /usr/local/bin/suricata-alert-stream

echo "== Ротация логов"
cat > /etc/logrotate.d/suricata <<'EOF'
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    create 640 suricata suricata
    postrotate
        systemctl kill -s HUP suricata.service >/dev/null 2>&1 || true
    endscript
}
EOF

cat > /etc/logrotate.d/sec-events <<'EOF'
/var/log/sec-events.jsonl {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    create 640 root alerts
}
EOF

echo "== Запуск"
systemctl daemon-reload
systemctl enable --now sysmon.timer
fail2ban-client -t >/dev/null && systemctl restart fail2ban
logrotate -d /etc/logrotate.d/suricata >/dev/null 2>&1 && echo "logrotate: OK"

echo
echo "Готово. Тестовое событие:"
printf '{"kind":"test","level":"info","msg":"Тест оповещений сервера","t":"%s"}\n' "$(date -Is)" >> "$EV"
echo "Должно всплыть уведомление 'Тест оповещений сервера' на Windows."
