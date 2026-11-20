#!/bin/bash
# Резервный канал оповещений: письма с сенсора на рабочую почту Яндекса.
# Запуск под root: bash /root/mail-setup.sh
# Спросит адрес и пароль приложения, ничего не выводит на экран.
set -e

echo "== Установка msmtp"
DEBIAN_FRONTEND=noninteractive apt-get install -y msmtp >/dev/null
echo "   ok"

echo "== Адрес и пароль"
read -rp "Адрес рабочей почты Яндекса: " ADDR
read -rsp "Пароль приложения (не отображается): " PASS; echo
[ -n "$ADDR" ] && [ -n "$PASS" ] || { echo "Пусто - отмена"; exit 1; }
umask 077
printf '%s' "$PASS" > /etc/msmtp-yandex.pass
unset PASS

cat > /etc/msmtprc <<EOF
defaults
auth on
tls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile /var/log/msmtp.log

account yandex
host smtp.yandex.ru
port 465
tls_starttls off
from $ADDR
user $ADDR
passwordeval "cat /etc/msmtp-yandex.pass"

account default : yandex
EOF

cat > /etc/mail-alerts.conf <<EOF
MAILTO="$ADDR"
ADMIN_IP="10.0.0.50"   # входы по SSH с этого адреса письмом не дублируются
MAX_PER_HOUR=20             # не больше писем в час (защита от лавины)
DEDUP_SECONDS=3600          # одинаковая тревога - не чаще раза в час
EOF
chmod 600 /etc/msmtprc /etc/msmtp-yandex.pass /etc/mail-alerts.conf
umask 022

echo "== Отправка письма (/usr/local/bin/mail-alert-send)"
cat > /usr/local/bin/mail-alert-send <<'EOF'
#!/bin/sh
# Использование: echo "текст" | mail-alert-send "Тема"
. /etc/mail-alerts.conf
SUBJ=$(printf '%s' "$1" | base64 -w0)
{
  printf 'To: %s\nFrom: Suricata <%s>\nSubject: =?UTF-8?B?%s?=\n' "$MAILTO" "$MAILTO" "$SUBJ"
  printf 'MIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\nDate: %s\n\n' "$(date -R)"
  cat
  printf '\n--\nСенсор Suricata, %s\n' "$(hostname)"
} | msmtp -a yandex "$MAILTO"
EOF
chmod 700 /usr/local/bin/mail-alert-send

echo "== Поток оповещений (/usr/local/bin/mail-alerts)"
cat > /usr/local/bin/mail-alerts <<'EOF'
#!/bin/bash
# Следит за тревогами Suricata и событиями сервера, критичное отправляет письмом.
. /etc/mail-alerts.conf
declare -A LAST
SENT=0; HOUR=$(date +%Y%m%d%H)

tail -q -n0 -F /var/log/suricata/eve.json /var/log/sec-events.jsonl 2>/dev/null |
jq -c --unbuffered -R '
  fromjson? |
  if .event_type == "alert" then
    select((.alert.signature_id == 9000001)
      or ((.alert.category // "") | test("Trojan|Command and Control|C2|Exploit Kit|Privilege Gain|Web Application Attack|Executable code|Targeted Malicious"))
      or (((.alert.metadata.signature_severity // [""])[0]) == "Critical"))
    | {key: "\(.alert.signature_id)|\(.src_ip)",
       subj: "КРИТИЧЕСКАЯ тревога: \(.alert.signature)",
       body: "Время: \(.timestamp)\nСигнатура: \(.alert.signature) (sid \(.alert.signature_id))\nКатегория: \(.alert.category)\nОткуда: \(.src_ip):\(.src_port)\nКуда: \(.dest_ip):\(.dest_port) \(.proto)\n\nПодробности - в EveBox."}
  elif .kind then
    {key: "\(.kind)|\(.level)|\(.msg)", kind: .kind,
     subj: "Сенсор: \(.msg)",
     body: "Время: \(.t)\nТип: \(.kind) (\(.level))\n\(.msg)"}
  else empty end' |
while IFS= read -r line; do
  kind=$(jq -r '.kind // ""' <<<"$line")
  subj=$(jq -r .subj <<<"$line")
  # свои входы по SSH с ПК администратора не шлём
  [ "$kind" = "ssh-login" ] && [[ "$subj" == *"$ADMIN_IP"* ]] && continue
  key=$(jq -r .key <<<"$line"); now=$(date +%s)
  [ -n "${LAST[$key]}" ] && [ $((now - LAST[$key])) -lt "$DEDUP_SECONDS" ] && continue
  h=$(date +%Y%m%d%H); [ "$h" != "$HOUR" ] && { HOUR=$h; SENT=0; }
  if [ "$SENT" -ge "$MAX_PER_HOUR" ]; then
    logger -t mail-alerts "лимит писем в час, пропущено: $subj"; continue
  fi
  LAST[$key]=$now; SENT=$((SENT + 1))
  jq -r .body <<<"$line" | /usr/local/bin/mail-alert-send "$subj" \
    || logger -t mail-alerts "не удалось отправить: $subj"
done
EOF
chmod 700 /usr/local/bin/mail-alerts

echo "== Ежедневная сводка (/usr/local/bin/mail-summary)"
cat > /usr/local/bin/mail-summary <<'EOF'
#!/bin/bash
# Сводка за сутки. Если письма в 9:00 нет - сломан сам канал оповещений.
since=$(date -d '-24 hours' +%Y-%m-%dT%H:%M)
cd /var/log/suricata
A=$(cat eve.json.1 eve.json 2>/dev/null | grep -F '"event_type":"alert"' |
    nice -n 19 jq -c --arg s "$since" 'select(.timestamp >= $s) |
      {sev: .alert.severity, sig: .alert.signature,
       crit: (((.alert.category // "") | test("Trojan|Command and Control|C2|Exploit Kit|Privilege Gain|Web Application Attack|Executable code|Targeted Malicious"))
              or (((.alert.metadata.signature_severity // [""])[0]) == "Critical"))}')
CRIT=$(grep -c '"crit":true' <<<"$A" || true)
S12=$(grep -cE '"sev":[12],' <<<"$A" || true)
TOP=$(jq -r 'select(.sev <= 2) | .sig' <<<"$A" 2>/dev/null | sort | uniq -c | sort -rn | head -5)
WARN=$(jq -r --arg s "$since" 'select(.level == "warn" and .t >= $s) | "\(.t[0:16]) \(.msg)"' /var/log/sec-events.jsonl 2>/dev/null)
SUR=$(systemctl is-active suricata)
DROP=$(suricatasc -c dump-counters 2>/dev/null | jq -r '.message.capture | if .kernel_packets > 0 then (.kernel_drops * 10000 / .kernel_packets | floor / 100 | tostring) + "%" else "н/д" end')
DISK=$(df -h / | awk 'NR==2{print $5}')
BK=$(ls -t /var/backups/mikrotik/*.rsc 2>/dev/null | head -1)
MTF=$(grep -c 'login failure' /var/log/mikrotik.log 2>/dev/null || true)
REB=$([ -f /var/run/reboot-required ] && echo "да (установлены обновления ядра)" || echo "нет")

STATUS="OK"
[ "$CRIT" -gt 0 ] || [ -n "$WARN" ] || [ "$SUR" != "active" ] && STATUS="ВНИМАНИЕ"

/usr/local/bin/mail-alert-send "Сводка сенсора за сутки: $STATUS" <<TXT
Критических тревог: $CRIT
Тревог уровня 1-2: $S12
Suricata: $SUR, потери пакетов с запуска: $DROP
Диск: $DISK
Последний бэкап MikroTik: ${BK:-нет}
Неудачных входов на MikroTik (журнал за сегодня): $MTF
Нужна перезагрузка Debian: $REB

Предупреждения сервера за сутки:
${WARN:-нет}

Частые тревоги уровня 1-2:
${TOP:-нет}
TXT
EOF
chmod 700 /usr/local/bin/mail-summary

echo "== Службы systemd"
cat > /etc/systemd/system/mail-alerts.service <<'EOF'
[Unit]
Description=Email alerts from Suricata sensor (Yandex)
After=network-online.target suricata.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/mail-alerts
Restart=always
RestartSec=30
Nice=10

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/mail-summary.service <<'EOF'
[Unit]
Description=Daily sensor summary by email

[Service]
Type=oneshot
ExecStart=/usr/local/bin/mail-summary
EOF

cat > /etc/systemd/system/mail-summary.timer <<'EOF'
[Unit]
Description=Daily sensor summary by email

[Timer]
OnCalendar=*-*-* 09:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

cat > /etc/logrotate.d/msmtp <<'EOF'
/var/log/msmtp.log {
  monthly
  rotate 6
  compress
  missingok
  notifempty
}
EOF

systemctl daemon-reload
systemctl enable --now mail-alerts.service mail-summary.timer >/dev/null 2>&1

echo "== Тестовое письмо"
if echo "Если вы читаете это письмо, почтовые оповещения сенсора работают." | /usr/local/bin/mail-alert-send "Тест: оповещения сенсора на почту"; then
  echo "   отправлено, проверьте почту"
else
  echo "   ОШИБКА отправки, смотрите: tail /var/log/msmtp.log"
fi
echo
systemctl is-active mail-alerts.service
systemctl list-timers mail-summary.timer --no-pager | head -2
