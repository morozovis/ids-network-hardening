#!/bin/bash
# Аудит событий за 7 дней на сенсоре Suricata. Только чтение.
cd /var/log/suricata

echo "===== 1. События сервера (sec-events) по типам"
zcat -f /var/log/sec-events.jsonl* 2>/dev/null | jq -r '"\(.kind) \(.level)"' | sort | uniq -c | sort -rn
echo "----- предупреждения (последние 30)"
zcat -f /var/log/sec-events.jsonl* 2>/dev/null | jq -r 'select(.level=="warn") | "\(.t[0:16]) [\(.kind)] \(.msg)"' | sort | tail -30

echo
echo "===== 2. Критические тревоги Suricata за 7 дней (кол-во, день, sid, сигнатура, откуда -> куда)"
for f in $(ls -tr eve.json*); do zcat -f "$f"; done | grep -F '"event_type":"alert"' > /tmp/alerts7d.json
nice -n 19 jq -r 'select((.alert.category | test("Trojan|Command and Control|C2|Exploit Kit|Privilege Gain|Web Application Attack|Executable code|Targeted Malicious")) or ((.alert.metadata.signature_severity // [""])[0] == "Critical")) | "\(.timestamp[0:10]) \(.alert.signature_id) \(.alert.signature) | \(.src_ip) -> \(.dest_ip):\(.dest_port)"' /tmp/alerts7d.json | sort | uniq -c | tail -40
echo "----- топ-15 сигнатур уровня 1"
nice -n 19 jq -r 'select(.alert.severity==1) | "\(.alert.signature_id) \(.alert.signature)"' /tmp/alerts7d.json | sort | uniq -c | sort -rn | head -15
rm -f /tmp/alerts7d.json

echo
echo "===== 3. MikroTik: успешные входы (пользователь, откуда, как)"
zgrep -h 'logged in' /var/log/mikrotik.log* 2>/dev/null | sed -E 's/.*user ([^ ]+) logged in from ([^ ]+) via ([^ ]+).*/\1 \2 \3/' | sort | uniq -c | sort -rn
echo "----- неудачные входы"
zgrep -h 'login failure' /var/log/mikrotik.log* 2>/dev/null | sed -E 's/.*for user ([^ ]+) from ([^ ]+) via ([^ ]+).*/\1 \2 \3/' | sort | uniq -c | sort -rn | head -10
echo "----- ошибки и критические (кроме неудачных входов), последние 15"
zgrep -hE 'error|critical' /var/log/mikrotik.log* 2>/dev/null | grep -v 'login failure' | sort | tail -15

echo
echo "===== 4. Suricata и сервер"
systemctl is-active suricata evebox fail2ban rsyslog unattended-upgrades
systemctl show suricata -p ActiveEnterTimestamp
suricatasc -c dump-counters 2>/dev/null | jq -c '.message.capture'
uptime
df -h / | tail -1
free -m | grep -E 'Mem|Swap'
ls /var/run/reboot-required 2>/dev/null && echo "НУЖНА ПЕРЕЗАГРУЗКА"

echo
echo "===== 5. Debian: входы по SSH за 7 дней"
journalctl -u ssh --since "7 days ago" --no-pager 2>/dev/null | grep -oE '(Accepted|Failed) [a-z-]+ for [^ ]+ from [^ ]+' | sort | uniq -c | sort -rn
fail2ban-client status sshd 2>/dev/null | tail -3
