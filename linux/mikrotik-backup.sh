#!/bin/sh
# Еженедельный экспорт конфигурации MikroTik на сервер.
# Установка: /usr/local/bin/mikrotik-backup (chmod 700), запуск по systemd-таймеру.
#
# На MikroTik нужна учётка только для чтения с входом по ключу (см. mikrotik/logging-and-backup-user.rsc).
# Файлы содержат ключи WireGuard и пароли PPP/Wi-Fi, поэтому каталог и файлы доступны только root.
#
# Важно: ssh -n. Без него при запуске из терминала ssh, запущенный через timeout
# (отдельная группа процессов), пытается читать терминал, получает SIGTTIN и зависает,
# не реагируя на Ctrl+C. Из systemd проблема не проявляется, но -n нужен всё равно.

ROUTER=10.0.0.1
D=/var/backups/mikrotik
F=$D/router-$(date +%F).rsc
O="-i /root/.ssh/mikrotik_backup -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=20 -o StrictHostKeyChecking=accept-new"

mkdir -p $D; chmod 700 $D
timeout 300 ssh -n $O backup@$ROUTER "/export show-sensitive" 2>/dev/null | tr -d '\r' > $F.tmp

# Сохраняем, только если пришла настоящая конфигурация, а не текст ошибки
if grep -q '^/interface' $F.tmp; then
  mv $F.tmp $F; chmod 600 $F
  find $D -name 'router-*.rsc' -mtime +180 -delete
else
  rm -f $F.tmp
  # Событие подхватывает поток оповещений и показывает на ПК администратора
  printf '{"kind":"backup","level":"warn","msg":"Не удалось сделать бэкап MikroTik","t":"%s"}\n' "$(date -Is)" >> /var/log/sec-events.jsonl
  exit 1
fi
