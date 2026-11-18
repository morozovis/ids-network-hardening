# RouterOS 7: защита проброшенного RDP
# Адреса условные. Перед применением: Safe Mode (Ctrl+X) и /export file=before.
#
# Схема:
#   1) RDP снаружи доступен только адресам из rdp-whitelist;
#   2) если адрес всё же дошёл (например, порт временно открыт для всех) - поэтапный автобан:
#      4 новых соединения за ~3 минуты -> blacklist;
#   3) blacklist отбрасывается в raw, до conntrack - атакующий не тратит ресурсы роутера.

# --- 1. Белый список
/ip firewall address-list
add list=rdp-whitelist address=203.0.113.10 comment="филиал 1"
add list=rdp-whitelist address=198.51.100.20 comment="филиал 2"

# --- 2. Проброс только для белого списка (внешний порт нестандартный)
/ip firewall nat
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=4242 \
    src-address-list=rdp-whitelist to-addresses=10.0.0.101 to-ports=3389 comment="RDS"

# --- 3. Сброс забаненных в raw
/ip firewall raw
add chain=prerouting action=drop in-interface-list=WAN src-address-list=blacklist comment="drop blacklist"

# --- 4. Поэтапный автобан в forward (после dst-nat порт уже 3389).
# ПОРЯДОК ВАЖЕН: бан должен стоять ПЕРВЫМ, "-> stage1" - последним.
# Адрес попадает в список сразу, поэтому при обратном порядке одно соединение
# проходит все ступени за один проход и банится с первой попытки.
# Если добавлять правила с place-before=0, они встанут в обратном порядке - проверяйте print.
/ip firewall filter
add chain=forward action=add-src-to-address-list connection-state=new connection-nat-state=dstnat \
    protocol=tcp dst-port=3389 src-address-list=rdp-stage3 \
    address-list=blacklist address-list-timeout=1d comment="RDP-BF 1: stage3 -> ban"
add chain=forward action=add-src-to-address-list connection-state=new connection-nat-state=dstnat \
    protocol=tcp dst-port=3389 src-address-list=rdp-stage2 \
    address-list=rdp-stage3 address-list-timeout=1m comment="RDP-BF 2: stage2 -> stage3"
add chain=forward action=add-src-to-address-list connection-state=new connection-nat-state=dstnat \
    protocol=tcp dst-port=3389 src-address-list=rdp-stage1 \
    address-list=rdp-stage2 address-list-timeout=1m comment="RDP-BF 3: stage1 -> stage2"
add chain=forward action=add-src-to-address-list connection-state=new connection-nat-state=dstnat \
    protocol=tcp dst-port=3389 src-address-list=!rdp-whitelist \
    address-list=rdp-stage1 address-list-timeout=1m comment="RDP-BF 4: -> stage1"

# Проверка порядка: сверху вниз должно быть RDP-BF 1, 2, 3, 4
# /ip firewall filter print where comment~"RDP-BF"
#
# Урок из практики: аналогичные правила для input без ограничения in-interface-list=WAN
# забанили 89 внутренних адресов, и у телефонов в Wi-Fi пропал DNS.
# Автобан - только на WAN.
