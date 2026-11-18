# RouterOS 7: отправка журналов на сервер и учётка для бэкапа
# Сервер (сенсор) - 10.0.0.5, роутер - 10.0.0.1. Адреса условные.

# --- Удалённый журнал (rsyslog на сервере, см. linux/rsyslog)
# Одно сообщение может иметь несколько тем (например system,error,critical).
# Исключения (!error, !warning) не дают отправить его на сервер несколько раз.
/system logging action
add name=remote-srv target=remote remote=10.0.0.5 remote-port=514 src-address=10.0.0.1
/system logging
add topics=error action=remote-srv
add topics=warning,!error action=remote-srv
add topics=account,!error,!warning action=remote-srv
add topics=system,info,!account action=remote-srv
# Проверка: :log warning "TEST syslog"  ->  tail /var/log/mikrotik.log на сервере

# --- Учётка только для чтения, вход по ключу и только с адреса сервера
# read + sensitive достаточно для /export show-sensitive; записи нет.
/user group
add name=backup policy=ssh,read,sensitive comment="только чтение, бэкап"
/user
add name=backup group=backup address=10.0.0.5/32 comment="бэкап на сервер"
/user ssh-keys
add user=backup key="ssh-ed25519 AAAA...ВАШ_ПУБЛИЧНЫЙ_КЛЮЧ mikrotik-backup"
# Когда у пользователя есть ключ, вход по паролю для него запрещён (password-authentication=yes-if-no-key).

# SSH на роутере - только для сервера
/ip service
set ssh disabled=no available-from=10.0.0.5/32
