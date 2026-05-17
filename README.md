# Researcher

`Researcher` - CLI-инструмент для первичного DFIR-разбора Linux-сервера по readonly-бэкапу или readonly-смонтированному диску. Он проходит по логам внутри смонтированной системы, достает IP-адреса и события, выделяет подозрительные запросы, считает статистику по атакующим и складывает результат в понятные отчеты.

Инструмент не изменяет смонтированную систему. Он только читает файлы из `--root` и пишет отчеты в отдельную папку `--out`.

## Для Чего Это Нужно

Типовой сценарий:

1. Есть образ или бэкап сервера, где мог находиться злоумышленник.
2. Бэкап монтируется в readonly-режиме, например через `guestmount`.
3. Нужно быстро понять:
   - какие IP встречались в логах;
   - кто чаще всего стучался в nginx/apache;
   - были ли SSH brute force попытки;
   - были ли успешные SSH-входы;
   - какие URL выглядели подозрительно;
   - какие логи реально были прочитаны;
   - где лежат raw-доказательства: файл, строка, исходный фрагмент лога.

`Researcher` не заменяет полноценную форензику, но дает быструю первичную выжимку, с которой удобно начинать расследование.

## Установка

Рекомендуемый вариант на Arch/Linux - через `pipx`:

```bash
sudo pacman -S python python-pipx
pipx install .
```

Если ты работаешь прямо из локальной папки проекта и хочешь, чтобы изменения подхватывались сразу:

```bash
pipx uninstall researcher
pipx install --editable .
```

Проверка:

```bash
researcher-scan --help
which researcher-scan
```

Альтернатива через обычный venv:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
researcher-scan --help
```

## Readonly-Монтирование

Пример через `guestmount`:

```bash
sudo mkdir -p /mnt/vm
sudo guestmount -a server-disk.img -i --ro /mnt/vm
```

Если обычный пользователь не может читать mountpoint, можно монтировать с `allow_other`, если это разрешено в конфигурации FUSE:

```bash
sudo guestmount -a server-disk.img -i --ro -o allow_other /mnt/vm
```

Важно: в `--root` нужно передавать именно корень смонтированной Linux-системы. Внутри должны быть похожие директории:

```text
/mnt/vm/bin
/mnt/vm/etc
/mnt/vm/usr
/mnt/vm/var
/mnt/vm/var/log
```

Проверка перед запуском:

```bash
ls -la /mnt/vm
ls -la /mnt/vm/var/log
```

Если путь находится в домашней директории, можно использовать `~`:

```bash
researcher-scan --root ~/backups/vm --out ./report
```

CLI сам разворачивает `~` в домашнюю директорию.

## Быстрый Запуск

```bash
researcher-scan --root /mnt/vm --out ./report
```

После завершения смотри сначала:

```bash
less ./report/scanned_files.txt
less ./report/attackers.txt
```

Если хочешь учитывать только глобально маршрутизируемые публичные IP:

```bash
researcher-scan --root /mnt/vm --out ./report --public-only
```

По умолчанию учитываются все IP, включая private/local/reserved. Это сделано специально: в реальных инцидентах в логах часто видны IP reverse proxy, VPN, NAT, Docker-сетей или внутренних балансировщиков.

## Авто-Sudo При Нехватке Прав

Если mountpoint можно читать только под root, инструмент попробует перезапуститься через `sudo`:

```bash
researcher-scan --root /mnt/vm --out ./report
```

Пример поведения:

```text
Root permissions are required to read this mount. Re-running with sudo...
[sudo] password for user:
```

После ввода пароля скан продолжится. Если `sudo` не подходит, можно сразу запускать явно:

```bash
sudo env PATH="$PATH" researcher-scan --root /mnt/vm --out /home/user/report
```

Лучше указывать `--out` в директорию пользователя, чтобы потом не получать root-owned отчеты в неудобном месте.

## Какие Логи Читаются

Сканер в первую очередь ищет логи внутри:

```text
<root>/var/log
```

Если `/var/log` внутри `--root` не найден, он пробует сканировать сам `--root`.

Поддерживаются обычные, ротированные и сжатые логи:

```text
access.log
access.log.1
access.log.2.gz
access.log.3.zst
error.log
error.log.1.gz
auth.log
auth.log.1
secure
syslog
messages
audit.log
ufw.log
cron
```

Поддерживаемые сжатия:

```text
.gz
.bz2
.xz
.zst
```

Также сканируются nginx/apache/httpd-похожие пути:

```text
/var/log/nginx/access.log
/var/log/nginx/access.log.1
/var/log/nginx/access.log.2.gz
/var/log/nginx/access.log.3.zst
/var/log/apache2/access.log
/var/log/httpd/access_log
```

Если внутри Ubuntu есть systemd journal:

```text
/var/log/journal
```

то инструмент попробует прочитать его через `journalctl --directory`, если `journalctl` доступен на машине, где запускается сканер.

## Что Извлекается

Сейчас инструмент извлекает:

- IP-адреса из логов;
- nginx/apache access events;
- HTTP method, URL, status code, user-agent;
- подозрительные web-запросы;
- SSH failed login;
- SSH successful login;
- пользователей из успешных SSH-входов;
- sudo-контекст, если рядом есть IP;
- referrer и user-agent из web-логов;
- raw-строку лога как evidence;
- аккаунты из `/etc/passwd`;
- metadata `/etc/shadow`;
- sudoers rules;
- SSH `authorized_keys`;
- cron/systemd persistence;
- shell history;
- подозрительные команды `wget`, `curl`, `base64`, `chmod +x`, reverse-shell-like patterns;
- webshell-похожие файлы в `/var/www`;
- недавно измененные файлы в `/etc`, `/var/www`, `/tmp`, `/dev/shm`, `/usr/local/bin`;
- hints на secrets, dumps и архивы;
- IOC: IP, URL, домены, user-agent, referrer, hashes, emails.

Для каждого события сохраняется:

- IP;
- тип события;
- категория;
- timestamp, если его удалось извлечь;
- исходный файл;
- номер строки;
- URL/status/user/referrer/user-agent, если применимо;
- исходная raw-строка.

## Подозрительные Web-Запросы

Запрос помечается как suspicious, если URL содержит типичные признаки сканирования или эксплуатации:

```text
/.env
/.git
wp-login.php
xmlrpc.php
phpmyadmin
adminer
../
%2e%2e
cmd=
exec=
shell
webshell
/etc/
passwd
base64
union select
<script
```

Это эвристика. Она не доказывает компрометацию, но помогает быстро поднять наверх шумные и потенциально опасные запросы.

## Отчеты

После запуска в `--out` создаются файлы:

```text
report/
  report.md
  summary.txt
  attackers.txt
  scanned_files.txt
  timeline.csv
  timeline.txt
  events.csv
  artifacts.csv
  summary.json
  indicators/
    risk_scores.csv
    successful_logins_after_bruteforce.txt
  iocs/
    ips.txt
    urls.txt
    domains.txt
    user_agents.txt
    referrers.txt
    hashes.txt
    emails.txt
  accounts/
    accounts.csv
    accounts.txt
  persistence/
    persistence.csv
    persistence.txt
  commands/
    commands.csv
    commands.txt
    downloaded_payloads.txt
  web_compromise/
    web_compromise.csv
    web_compromise.txt
  filesystem/
    filesystem.csv
    filesystem.txt
  secrets/
    secrets.csv
    secrets.txt
  archives/
    archives.csv
    archives.txt
  network/
    network_artifacts.txt
  events/
    web.csv
    auth.csv
    security.csv
    system.csv
    other.csv
    by-source/
      var_log_nginx_access.log.csv
      var_log_auth.log.csv
```

### `report.md`

Главный человекочитаемый Markdown-отчет. Его удобно открыть в GitHub, VS Code, Obsidian или сконвертировать в PDF.

Внутри:

- executive summary;
- топ подозрительных IP;
- risk level и risk score;
- successful login after brute force;
- important artifact findings;
- suspicious web requests;
- ссылки на детальные файлы отчета;
- suggested manual checks.

### `summary.txt`

Короткая executive summary. Ее удобно читать первой после `scanned_files.txt`.

Внутри:

- общее число событий и IP;
- количество high/medium artifact findings;
- число successful login событий;
- число suspicious web requests;
- brute-force-then-success кандидаты;
- топ-10 подозрительных IP;
- самые важные artifact findings.

### `attackers.txt`

Главный человекочитаемый отчет. IP отсортированы по attack score и активности.

Для каждого IP показывается:

- attack score;
- общее количество событий;
- количество web-запросов;
- количество suspicious web-запросов;
- failed SSH logins;
- successful SSH logins;
- другие появления IP;
- топ HTTP status codes;
- топ URL;
- пользователи;
- user-agent и referrer;
- источники логов.

### `scanned_files.txt`

Инвентарь просканированных файлов. Его стоит открыть первым, если кажется, что инструмент ничего не нашел.

Там видно:

- сколько файлов прочитано;
- сколько событий извлечено;
- какие категории событий найдены;
- какие конкретно файлы были обработаны;
- сколько событий было найдено в каждом файле;
- какие источники были пропущены и почему.

Пример:

```text
Files:
  var/log/nginx/access.log - events: 1204
  var/log/nginx/access.log.1.gz - events: 982
  var/log/auth.log - events: 31
```

### `events.csv`

Полная таблица всех событий. Удобно открывать в LibreOffice, Excel, pandas или grep/awk.

Колонки:

```text
ip
kind
timestamp
source
category
line_number
method
url
status
user
referrer
user_agent
raw
```

### `events/`

Разделенные отчеты, чтобы не было мешанины:

- `events/web.csv` - web access/error события;
- `events/auth.csv` - SSH/auth/sudo события;
- `events/security.csv` - firewall/audit/ufw/fail2ban;
- `events/system.csv` - syslog/messages/cron/system;
- `events/other.csv` - все, что не попало в категории;
- `events/by-source/*.csv` - отдельный CSV на каждый исходный лог.

### `summary.json`

Машиночитаемый отчет для дальнейшей автоматизации. Подходит для скриптов, CI, импорта в другие системы или последующей генерации HTML.

### `timeline.csv` и `timeline.txt`

Единая временная шкала по логовым событиям и файловым артефактам. В timeline попадают:

- SSH failed/successful login;
- sudo/auth события;
- web-запросы;
- подозрительные web-запросы;
- cron/systemd/startup findings;
- shell history findings;
- webshell/secret/archive/recent-file findings.

### `indicators/`

Отчеты по признакам компрометации и risk scoring:

- `risk_scores.csv` - IP, risk level, risk score и основные счетчики;
- `successful_logins_after_bruteforce.txt` - IP, у которых есть и failed login, и successful login.

### `iocs/`

Чистые списки индикаторов:

- `ips.txt`;
- `urls.txt`;
- `domains.txt`;
- `user_agents.txt`;
- `referrers.txt`;
- `hashes.txt`;
- `emails.txt`.

### `accounts/`

Аккаунты и доступы:

- пользователи из `/etc/passwd`;
- UID 0 non-root пользователи помечаются high;
- interactive shell у пользователя помечается medium;
- metadata `/etc/shadow`;
- sudoers entries;
- SSH `authorized_keys`.

### `persistence/`

Закрепление:

- `/etc/crontab`;
- `/etc/cron.*`;
- `/var/spool/cron`;
- systemd services/timers/sockets/paths в `/etc/systemd/system`;
- `/etc/rc.local`;
- `/etc/profile`, `/etc/bash.bashrc`, `/etc/profile.d/*`.

### `commands/`

Команды и payload hints:

- shell history из `/root` и `/home/*`;
- `wget`, `curl`, `base64 -d`, `chmod +x`, `nc`, `socat`, `/dev/tcp` и похожие паттерны;
- отдельный `downloaded_payloads.txt` с наиболее интересными строками.

### `web_compromise/`

Web compromise triage:

- PHP/JS/JSP/ASP-похожие web-файлы;
- upload-area files;
- webshell-похожие строки: `eval`, `system`, `shell_exec`, `passthru`, `base64_decode`, `$_POST`, `$_GET`.

### `filesystem/`, `secrets/`, `archives/`

Filesystem triage:

- недавно измененные файлы в важных директориях;
- executable-файлы в `/tmp`, `/dev/shm`, `/usr/local/bin`;
- `.env`, token/password/key hints;
- `.sql`, `.dump`, `.zip`, `.tar.gz`, `.bak`, backup/archive files.

## Attack Score И Risk Score

Сейчас рейтинг считается так:

```text
web_requests + failed_logins + suspicious_web_requests*5 + successful_logins*3
```

Для `indicators/risk_scores.csv` дополнительно считается risk score:

```text
total_events + failed_logins*2 + suspicious_web_requests*8 + successful_logins*12 + brute_force_then_success_bonus
```

Risk level:

- `critical` - IP сначала brute-force'ит, потом успешно логинится;
- `high` - высокий score или есть successful login;
- `medium` - suspicious web или заметная активность;
- `low` - слабый сигнал.

Идея простая:

- обычный web-запрос дает небольшой вес;
- failed SSH login важен;
- suspicious web request важнее обычного запроса;
- successful SSH login особенно важен, потому что может указывать на реальный доступ.

Это не “истина”, а сортировка для triage. IP сверху нужно проверять первыми.

## Как Читать Результат

Практический порядок:

1. Открой `scanned_files.txt` и убедись, что нужные логи реально прочитались.
2. Открой `report.md` для человекочитаемой общей картины.
3. Открой `summary.txt`, если нужен короткий plain-text вариант.
4. Открой `indicators/risk_scores.csv` и `attackers.txt`.
5. Проверь `indicators/successful_logins_after_bruteforce.txt`.
6. Для подозрительного IP найди его в `events.csv`.
7. Посмотри `source` и `line_number`, чтобы перейти к исходному логу.
8. Проверь `timeline.csv`, чтобы увидеть порядок событий.
9. Проверь `accounts/`, `persistence/`, `commands/`, `web_compromise/`.
10. Забери IOC из `iocs/` для блокировок или дальнейшего поиска.

Примеры:

```bash
grep "1.2.3.4" report/events.csv
grep "successful_login" report/events.csv
grep "suspicious_web_request" report/events/web.csv
grep "critical" report/indicators/risk_scores.csv
```

## Частые Проблемы

### `--root does not exist`

Проверь, что путь указывает именно на mountpoint:

```bash
ls -la /mnt/vm
ls -la /mnt/vm/var/log
```

Если используешь `~`, обнови инструмент до свежей версии: CLI разворачивает `~` автоматически.

### `permission denied`

Mountpoint может быть доступен только root. Используй обычный запуск, инструмент попробует sudo сам:

```bash
researcher-scan --root /mnt/vm --out ./report
```

Или явно:

```bash
sudo env PATH="$PATH" researcher-scan --root /mnt/vm --out /home/user/report
```

### `scanned_files.txt` пустой или почти пустой

Проверь, что внутри `--root` есть `var/log`:

```bash
ls -la /mnt/vm/var/log
```

Если ты передал путь до папки, где лежит образ, а не до смонтированной файловой системы, инструмент не найдет Linux-логи.

### Нашел мало IP

Попробуй без `--public-only`. По умолчанию инструмент уже включает все IP. Если был старый релиз, переустанови:

```bash
pipx uninstall researcher
pipx install --editable .
```

### На Ubuntu нет `auth.log`

В новых системах часть событий может быть только в journal:

```bash
ls -la /mnt/vm/var/log/journal
```

Если `journalctl` есть на хосте, инструмент попробует прочитать journal автоматически.

## Разработка

Запуск из исходников:

```bash
python -m researcher --root /mnt/vm --out ./report
```

Тесты:

```bash
python -m unittest discover -s tests
```

Проверка компиляции:

```bash
python -m compileall researcher
```

Сборка пакета:

```bash
python -m pip install --upgrade build
python -m build
```

## Релизы

GitHub Actions workflow запускается на push тегов вида `v*`:

```bash
git tag -a v0.1.1 -m "Release v0.1.1"
git push origin v0.1.1
```

Версия пакета берется из Git-тега через `setuptools_scm`. Для тега `v0.1.1` должны собираться файлы:

```text
researcher-0.1.1.tar.gz
researcher-0.1.1-py3-none-any.whl
```

## Что Можно Добавить Дальше

Основные triage-отчеты уже есть. Следующие полезные улучшения:

- HTML-отчет;
- YARA-поиск по `/var/www`, `/tmp`, `/dev/shm`;
- SQLite-база для больших расследований;
- более точный парсинг auditd;
- группировка событий в incident chains;
- сравнение с known-good baseline;
- экспорт в STIX/OpenIOC.
