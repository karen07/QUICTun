# QUICTun

QUICTun - это UDP туннель для WireGuard, где QUIC используется как control plane, а WireGuard payload передается в отдельном custom UDP data plane.

QUIC дает:

- handshake
- TLS аутентификацию
- клиентские сертификаты
- exporter-derived secrets
- Connection ID
- привязку data plane к конкретной QUIC сессии

WireGuard payload не передается через QUIC streams. После QUIC handshake он упаковывается в compact QUIC-like UDP packet format и отправляется отдельно.

Важно: WireGuard payload уже зашифрован и аутентифицирован самим WireGuard. QUICTun не добавляет второй полноценный VPN encryption layer поверх каждого payload packet. QUICTun слой сейчас используется для session binding, fast demux, lightweight masking/obfuscation, short keyed tag и привязки пакетов к QUIC соединению.

## Что делает проект

Схема трафика:

```text
[WireGuard client]
      |
      | UDP
      v
[QUICTun client]
      |
      | QUIC handshake + certificate auth + exporter-derived keys
      | WG payload -> compact QUIC-like UDP packet
      v
~~~~~~~~~~~~ Internet / UDP ~~~~~~~~~~~~
      v
[QUICTun server]
      |
      | classify by CID / wire_id / short keyed tag
      | if tunnel data packet -> local WG
      | else -> ordinary QUIC packet
      v
[WireGuard endpoint]
```

Обратное направление работает симметрично.

Ключевая идея:

1. между клиентом и сервером устанавливается настоящее QUIC соединение на базе picoquic;
1. клиент аутентифицируется сертификатом;
1. из QUIC сессии выводятся data-plane keys;
1. WireGuard payload передается в собственном UDP формате, похожем на short QUIC packet;
1. принимающая сторона быстро отличает обычный QUIC control traffic от туннельных data packets;
1. WireGuard payload передается дальше в локальный WireGuard endpoint.

То есть это не "WireGuard поверх QUIC streams", а:

```text
WireGuard payload поверх собственного QUIC-like UDP packet format,
привязанного к QUIC сессии через exporter-derived/session-derived keys,
Connection ID, compact wire id, short keyed tag и packet counter.
```

## Security model

QUICTun не заменяет криптографию WireGuard.

Основная confidentiality и integrity для payload обеспечиваются WireGuard:

- WireGuard шифрует свой payload;
- WireGuard аутентифицирует свой payload;
- QUICTun не должен рассматриваться как независимый VPN encryption layer поверх WireGuard.

QUICTun слой сейчас отвечает за другое:

- QUIC session binding;
- TLS certificate authentication;
- exporter-derived/session-derived data keys;
- compact wire id;
- short keyed tag;
- packet counter;
- lightweight masking/obfuscation;
- fast demux между обычными QUIC packets и tunnel data packets.

Short keyed tag в QUICTun не является полноценной AEAD аутентификацией всего WireGuard payload.

Если нужна независимая криптографическая защита поверх WireGuard payload, надо возвращать полноценный AEAD layer с нормальным nonce management, полноценным tag и четкой security model.

Текущая модель честнее описывается так:

```text
WireGuard отвечает за криптографическую защиту payload.
QUIC отвечает за handshake, TLS auth и session secrets.
QUICTun data plane отвечает за QUIC-like транспорт, masking, short tag,
counter и привязку к QUIC сессии.
```

## Что НЕ делает текущий data plane

Текущий data plane не надо описывать как:

- полноценный AEAD encryption layer поверх каждого пакета;
- ChaCha20-Poly1305 encryption для всего WireGuard payload;
- packet format с nonce 12 bytes и tag 16 bytes;
- независимую криптографическую защиту, равную WireGuard или TLS.

Старое описание вида:

```text
nonce 12 bytes
tag 16 bytes
encrypted metadata block
ChaCha20-Poly1305
```

больше не соответствует текущей lightweight data-plane модели.

## Packet format для WireGuard payload

После установления QUIC сессии WireGuard payload передается в compact QUIC-like UDP packet format.

Концептуально пакет выглядит так:

```text
+------------+---------------+----------------------+----------------------+
| 1 byte     | DCID variable | QUICTun data header  | WireGuard payload    |
+------------+---------------+----------------------+----------------------+
```

Где:

- первый байт делается похожим на QUIC short header;
- дальше идет DCID, связанный с QUIC соединением;
- data header содержит compact tunnel metadata;
- после этого идет WireGuard payload.

Актуальные размеры data-plane элементов в коде:

```text
QT_WIRE_ID_SIZE  = 4
QT_TAG_SIZE      = 4
QT_MASK_SIZE     = 16
QT_DATA_HDR_SIZE = QT_WIRE_ID_SIZE + QT_TAG_SIZE
```

Data header:

```text
+-----------------+----------------+
| wire_id 4 bytes | tag 4 bytes    |
+-----------------+----------------+
```

`wire_id` используется как compact identifier для data-plane классификации.

`tag` - короткий keyed tag для быстрой проверки и отсеивания случайных или неподходящих packets. Это не полноценный 16-byte AEAD tag.

`QT_MASK_SIZE = 16` относится к lightweight masking/derived data механике. Это не надо описывать как `encrypted 16 bytes` AEAD block.

Packet counter хранится в состоянии соединения и используется data-plane логикой отправки.

## Как различаются обычный QUIC и tunnel data packets

Один UDP socket может получать два типа трафика:

- обычные QUIC packets для handshake/control plane;
- QUICTun tunnel data packets с WireGuard payload.

При получении UDP packet программа делает примерно такую классификацию:

1. смотрит QUIC-like header и Connection ID;
1. пытается найти активную session/connection entry;
1. проверяет compact wire id;
1. проверяет short keyed tag;
1. если проверка прошла, packet считается tunnel data packet;
1. WireGuard payload передается в локальный WireGuard endpoint;
1. если packet не распознан как tunnel data, он передается в обычную обработку QUIC.

То есть текущая логика - это не "try decrypt by CID + AEAD", а:

```text
classify by CID / wire_id / short keyed tag,
then demux to tunnel data plane or ordinary QUIC.
```

## Режимы работы

QUICTun работает в одном из двух режимов:

- client mode
- server mode

Одновременно включать оба режима нельзя.

## Client mode

Client mode включается, если в конфиге заданы:

```text
QuicEndpoint
WgListen
```

В этом режиме QUICTun:

1. слушает локальный UDP socket для трафика от WireGuard;
1. для каждого активного WireGuard peer/source создает QUIC client connection к серверу;
1. после готовности QUIC соединения получает data-plane keys;
1. упаковывает WireGuard payload в compact QUIC-like UDP packet format;
1. отправляет packet на сервер.

Пример клиентского конфига:

```ini
[Interface]
QuicEndpoint = 203.0.113.10:443
WgListen = 127.0.0.1:60000
CertsPath = /etc/QUICTun/client1
LogPath = /var/log/QUICTun_log.txt
StatPath = /var/log/QUICTun_stat.txt
SNI = example.com
```

## Server mode

Server mode включается, если в конфиге задан:

```text
QuicListen
```

И есть хотя бы одна секция:

```text
[Peer]
```

В этом режиме QUICTun:

1. слушает входящий QUIC и QUIC-like UDP трафик на одном UDP socket;
1. принимает клиентские QUIC соединения;
1. проверяет клиентский сертификат;
1. сопоставляет клиента с `[Peer]` по `PeerCertSHA256`;
1. привязывает data plane к этому peer;
1. проксирует WireGuard payload в соответствующий `WgEndpoint`.

Пример серверного конфига:

```ini
[Interface]
QuicListen = 0.0.0.0:443
CertsPath = /etc/QUICTun/server
LogPath = /var/log/QUICTun_log.txt
StatPath = /var/log/QUICTun_stat.txt
SNI = example.com

[Peer]
PeerCertSHA256 = 0tJHwf7l4P1nmlAh6WdzYDilaLrrWk0n9S9aI8jX8Hw=
WgEndpoint = 127.0.0.1:60000
```

## Конфигурация

Формат конфига похож на ini:

```ini
[Interface]
Key = Value

[Peer]
Key = Value
```

Поддерживаются комментарии:

```text
# comment
; comment
```

Пробелы по краям ключей и значений обрезаются.

## Ключи Interface

| Ключ | Режим | Значение |
| -------------- | ------------- | ------------------------------------------------------------------------- |
| `QuicListen` | server | Адрес `IP:PORT`, на котором сервер слушает QUIC/UDP. |
| `QuicEndpoint` | client | Адрес `IP:PORT` QUICTun сервера. |
| `WgListen` | client | Локальный UDP `IP:PORT`, который слушает клиент для трафика от WireGuard. |
| `CertsPath` | client/server | Каталог с `cert.pem`, `cert.key`, `ca.pem`. |
| `LogPath` | client/server | Файл runtime логов. |
| `StatPath` | client/server | Файл статистики. |
| `SNI` | client/server | SNI для QUIC/TLS handshake. |

Примеры:

```ini
QuicListen = 0.0.0.0:443
QuicEndpoint = 203.0.113.10:443
WgListen = 127.0.0.1:60000
CertsPath = /etc/QUICTun/client1
LogPath = /var/log/QUICTun_log.txt
StatPath = /var/log/QUICTun_stat.txt
SNI = example.com
```

## Ключи Peer

Секция `[Peer]` используется на сервере.

| Ключ | Значение |
| ---------------- | ------------------------------------------------ |
| `PeerCertSHA256` | Base64 от SHA-256 клиентского сертификата. |
| `WgEndpoint` | Локальный UDP endpoint WireGuard для этого peer. |

Пример:

```ini
[Peer]
PeerCertSHA256 = 0tJHwf7l4P1nmlAh6WdzYDilaLrrWk0n9S9aI8jX8Hw=
WgEndpoint = 127.0.0.1:60000
```

## Аутентификация клиентов

На сервере включена клиентская аутентификация сертификатами.

Логика:

1. клиент предъявляет сертификат;
1. сервер проверяет цепочку до `ca.pem`;
1. у leaf сертификата считается SHA-256;
1. SHA-256 переводится в Base64;
1. сервер ищет этот Base64 в `PeerCertSHA256`;
1. если hash найден, QUIC connection привязывается к соответствующему peer;
1. если hash не найден, handshake отклоняется.

Если сертификат неизвестен, в `LogPath` пишется сообщение вида:

```text
Cert verify failed: unknown cert_hash=<hash>
```

## Основные структуры состояния

### Client entries

На клиенте хранится таблица `connects_client[]`.

Одна запись содержит:

- адрес локального WireGuard peer/source;
- QUIC connection;
- UDP socket к серверу;
- локальный адрес этого UDP socket;
- `remote_dcid`;
- `local_dcid`;
- `data_send_key`;
- `data_recv_key`;
- `data_send_ctr`;
- pending WireGuard packet queue;
- lifecycle flags.

Основные lifecycle flags:

```text
del_mark
timeout_mark
prefetch_mark
used_mark
```

### Server entries

На сервере хранится таблица `connects_server[]`.

Одна запись содержит:

- `peer_id`;
- QUIC connection;
- UDP socket к локальному WireGuard endpoint;
- адрес клиентского QUIC peer;
- `remote_dcid`;
- `local_dcid`;
- `data_send_key`;
- `data_recv_key`;
- `data_send_ctr`;
- lifecycle flags.

## Жизненный цикл соединения

### На клиенте

Когда от локального WireGuard приходит packet:

1. ищется запись по адресу отправителя;
1. если записи нет, создается новая QUIC client connection;
1. первый packet может быть поставлен в pending queue или потерян, пока QUIC connection еще не готова;
1. после готовности QUIC соединения инициализируются data-plane keys;
1. запись начинает передавать WireGuard payload в tunnel data plane.

### На сервере

Когда QUIC connection доходит до рабочего состояния:

1. определяется peer, привязанный к сертификату;
1. создается server connection entry;
1. инициализируются data-plane keys;
1. создается UDP socket к `WgEndpoint`;
1. соединение становится рабочим для data plane.

## TTL и prefetch

На клиенте есть логика обновления соединений по времени жизни.

Параметры:

```text
MAX_CNX_TTL
EARLY_START = 0.9
LATE_START = 1.1
```

Поведение:

- если соединение используется и его возраст превысил `TTL * 0.9`, заранее создается новое соединение для того же peer;
- если возраст превысил `TTL * 1.1`, старое соединение закрывается.

Это нужно, чтобы не ждать полного устаревания старой сессии и заранее подготовить новую.

## Логи и статистика

### stdout

В stdout пишутся:

- баннер версии;
- распечатка конфига;
- выбранный режим;
- fatal errors;
- финальное сообщение завершения.

При запуске через systemd это попадает в journal.

### LogPath

В runtime log пишутся события вроде:

```text
Loop started
Loop finished
Client created
Client prefetch created
Client connected
Client disconnected
Client deleted
Client timeout
Cert matched
Connection bound
Connection closing
Cert verify failed: unknown cert_hash=...
```

### StatPath

Файл статистики периодически перезаписывается и содержит counters по стадиям pipeline:

```text
recvfrom_wg_*
recvfrom_wg_drop_*
recvfrom_wg_drop_encrypt_*
sendto_new_quic_*
recvfrom_new_quic_*
sendto_wg_*
recvfrom_quic_*
quic_in_*
sendto_quic_*
```

## Systemd

Генератор systemd unit файлов создает:

```text
QUICTun-server.service
QUICTun-client1.service
QUICTun-client2.service
```

Серверный unit запускает:

```text
/usr/bin/QUICTun /etc/QUICTun/server.conf
```

Клиентский unit запускает:

```text
/usr/bin/QUICTun /etc/QUICTun/clientN.conf
```

Units зависят от `network-online.target` и могут иметь связи с `wg-quick@...`.

## Генераторы

В каталоге `shs/` лежат вспомогательные shell скрипты.

### certs.sh

Создает CA, серверный сертификат и клиентские сертификаты:

```text
certs/ca/ca.key
certs/ca/ca.pem
certs/server/cert.pem
certs/server/cert.key
certs/server/ca.pem
certs/clientN/cert.pem
certs/clientN/cert.key
certs/clientN/ca.pem
```

CA использует ED25519.

### configs.sh

Создает QUICTun конфиги:

```text
configs/server.conf
configs/client1.conf
configs/client2.conf
```

Серверный конфиг получает `[Peer]` секции. Значение `PeerCertSHA256` берется из клиентских сертификатов.

### wgs.sh

Создает WireGuard конфиги:

```text
wgs/serverN.conf
wgs/clientN.conf
wgs/openwrt-clientN.uci
```

### systemds.sh

Создает systemd unit файлы для сервера и клиентов в каталоге:

```text
systemd/
```

## Структура проекта

```text
.
|-- CMakeLists.txt
|-- CMakePresets.json
|-- LICENSE
|-- README.md
|-- deploy.sh
|-- deploy-all.sh
|-- picoquic
|-- picotls
|-- shs
|   |-- certs.sh
|   |-- configs.sh
|   |-- systemds.sh
|   `-- wgs.sh
|-- src
|   |-- QUICTun.c
|   `-- errno_names.c
|-- test_config_validation.py
`-- test_success_e2e.py
```

Основные файлы:

| Путь | Назначение |
| --------------------------- | --------------------------------------------------- |
| `src/QUICTun.c` | Основная программа на C. |
| `src/errno_names.c` | Вспомогательный вывод errno names. |
| `picoquic/` | QUIC implementation submodule. |
| `picotls/` | TLS library submodule для picoquic. |
| `shs/certs.sh` | Генерация CA, серверного и клиентских сертификатов. |
| `shs/configs.sh` | Генерация QUICTun конфигов. |
| `shs/wgs.sh` | Генерация WireGuard конфигов. |
| `shs/systemds.sh` | Генерация systemd unit файлов. |
| `deploy.sh` | Deploy и тестовый запуск на стенде. |
| `deploy-all.sh` | Обертка для запуска полного deploy сценария. |
| `test_config_validation.py` | Тесты валидации конфигов. |
| `test_success_e2e.py` | E2E тест успешного сценария. |

## Сборка

Клонируйте репозиторий с submodules:

```sh
git clone --recurse-submodules https://github.com/karen07/QUICTun.git
cd QUICTun
```

Если репозиторий уже был склонирован без submodules:

```sh
git submodule update --init --recursive
```

Обычная release сборка:

```sh
cmake --preset release
cmake --build --preset release
```

Или без preset:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Для deploy/test может использоваться сборка с `-DDEPLOY`.

Иногда в тестовом сценарии также подставляется:

```text
-DMAX_CNX_TTL=<value>
-DDEPLOY
```

Установка:

```sh
sudo cmake --install build
```

По умолчанию install target ставит бинарник в:

```text
/usr/bin
```

## CMake presets

В проекте есть presets:

```text
debug
debug-asan
debug-msan
release
```

Примеры:

```sh
cmake --preset debug
cmake --build --preset debug

cmake --preset debug-asan
cmake --build --preset debug-asan

cmake --preset release
cmake --build --preset release
```

## Зависимости

Основные зависимости:

- C compiler с поддержкой GNU11
- CMake
- make
- OpenSSL
- Git
- picoquic submodule
- picotls submodule

Для генераторов, deploy и тестового стенда также могут понадобиться:

- openssl
- wireguard-tools
- wg
- wg-quick
- ssh
- scp
- jq
- iperf3
- systemctl
- python3

## Deploy и тестовый стенд

`deploy.sh` предназначен для controlled deployment и тестового стенда с несколькими VM.

Он может:

1. собрать бинарник `QUICTun`;
1. скопировать его на хосты в `/usr/bin/QUICTun`;
1. скопировать QUICTun конфиги и сертификаты в `/etc/QUICTun/`;
1. скопировать WireGuard конфиги в `/etc/wireguard/`;
1. скопировать systemd unit файлы в `/etc/systemd/system/`;
1. выполнить `systemctl daemon-reload`;
1. запустить QUICTun через systemd;
1. поднять WireGuard через зависимости `wg-quick@...`.

В тестовом режиме deploy script может:

- поднимать iperf3 server/client;
- мерить upload/download;
- делать restart сервера или клиентов;
- собирать `journalctl`, `LogPath` и `StatPath`.

## Тесты

В репозитории есть Python тесты:

```text
test_config_validation.py
test_success_e2e.py
```

Запуск:

```sh
python3 test_config_validation.py
python3 test_success_e2e.py
```

E2E тесты могут требовать подготовленный стенд, сетевые namespace, VM или доступ к хостам, в зависимости от текущей конфигурации тестового окружения.

## Ограничения текущей реализации

- Максимум активных peer/connection entries ограничен `MAX_PEERS_COUNT`.
- Таблицы соединений реализованы как фиксированные массивы.
- Поиск по таблицам линейный.
- Для нового peer первый WireGuard packet может быть потерян, пока QUIC connection еще не готова.
- Prefetch может создать короткий период, когда для одного peer существуют две записи.
- Runtime log и statistics пишутся в файлы.
- Собственный packet format проекта не является стандартным QUIC DATAGRAM API.
- Short keyed tag в data plane короткий и не должен рассматриваться как полноценный AEAD tag.
- QUICTun masking/obfuscation не заменяет WireGuard cryptography.
- Если нужна самостоятельная защита payload поверх WireGuard, нужен отдельный полноценный AEAD design.

## Для чего этот проект

QUICTun подходит для экспериментов и controlled deployment, когда нужно:

- использовать QUIC handshake и TLS certificate authentication;
- привязать UDP data plane к QUIC сессии;
- передавать WireGuard payload без QUIC streams;
- маскировать WireGuard трафик под QUIC-like UDP;
- авторизовать клиентов по whitelist сертификатов;
- быстро demux делать между QUIC control plane и tunnel data plane;
- тестировать restart, TTL и prefetch поведение;
- разворачивать multi-peer стенд с systemd и WireGuard.

## Не цели проекта

Проект не пытается:

- заменить WireGuard;
- быть универсальным VPN клиентом;
- реализовать стандартный QUIC DATAGRAM transport;
- дать второе полноценное шифрование поверх WireGuard payload;
- скрыть все сетевые признаки трафика;
- автоматически настраивать firewall и routing policy;
- быть production ready решением без аудита и дополнительных проверок.

## Коротко

```sh
git clone --recurse-submodules https://github.com/karen07/QUICTun.git
cd QUICTun
cmake --preset release
cmake --build --preset release
```

QUICTun - это специализированный UDP туннель для WireGuard, где:

- QUIC дает handshake, TLS аутентификацию, сертификаты, exporter-derived/session-derived secrets и session binding;
- WireGuard payload передается не через QUIC streams, а в собственном compact QUIC-like UDP data plane;
- payload уже защищен WireGuard;
- QUICTun data plane добавляет lightweight masking/obfuscation, compact wire id, short keyed tag, packet counter и fast demux;
- README не должен описывать текущий data plane как ChaCha20-Poly1305 AEAD layer с 12-byte nonce и 16-byte tag.

## Лицензия

Проект распространяется под лицензией GNU Affero General Public License v3.0. Подробности смотрите в файле LICENSE.
