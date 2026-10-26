# QUICTun

QUICTun is a WireGuard UDP tunnel with a real QUIC control connection and a separate
session-bound UDP data plane. QUIC authenticates and establishes session secrets;
WireGuard payload packets travel outside the QUIC stream.

## Описание

QUICTun - UDP-туннель для WireGuard с настоящим QUIC-соединением для управления и отдельной
привязанной к сессии плоскостью данных UDP. QUIC обеспечивает аутентификацию и установление
сеансовых секретов, а пакеты WireGuard передаются вне потоков QUIC.

QUIC использует сертификаты TLS для аутентификации и exporter для получения сеансовых секретов.
Идентификаторы соединения и состояние сессии связывают каждый пакет плоскости данных с
соответствующей аутентифицированной сессией.

После установления сессии QUIC пакеты WireGuard инкапсулируются в компактный QUIC-подобный формат UDP и разделяются по сеансам с помощью производных идентификаторов, счетчиков, маскирования и короткой ключевой метки. За криптографическую конфиденциальность и целостность туннелируемой полезной нагрузки по-прежнему отвечает сам WireGuard.

Проект в первую очередь является сетевым экспериментом по разделению аутентифицированного установления сессии QUIC и легкого высокопроизводительного пути данных UDP при сохранении обычной конечной точки WireGuard на каждой стороне.

## Содержание

- [С чего начать](#%D1%81-%D1%87%D0%B5%D0%B3%D0%BE-%D0%BD%D0%B0%D1%87%D0%B0%D1%82%D1%8C)
- [Что делает проект](#%D1%87%D1%82%D0%BE-%D0%B4%D0%B5%D0%BB%D0%B0%D0%B5%D1%82-%D0%BF%D1%80%D0%BE%D0%B5%D0%BA%D1%82)
- [Модель безопасности](#%D0%BC%D0%BE%D0%B4%D0%B5%D0%BB%D1%8C-%D0%B1%D0%B5%D0%B7%D0%BE%D0%BF%D0%B0%D1%81%D0%BD%D0%BE%D1%81%D1%82%D0%B8)
- [Что НЕ делает текущий data plane](#%D1%87%D1%82%D0%BE-%D0%BD%D0%B5-%D0%B4%D0%B5%D0%BB%D0%B0%D0%B5%D1%82-%D1%82%D0%B5%D0%BA%D1%83%D1%89%D0%B8%D0%B9-data-plane)
- [Формат пакета для WireGuard payload](#%D1%84%D0%BE%D1%80%D0%BC%D0%B0%D1%82-%D0%BF%D0%B0%D0%BA%D0%B5%D1%82%D0%B0-%D0%B4%D0%BB%D1%8F-wireguard-payload)
- [Режимы работы](#%D1%80%D0%B5%D0%B6%D0%B8%D0%BC%D1%8B-%D1%80%D0%B0%D0%B1%D0%BE%D1%82%D1%8B)
- [Конфигурация](#%D0%BA%D0%BE%D0%BD%D1%84%D0%B8%D0%B3%D1%83%D1%80%D0%B0%D1%86%D0%B8%D1%8F)
- [systemd](#systemd)
- [Структура проекта](#%D1%81%D1%82%D1%80%D1%83%D0%BA%D1%82%D1%83%D1%80%D0%B0-%D0%BF%D1%80%D0%BE%D0%B5%D0%BA%D1%82%D0%B0)
- [Сборка](#%D1%81%D0%B1%D0%BE%D1%80%D0%BA%D0%B0)
- [Тесты](#%D1%82%D0%B5%D1%81%D1%82%D1%8B)
- [Ограничения текущей реализации](#%D0%BE%D0%B3%D1%80%D0%B0%D0%BD%D0%B8%D1%87%D0%B5%D0%BD%D0%B8%D1%8F-%D1%82%D0%B5%D0%BA%D1%83%D1%89%D0%B5%D0%B9-%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%B0%D1%86%D0%B8%D0%B8)

## С чего начать

Если нужна рабочая конфигурация, переходите к разделам
[Сборка](#%D1%81%D0%B1%D0%BE%D1%80%D0%BA%D0%B0),
[Конфигурация](#%D0%BA%D0%BE%D0%BD%D1%84%D0%B8%D0%B3%D1%83%D1%80%D0%B0%D1%86%D0%B8%D1%8F)
и [Режимы работы](#%D1%80%D0%B5%D0%B6%D0%B8%D0%BC%D1%8B-%D1%80%D0%B0%D0%B1%D0%BE%D1%82%D1%8B).
Перед развёртыванием ознакомьтесь с моделью безопасности и ограничениями
текущей реализации. Подробное описание формата пакетов приведено ниже
в качестве технического справочника.

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

## Модель безопасности

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

## Формат пакета для WireGuard payload

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

## Клиентский режим

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

## Серверный режим

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

## TTL и предварительное обновление

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

## systemd

При ручной настройке systemd можно создать unit-файлы:

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

## Структура проекта

```text
.
|-- CMakeLists.txt
|-- CMakePresets.json
|-- LICENSE
|-- README.md
|-- picoquic
|-- picotls
|-- src
|   |-- QUICTun.c
|   `-- errno_names.c
`-- tests
    |-- integration
    |   |-- Dockerfile
    |   |-- run.sh
    |   `-- test_quictun.py
    |-- load
    |   |-- Dockerfile
    |   |-- run.sh
    |   `-- test_load.py
    `-- unit
        |-- run.sh
        |-- test_core.c
        `-- test_install.py
```

Основные файлы:

| Путь | Назначение |
| --------------------------- | --------------------------------------------------- |
| `src/QUICTun.c` | Основная программа на C. |
| `src/errno_names.c` | Вспомогательный вывод errno names. |
| `picoquic/` | QUIC implementation submodule. |
| `picotls/` | TLS library submodule для picoquic. |
| `tests/integration/test_quictun.py` | Валидация, QUIC/UDP E2E и реальные WireGuard/network namespace тесты. |

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

Установка только самого QUICTun (без picoquic/picotls headers, libraries и demo-программ):

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build -j
sudo cmake --install build
```

В этом примере устанавливается **только** `/usr/bin/QUICTun`. Если использовать
CMake без `-DCMAKE_INSTALL_PREFIX=/usr`, стандартный префикс `/usr/local`
установит бинарник в `/usr/local/bin/QUICTun`.

Без root можно проверить содержимое установки в отдельном каталоге:

```sh
DESTDIR="$(mktemp -d)" cmake --install build
```

`add_subdirectory(picoquic EXCLUDE_FROM_ALL)` оставляет picoquic доступным
для сборки QUICTun, но не включает его собственные install-правила.
Уже ранее установленные файлы picoquic/picotls команда `install` **не удаляет**.

Форматирование исходников теперь явно запускается через `cmake --build build --target quictun-format`
(при наличии clang-format); обычная сборка не изменяет исходные файлы.

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

## Требования

Основные зависимости:

- C compiler с поддержкой GNU11
- CMake
- make
- OpenSSL
- Git
- picoquic submodule
- picotls submodule

## Тесты

Структура тестов повторяет AntiBlock: в `tests/` находятся только
`unit/`, `integration/` и `load/`. В каждом каталоге есть независимый `run.sh`.
Общего тестового runner или Dockerfile в корне `tests/` нет.

```sh
git submodule update --init --recursive

# C unit-тесты локально: GCC Release, Clang Release и Clang ASan/UBSan
./tests/unit/run.sh

# Интеграционные E2E: собственный Dockerfile и три сборки
./tests/integration/run.sh

# Нагрузочные тесты: собственный Dockerfile и три сборки
./tests/load/run.sh

# Только CMake install-contract (без submodules)
./tests/unit/run.sh --install-only

# Сборка Docker без кэша
INTEGRATION_NO_CACHE=1 ./tests/integration/run.sh
LOAD_NO_CACHE=1 ./tests/load/run.sh

# Более интенсивные тесты
QUICTUN_E2E_PACKETS=512 ./tests/integration/run.sh
QUICTUN_STRESS_SCALE=2 ./tests/load/run.sh
QUICTUN_LONG_STRESS_PACKETS=100000 ./tests/load/run.sh
QUICTUN_LONG_STRESS_PACKETS=500000 QUICTUN_LONG_STRESS_PPS=4000 ./tests/load/run.sh
```

Для `unit/` на хосте нужны CMake, GCC, Clang, Python, OpenSSL и зависимости
PicoQUIC/Picotls; Docker не требуется. `tests/unit/test_install.py` отдельно
проверяет `cmake --install` с `DESTDIR` и двумя префиксами на заглушках
зависимостей. При обычном unit-прогоне каждый профиль также проверяет установку
с настоящими submodules: только `/usr/bin/QUICTun`.

Для `integration/` и `load/` на хосте нужны Docker и инициализированные
Git submodules. Каждая папка собирает собственный Arch Linux Docker-образ с
GCC Release, Clang Release и Clang ASan/UBSan, затем запускает тесты в
отдельных одноразовых контейнерах (`docker run --rm`). Если один профиль
провалится, общий результат соответствующего набора будет FAIL.

Integration-тесты требуют `NET_ADMIN`, `NET_RAW`, `SYS_ADMIN` и разрешения на
mount/unshare для WireGuard и network namespaces, а также поддержку WireGuard
в ядре хоста. Load-тесты запускаются без дополнительных Docker capabilities.

При отладке можно передать путь к предварительно собранному бинарнику каждому
`run.sh` как аргумент либо через `QUICTUN_BIN`/`QUICTUN_UNIT_BIN`; в этом режиме
сборка не выполняется.

`tests/integration/test_quictun.py` проверяет ошибочные конфигурации,
QUIC-handshake, сертификаты, CA, peer hash, SNI,
передачу UDP payload и побайтовую проверку пакетов. По умолчанию проверяются
64 пакета разных длин; `QUICTUN_E2E_PACKETS` меняет количество (0-10000).

Дополнительный integration E2E теперь создает внутри одного Docker-контейнера
**три изолированных Linux network namespaces** и соединяет их виртуальным
Ethernet bridge. Сервер QUICTun работает с двумя независимыми клиентами,
используя настоящий WireGuard на каждом конце:

- Отдельные клиентские TLS-сертификаты и whitelist hash для каждого peer.
- Реальные WG interfaces: IPv4 и IPv6 пакеты в обоих направлениях.
- Параллельные запросы через оба туннеля для проверки multi-peer демультиплексирования.
- `iperf3` TCP/UDP через WireGuard с проверкой доставленных данных и статистики потерь.
- Перезапуск одного клиента без остановки второго и переподключение к серверу.
- Перезапуск QUICTun-сервера с проверкой восстановления обоих туннелей.
- Повторный прогон WG IPv4/IPv6 поверх внешней сети QUIC IPv6.
- `tc netem` с задержкой 25 ms и потерями 1% на подлежащем Ethernet.
  По умолчанию сценарий обязателен: отсутствие netem завершает тест ошибкой.
  Чтобы разрешить явный SKIP на хосте без этого qdisc, запустите с
  `QUICTUN_REQUIRE_NETEM=0`.

В этой проверке IP-пакеты **действительно проходят через WireGuard и QUICTun**,
а не через одну loopback-сеть. Для запуска нужны Docker и поддержка WireGuard
в ядре хоста. Санитайзеры охватывают те же сценарии под Clang ASan/UBSan.

`tests/unit/test_core.c` тестирует непосредственно production C-функции:
IPv4/IPv6 адреса, разбор строк конфигурации, маскирование/обратное
преобразование tunnel header, отбрасывание повреждённых заголовков,
ограничения TX-очереди и FIFO/TTL pending-пакетов. Для сборки unit-target
нужен `-DQUICTUN_BUILD_TESTS=ON`; `quictun-unit` не устанавливается.

`tests/load/test_load.py` запускает **настоящий QUICTun client/server с
сертификатами и QUIC handshake**, затем проверяет 4 варианта передачи:

1. Mixed 16/64/512/1200-byte UDP packets (1000 пакетов, 100% доставка).
1. Sustained 1200-byte traffic (3000 пакетов, минимум 99.5% доставка).
1. High-rate burst (4000 пакетов, минимум 98% доставка).
1. Post-idle recovery (500 пакетов после паузы, 100% доставка).

Каждый пакет имеет уникальный sequence number, сверяется побайтово, дубли
и повреждения считаются ошибками. Скрипт выводит отправленные/полученные
пакеты, потери, длительность и фактический packets/s. Минимальные пороги
доставки в нагрузочных режимах учитывают UDP drops в виртуализованном
окружении, но не допускают порчу данных. Это loopback-regression,
**не измерение пропускной способности WireGuard через реальную сеть**.
Переменная `QUICTUN_STRESS_SCALE` (1-10) меняет число отправленных пакетов.

`QUICTUN_LONG_STRESS_PACKETS` (0-500000, default 0) включает дополнительный длительный
stress-прогон. `QUICTUN_LONG_STRESS_PPS` (1-30000, default 4000) регулирует
целевой темп отправки. Отчёт разделяет время отправки и полное время ожидания
доставки. Длительный прогон выполняется во всех трёх профилях компилятора.

При исчерпании UDP TX-очереди QUICTun применяет best-effort семантику:
неотправленные пакеты отбрасываются. Нагрузочный тест фиксирует потерю,
а не гарантирует retransmit на этом уровне. Короткий тег data plane
не обеспечивает AEAD-аутентификацию всей полезной нагрузки.

Артефакты integration/load остаются внутри Docker и удаляются после
тестирования (`docker run --rm`). Локальные unit-сборки сохраняются в
`build/tests/unit/` и исключены из Docker-контекста. Для отладки можно отдельно
запустить тесты непосредственно из дерева исходников с `QUICTUN_BIN`, но это
не стандартный путь запуска.

Loopback E2E проверяет QUIC и UDP непосредственно, тогда как network E2E
проверяет WireGuard поверх виртуальной IPv4/IPv6 сети внутри Docker. Показания
`iperf3` на одном хосте не равны результатам на физической сети.

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
