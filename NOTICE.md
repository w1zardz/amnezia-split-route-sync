# Источники данных

Списки в `dist/` собираются из собственного каталога сервисов
[`data/services/`](data/services) — он составлен вручную для этого проекта.
Чужие списки целиком не копируются и не перелицензируются.

Технические данные, которые запрашиваются во время сборки:

- **Team Cymru IP-to-ASN bulk whois** (`whois.cymru.com`) — сопоставление IP с
  ASN и анонсируемым BGP-префиксом. Используется по назначению сервиса,
  результат кэшируется в `data/prefixes.json`.
- **RIPEstat Data API** (`stat.ripe.net`, announced-prefixes) — список
  префиксов, анонсируемых конкретной AS. Публичный API RIPE NCC.
- **iptoasn.com** (`ip2asn-v4.tsv.gz`) — таблица IP → ASN и страна, производная
  от публичных BGP-анонсов. Отдаётся в Public Domain; используется только как
  справочник при проверке чужих списков, в репозиторий не копируется.
- Публичный DNS — резолв доменов каталога.

## Внешние списки сетей

`tools/import_external.py` читает публичные списки российских сетей как
кандидатов. Источники перечислены в
[`config/external-sources.json`](config/external-sources.json), на момент
написания это:

- [`hxehex/russia-mobile-internet-whitelist`](https://github.com/hxehex/russia-mobile-internet-whitelist) — MIT
- [`escapingworm/russia-whitelist`](https://github.com/escapingworm/russia-whitelist) — MIT
- [`UnRKN/ru-blocklist`](https://github.com/UnRKN/ru-blocklist) — кандидаты доменов с ограничениями VPN
- [`itdoginfo/allow-domains`](https://github.com/itdoginfo/allow-domains) — только `Russia/outside-raw.lst`, ресурсы, доступные из России
- [`lib4u/amnezia-tunneling-ru`](https://github.com/lib4u/amnezia-tunneling-ru) — домены и IPv4 из `amnezia.json`, сборка на основе `v2fly/domain-list-community`

Их файлы в репозиторий не копируются. В `data/external.json` попадает результат
собственной проверки: CIDR внутри диапазонов IP→ASN сервисов каталога и новые
поддомены уже проверенных сервисов. Для каждой записи сохраняется происхождение;
остальные домены перечислены в `data/external-candidates.json` для проверки.
Код и документация внешних проектов не импортируются. Ссылки выше указывают на
оригинальные репозитории и их условия использования.

MIT License в этом репозитории относится к исходному коду, каталогу сервисов и
документации этого проекта.

При составлении каталога учитывался публичный список
[`kozlovartem20201/amnezia-vpn-russia`](https://github.com/kozlovartem20201/amnezia-vpn-russia)
как ориентир по покрытию сервисов. Его файлы в репозиторий не включены; домены
перепроверены, мёртвые и нерелевантные записи отброшены.
