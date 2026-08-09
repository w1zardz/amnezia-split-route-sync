# AmneziaVPN / AmneziaWG Split Tunneling — RU Direct Route Sync

Автоматический **RU Direct split tunneling для AmneziaVPN и протокола
AmneziaWG**: безопасное обновление IPv4-маршрутов российских сервисов на macOS
и Windows, плюс генератор `ip-list.json` для iOS, Android и Linux. Yandex, Ozon,
VK, Wildberries, банки и платёжные сервисы из списка идут напрямую, а остальной
трафик продолжает идти через VPN.

**English:** automatic Russian direct-routing exceptions for AmneziaVPN split
tunneling. Safe route sync on macOS and Windows; portable Amnezia `ip-list.json`
generation for iOS, Android and Linux.

Проект не содержит VPN-конфигураций, адресов серверов, ключей, паролей, UUID,
доменов владельца или готовых подключений. IP вашего VPN-сервера хранится только
в исключённом из Git `config/custom-host-policy.json` и его приватной установленной
копии в каталоге текущего пользователя. На macOS копия получает mode `600`, на
Windows наследует ACL пользовательского профиля; в репозиторий они не отправляются.

## Что поддерживается

| Платформа | Режим |
|---|---|
| macOS + AmneziaVPN 5.x + AmneziaWG | Автоматически при входе и каждые 6 часов |
| Windows 10/11 + AmneziaVPN 5.x | Автоматически через Task Scheduler каждые 6 часов |
| iOS / Android / Linux | Генерация `ip-list.json` на компьютере и ручной импорт |

AmneziaVPN работает с IPv4-маршрутами; IPv6 этот проект не настраивает. В
Amnezia Free раздельное туннелирование по IP может быть недоступно. Актуальную
матрицу возможностей смотрите в
[официальной документации Amnezia](https://docs.amnezia.org/ru/documentation/instructions/vpn-split-tunneling/).

## Как это устроено

1. Скрипт скачивает семь публичных списков: Yandex, Ozon, VK, Wildberries,
   банки, платёжные сервисы и российские CDN.
2. Каждый новый CIDR должен лежать внутри проверенной границы из
   `config/route-policy.json`.
3. Слишком широкие сети, неожиданный рост списка и сеть, содержащая IP вашего
   VPN-сервера, отклоняются до изменения настроек.
4. Ручные записи Amnezia сохраняются. Скрипт заменяет только маршруты, которыми
   управлял сам.
5. При сетевой ошибке остаётся последняя рабочая версия.

Это намеренный split tunnel: сайты из списка видят ваш обычный внешний IP, а не
IP VPN. Не добавляйте в исключения сервисы, которые должны оставаться внутри
VPN.

## Обязательная настройка

Из корня скачанного репозитория создайте приватный локальный конфиг:

```bash
cp config/custom-host-policy.example.json config/custom-host-policy.json
```

Откройте `config/custom-host-policy.json` и замените
`REPLACE_WITH_YOUR_VPN_SERVER_IP` на публичный IPv4 вашего VPN-сервера:

```json
{
  "version": 1,
  "protected_ips": ["203.0.113.10"],
  "groups": []
}
```

`203.0.113.10` здесь только адрес из документационного диапазона. Не копируйте
его буквально. Если подключение имеет несколько endpoint-адресов, внесите их
все. Значения `protected_ips` не печатаются и не попадают в сгенерированный
файл.

## macOS: полностью автоматически

Требования: macOS 14+, AmneziaVPN 5.x в `/Applications`, Python 3 из состава
macOS и Xcode Command Line Tools.

```bash
xcode-select --install  # только если Command Line Tools ещё не установлены
bash macos/install.sh
```

Installer сначала собирает Swift-helper и выполняет dry-run. Только после
успешной проверки он атомарно обновляет пользовательский LaunchAgent. Для
AmneziaWG updater запоминает, было ли VPN-подключение активно,
безопасно закрывает AmneziaVPN и `amneziawg-go`, изменяет три routing-настройки,
проверяет результат и возвращает прежнее состояние приложения. При сбое
срабатывает журнал и rollback.

Автоматическое сохранение активной сессии на macOS поддерживается именно для
протокола AmneziaWG. Если GUI открыт без обнаруженного AmneziaWG-туннеля (в том
числе с другим протоколом), запись откладывается до закрытия приложения —
скрипт не станет разрывать неизвестный tunnel.

Проверка:

```bash
launchctl print "gui/${UID}/io.github.amnezia-route-sync"
cat "${HOME}/Library/Application Support/AmneziaRouteSync/status.json"
```

Логи находятся в том же каталоге `AmneziaRouteSync`. Конфиги подключений и
остальные настройки AmneziaVPN скрипт не изменяет.

## Windows: полностью автоматически

Требования: Windows 10/11, AmneziaVPN 5.x и Windows PowerShell 5.1. Запускайте
обычный PowerShell от своего пользователя; права администратора не нужны.

```powershell
Copy-Item .\config\custom-host-policy.example.json .\config\custom-host-policy.json
notepad .\config\custom-host-policy.json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\install.ps1
```

Installer выполняет dry-run, ставит файлы в `%LOCALAPPDATA%\AmneziaRouteSync`
и создаёт SID-scoped пользовательскую задачу `Amnezia-Split-Route-Sync-<SID>` для входа в систему
и проверки каждые 6 часов. Если AmneziaVPN открыта, новая версия списка
записывается как pending. Скрипт не завершает GUI принудительно.

Если автозапуск Amnezia был включён, installer сохраняет его и ставит wrapper:
pending применяется до запуска GUI. При выключенном автозапуске pending
применится, когда задача запустится при закрытой AmneziaVPN. Чтобы применить его
немедленно, закройте приложение и выполните:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\AmneziaRouteSync\update-amnezia-routes.ps1" -ApplyPending
```

Проверка:

```powershell
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Get-ScheduledTask -TaskName "Amnezia-Split-Route-Sync-$sid"
Get-Content "$env:LOCALAPPDATA\AmneziaRouteSync\status.json"
```

Автоматический rollback меняет только три routing-значения реестра и не
перезаписывает `Servers.*`, подключения или другие настройки AmneziaVPN.

## iOS, Android и Linux

Мобильная песочница не разрешает внешнему скрипту безопасно править настройки
AmneziaVPN. Поэтому сначала создайте файл на macOS, Windows или Linux с Python
3.10+ и `curl` (он уже входит в современные версии этих ОС).

macOS/Linux:

```bash
python3 tools/generate_routes.py \
  --policy config/route-policy.json \
  --config config/custom-host-policy.json \
  --output dist/ip-list.json
```

Windows PowerShell:

```powershell
py -3 .\tools\generate_routes.py --policy .\config\route-policy.json --config .\config\custom-host-policy.json --output .\dist\ip-list.json
```

Рядом появится `ip-list.manifest.json` с количеством маршрутов и SHA-256.
Выходной JSON содержит только CIDR — без endpoint, доменов, путей и секретов.

Передайте `dist/ip-list.json` на устройство, затем в AmneziaVPN:

1. Откройте настройки раздельного туннелирования сайтов/IP.
2. Выберите режим **«Адреса из списка не должны открываться через VPN»**.
3. Нажмите меню `⋮` → **«Заменить список с сайтами»**.
4. Импортируйте `ip-list.json`, включите split tunneling и переподключитесь.

На iOS, Android и Linux обновление не автоматическое: повторяйте генерацию и
импорт после изменения policy. Формат и режим импорта соответствуют
[официальной инструкции Amnezia](https://docs.amnezia.org/ru/documentation/instructions/vpn-split-tunneling/).

## Полный JSON: 858+ российских сайтов, Кинопоиск и Госуслуги

Для тех, кому важнее максимальное покрытие сайтов, есть отдельный генератор
`amnezia-full-import.json`. Он объединяет три слоя в один файл:

1. проверенные CIDR Yandex, Ozon, VK, Wildberries, банков, платежей и CDN;
2. 858 доменов из community-списка
   [`kozlovartem20201/amnezia-vpn-russia`](https://github.com/kozlovartem20201/amnezia-vpn-russia),
   включая Кинопоиск, Госуслуги, маркетплейсы, банки, медиа и транспорт;
3. проверенные `/32` текущих DNS-адресов из локального
   `config/custom-host-policy.json` — сырые приватные домены в переносимый файл
   не добавляются.

macOS/Linux:

```bash
python3 tools/generate_amnezia_full_import.py \
  --config config/custom-host-policy.json \
  --output dist/amnezia-full-import.json
```

Windows PowerShell:

```powershell
py -3 .\tools\generate_amnezia_full_import.py --config .\config\custom-host-policy.json --output .\dist\amnezia-full-import.json
```

Затем полностью закройте AmneziaVPN, снова откройте приложение, выберите режим
**«Адреса из списка не должны открываться через VPN»** и выполните `⋮` →
**«Заменить список с сайтами»** → `dist/amnezia-full-import.json`. После импорта
переподключите VPN. Один и тот же JSON подходит для Windows, macOS, Linux,
Android и iOS; на мобильное устройство его можно передать через Files, AirDrop,
облако или мессенджер как обычный документ.

Файл в `dist/` может содержать маршруты из вашего приватного конфига, поэтому
весь каталог исключён из Git, а privacy-scan намеренно запрещает его публикацию.

Community-список загружается непосредственно из репозитория автора по
зафиксированному commit и принимается только при совпадении SHA-256, схемы и
числа записей. Четыре кириллических IDN автоматически переводятся в punycode.
Список не обновляется молча: новый upstream сначала должен пройти review, после
чего pinned commit меняется в коде. Лицензия на данные у автора не указана,
поэтому сторонний JSON не копируется в этот репозиторий.

Важно: по официальной документации Amnezia доменное имя при импорте резолвится
в его текущий IPv4 только один раз и затем автоматически не обновляется. Поэтому
полный JSON нужно заново сгенерировать и импортировать после обновления pinned
списка или при проблеме с конкретным сервисом. Встроенные в этот же файл CIDR
дают более устойчивое покрытие основных категорий, а автоматические installers
продолжают обновлять компактный managed-набор каждые 6 часов.

Локальные пользовательские hostnames сначала резолвятся генератором и проходят
проверку `allowed_networks`; в JSON попадают только принятые `/32`. Это исключает
повторный непроверенный DNS-resolve личного домена внутри Amnezia при импорте.

Полный режим шире компактного автоматического набора: upstream содержит также
международные и общие домены вроде `booking.com`, `coursera.org` и
`akamaized.net`. Они тоже пойдут напрямую. Если это нежелательно, используйте
обычный `ip-list.json` из предыдущего раздела.

## Свои сайты и сервисы

Добавляйте группы только в игнорируемый `config/custom-host-policy.json`:

```json
{
  "version": 1,
  "protected_ips": ["<VPN_SERVER_IPV4>"],
  "groups": [
    {
      "name": "my-service",
      "hosts": ["api.example.com", "www.example.com"],
      "optional_hosts": [],
      "allowed_networks": ["<REVIEWED_IPV4_CIDR>"],
      "minimum_unique_ipv4": 1
    }
  ]
}
```

Все обязательные hostnames должны вернуть хотя бы один IPv4. Каждый ответ DNS
должен входить в `allowed_networks`; иначе обновление останавливается и сохраняет
последнюю рабочую версию. Это защищает от DNS-подмены и случайного добавления
чужой большой сети. `optional_hosts` используйте только для имён, которые
действительно могут временно не иметь A-записи.

Проверка без изменений:

```bash
python3 tools/generate_routes.py --dry-run
```

## Автообновление и безопасность

- Период: 6 часов на macOS и Windows.
- Источник скачивается только по HTTPS с проверкой сертификата, размера и
  таймаутом.
- Набор источников фиксирован. Mutable upstream принимается только внутри
  локальной reviewed-policy; неожиданная сеть блокирует обновление.
- Минимальный префикс — `/16`, максимум 256 итоговых CIDR и 1 000 000 IPv4.
- Любой CIDR, покрывающий `protected_ips`, является фатальной ошибкой.
- Dry-run ничего не пишет. Генератор публикует файл атомарно.
- macOS использует user LaunchAgent; Windows — HKCU и задачу текущего
  пользователя. Root/Administrator не требуются.

Перед первым запуском рекомендуется создать backup настроек AmneziaVPN. После
установки проверьте один адрес из списка: он должен идти напрямую, а контрольный
адрес вне списка — через VPN.

## FAQ: AmneziaVPN, AmneziaWG и RU Direct

### Как настроить split tunneling AmneziaWG на macOS или Windows?

Используйте AmneziaWG как протокол внутри AmneziaVPN 5.x, внесите endpoint в
`protected_ips` и запустите installer для своей ОС. macOS LaunchAgent и Windows
Task Scheduler будут проверять RU Direct маршруты каждые 6 часов.

### Можно ли добавить маршруты Yandex, Ozon, VK и банков автоматически?

Да. Эти категории уже входят в публичный policy. Скрипт скачивает свежие CIDR,
проверяет их границы и заменяет только ранее управляемые записи. Ручные маршруты
AmneziaVPN сохраняются.

### Это замена custom `geosite.dat` и `geoip.dat` из Happ/Xray?

Для AmneziaVPN нужен другой формат. Happ/Xray умеют читать `geosite.dat` и
`geoip.dat`, а AmneziaVPN импортирует IPv4 CIDR из `ip-list.json`. Этот проект
берёт эквивалентные RU-категории и формирует безопасный список именно для
AmneziaVPN.

### Работает ли скрипт в отдельном приложении AmneziaWG?

Автоматические installers изменяют split-tunneling настройки **AmneziaVPN**,
когда в нём выбран протокол AmneziaWG. Они не редактируют конфигурацию отдельного
native-клиента AmneziaWG. Для других устройств используйте ручной импорт
`ip-list.json` в AmneziaVPN.

### Всегда ли загружается самая свежая версия маршрутов?

macOS и Windows проверяют upstream каждые 6 часов. Новая версия принимается
только внутри reviewed-policy. Если upstream недоступен или внезапно публикует
неожиданную сеть, настройки не меняются и остаётся последняя проверенная версия.

### Почему IP VPN-сервера обязателен в `protected_ips`?

Если endpoint случайно попадёт в direct-исключение, само VPN-подключение может
перестать устанавливаться. Поэтому любой маршрут, покрывающий endpoint,
отклоняется до записи. Endpoint остаётся только в локальном ignored-конфиге и
его закрытой установленной копии.

## Удаление

Остановка автоматизации не удаляет уже импортированные маршруты. Сначала в
AmneziaVPN очистите или замените список split tunneling, затем запустите
uninstaller.

macOS:

```bash
bash macos/uninstall.sh
```

Windows PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\uninstall.ps1
```

Windows-uninstaller восстанавливает исходную команду автозапуска Amnezia, если
пользователь не менял её после установки. Если он сообщает о незавершённой
Registry-транзакции, закройте AmneziaVPN, один раз запустите установленный updater
с `-ApplyPending`, затем повторите удаление. Journal и rollback backup никогда не
удаляются до успешного recovery.

## Разработка

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile macos/update_amnezia_routes.py tools/generate_routes.py
bash -n macos/install.sh
```

Windows self-tests:

```powershell
powershell.exe -NoProfile -File .\windows\update-amnezia-routes.ps1 -CodecSelfTest
powershell.exe -NoProfile -File .\windows\update-amnezia-routes.ps1 -ValidationSelfTest
```

Сторонний источник и его лицензионный статус описаны в [NOTICE.md](NOTICE.md).
Сообщения об уязвимостях — по инструкции в [SECURITY.md](SECURITY.md).

## Ограничение ответственности

Проект не связан с Amnezia и не является официальным компонентом AmneziaVPN.
Маршруты и IP-инфраструктура сервисов меняются; проверяйте результат на своих
устройствах. Используйте только там, где это разрешено правилами сервисов и
законом вашей юрисдикции.
