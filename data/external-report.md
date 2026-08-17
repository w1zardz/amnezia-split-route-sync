# Внешние источники — отчёт импорта

Сборка 2026-08-17. Файл генерируется `tools/import_external.py`, правки руками бессмысленны.

## Источники

| Источник | Записей | Прошло проверку |
|---|---|---|
| `mobile-whitelist-cidr` | 30228 | 290 |
| `mobile-whitelist-domains` | 910 | — домены в сборку не идут |
| `operator-whitelist-cidr` | 88 | 21 |

После схлопывания в анонсируемые префиксы принято сетей: **191** (потолок 1600).

## Почему отсеяно

| Причина | Сетей |
|---|---|
| не российская сеть | 22594 |
| нет в таблице IP→ASN или сеть не анонсируется | 2334 |
| ASN не обслуживает ни один сервис каталога | 1372 |
| сеть лежит в двух разных ASN | 1352 |
| адресное пространство оператора связи | 1306 |
| глобальный CDN или облако | 668 |
| уже покрыто снапшотом | 379 |

Зарубежные сети по странам: US — 5068, GB — 1746, TR — 1726, DE — 1522, FR — 1166, IT — 970, NL — 921, CH — 809, SE — 680, AT — 559, ES — 556, PL — 459. Именно ради этих записей и написан фильтр: попади они в direct, часть трафика ушла бы мимо VPN с домашнего адреса.

## Российские ASN, которых нет в каталоге

Сети этих ASN отклонены, потому что ни один сервис каталога на них не живёт. Если среди них окажется CDN российского сервиса — его место в `config/asn-expand.json`, а не здесь. ASN операторов связи не добавляем никогда: их адресное пространство огромно и в direct не нужно.

| ASN | Имя | Сетей |
|---|---|---|
| AS25513 | ASN-MGTS-USPD | 26 |
| AS204720 | CDNETWORKS | 22 |
| AS12683 | STATEL-AS PJSC Rostelecom. Stavropol branch | 21 |
| AS41560 | UT-SVR | 19 |
| AS5523 | CREDO-TELECOM | 18 |
| AS20533 | SAKHTEL-AS | 17 |
| AS47193 | LAN-OPTIC | 17 |
| AS56340 | UMNYESETI-AS | 16 |
| AS20632 | PETERSTAR-AS Saint-Petersburg | 16 |
| AS57363 | CDNVIDEO-AS | 15 |
| AS38917 | KOMTEL-AS | 15 |
| AS56981 | TOMSK-AS | 15 |
| AS15974 | VTT-AS ISP, Saratov, Russia. | 15 |
| AS31163 | MF-KAVKAZ-AS | 14 |
| AS8402 | CORBINA-AS OJSC Vimpelcom | 14 |
| AS20597 | ELTEL-AS | 14 |
| AS20807 | CREDOLINK-ASN St.-Petersburg | 14 |
| AS30822 | MAGEAL-AS | 13 |
| AS8752 | ASVT-NETWORK Russia | 13 |
| AS210079 | EUROBYTE | 12 |
| AS25490 | STC-AS OJSC Southern Telecommunications Company | 12 |
| AS31359 | FORATEC-AS Foratec Net | 12 |
| AS29076 | CITYTELECOM-AS Filanco LTD | 11 |
| AS31200 | NTK IPv6 customers | 11 |
| AS8615 | CNT-AS Moscow, Russia | 11 |
| AS13174 | MTSNET Moscow, Russia | 11 |
| AS15868 | NALTEL-AS | 10 |
| AS3253 | SOVINTEL-EF-AS Uralrelcom Net | 10 |
| AS31261 | GARS-AS Moscow, Russia | 9 |
| AS15774 | TTK-RTL Retail | 9 |
| AS48096 | ITGRAD | 9 |
| AS3226 | MARK-ITT-AS | 9 |
| AS41575 | INTERCITY-AS | 9 |
| AS6789 | CRELCOM-NET | 9 |
| AS15552 | CK | 8 |
| AS39238 | OKBPROGRESS Moscow, Russia | 8 |
| AS20764 | RASCOM-AS CJSC RASCOM ISP | 8 |
| AS12958 | MCC T2 Russia Network | 8 |
| AS8570 | LES OJSC Lipetskelectrosvyaz | 8 |
| AS20576 | GAZSVYAZ 16, Nametkina street | 8 |

## Домены вне каталога — 824

Кандидаты на добавление в `data/services/`. В сборку автоматически не попадают: список доменов курируется руками.

```
00.img.avito.st
01.img.avito.st
02.img.avito.st
03.img.avito.st
04.img.avito.st
05.img.avito.st
06.img.avito.st
07.img.avito.st
08.img.avito.st
09.img.avito.st
10.img.avito.st
11.img.avito.st
12.img.avito.st
13.img.avito.st
14.img.avito.st
15.img.avito.st
16.img.avito.st
17.img.avito.st
18.img.avito.st
19.img.avito.st
1l-api.mail.ru
1l-go.mail.ru
1l-hit.mail.ru
1l-s2s.mail.ru
1l-view.mail.ru
1l.mail.ru
1link.mail.ru
20.img.avito.st
2018.mail.ru
2019.mail.ru
2020.mail.ru
2021.mail.ru
21.img.avito.st
22.img.avito.st
23.img.avito.st
23feb.mail.ru
24.img.avito.st
25.img.avito.st
26.img.avito.st
27.img.avito.st
28.img.avito.st
29.img.avito.st
30.img.avito.st
300.ya.ru
31.img.avito.st
32.img.avito.st
33.img.avito.st
34.img.avito.st
3475482542.mc.yandex.ru
35.img.avito.st
36.img.avito.st
37.img.avito.st
38.img.avito.st
39.img.avito.st
40.img.avito.st
41.img.avito.st
42.img.avito.st
43.img.avito.st
44.img.avito.st
45.img.avito.st
46.img.avito.st
47.img.avito.st
48.img.avito.st
49.img.avito.st
50.img.avito.st
51.img.avito.st
52.img.avito.st
53.img.avito.st
54.img.avito.st
55.img.avito.st
56.img.avito.st
57.img.avito.st
58.img.avito.st
59.img.avito.st
60.img.avito.st
61.img.avito.st
62.img.avito.st
63.img.avito.st
64.img.avito.st
65.img.avito.st
66.img.avito.st
67.img.avito.st
68.img.avito.st
69.img.avito.st
70.img.avito.st
71.img.avito.st
72.img.avito.st
73.img.avito.st
74.img.avito.st
742231.ms.ok.ru
75.img.avito.st
76.img.avito.st
77.img.avito.st
78.img.avito.st
79.img.avito.st
80.img.avito.st
81.img.avito.st
82.img.avito.st
83.img.avito.st
84.img.avito.st
85.img.avito.st
86.img.avito.st
87.img.avito.st
88.img.avito.st
89.img.avito.st
8mar.mail.ru
8march.mail.ru
90.img.avito.st
91.img.avito.st
92.img.avito.st
93.img.avito.st
94.img.avito.st
95.img.avito.st
96.img.avito.st
97.img.avito.st
98.img.avito.st
99.img.avito.st
9may.mail.ru
a.auth-nsdi.ru
a.res-nsdi.ru
a.wb.ru
aa.mail.ru
adm.digital.gov.ru
adm.mp.rzd.ru
admin.cs7777.vk.ru
admin.tau.vk.ru
adv.ozon.ru
afisha.mail.ru
agent.mail.ru
akashi.vk-portal.net
alfa-mobile.alfabank.ru
alpha3.minigames.mail.ru
alpha4.minigames.mail.ru
amigo.mail.ru
ams2-cdn.2gis.com
an.yandex.ru
analytics.predict.mail.ru
analytics.vk.ru
answer.mail.ru
answers.mail.ru
api-maps.yandex.ru
api.2gis.ru
api.browser.yandex.com
api.browser.yandex.ru
api.cs7777.vk.ru
api.dobro.ru
api.events.plus.yandex.net
api.evotor.ru
api.hrlink.ru
api.lizaalert.org
api.max.ru
api.photo.2gis.com
api.plus.kinopoisk.ru
api.predict.mail.ru
api.reviews.2gis.com
api.roskachestvo.gov.ru
api.s3.yandex.net
api.tau.vk.ru
api.uxfeedback.yandex.net
app.hrlink.ru
apps.research.mail.ru
authdl.mail.ru
autodiscover.corp.mail.ru
autodiscover.ord.ozon.ru
av.mail.ru
avatars.mds.yandex.com
aw.mail.ru
away.cs7777.vk.ru
away.tau.vk.ru
azt.mail.ru
b.auth-nsdi.ru
b.res-nsdi.ru
bank.ozon.ru
banners-website.wildberries.ru
bb.mail.ru
bd.mail.ru
beko.dom.mail.ru
bender.mail.ru
beta.mail.ru
bfds.sberbank.ru
bitva.mail.ru
biz.mail.ru
blackfriday.mail.ru
blog.mail.ru
bot.gosuslugi.ru
botapi.max.ru
bratva-mr.mail.ru
bro-bg-store.s3.yandex.com
bro-bg-store.s3.yandex.net
bro-bg-store.s3.yandex.ru
brontp-pre.yandex.ru
browser.mail.ru
browser.yandex.com
business.vk.ru
cabinet.evotor.ru
calendar.mail.ru
capsula.mail.ru
cargo.rzd.ru
cars.mail.ru
catalog.api.2gis.com
… ещё 624
```
