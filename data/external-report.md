# Внешние источники — отчёт импорта

Сборка 2026-09-10. Файл генерируется `tools/import_external.py`, правки руками бессмысленны.

## Источники

| Источник | Уникальных IP/CIDR | Принято IP/CIDR | Домены | Новые поддомены | Корни |
|---|---:|---:|---:|---:|---:|
| `mobile-whitelist-cidr` | 30228 | 280 | 0 | 0 | 0 |
| `mobile-whitelist-domains` | 0 | 0 | 910 | 783 | 0 |
| `operator-whitelist-cidr` | 88 | 18 | 0 | 0 | 0 |
| `unrkn-vpn-domains` | 0 | 0 | 480 | 0 | 0 |
| `itdog-russia-only` | 0 | 0 | 39 | 6 | 0 |
| `lib4u-amnezia` | 1540 | 260 | 1954 | 106 | 1043 |
| `v2fly-ru` | 0 | 0 | 1741 | 9 | 998 |
| `jirnobruh-amnezia` | 768 | 144 | 925 | 176 | 305 |
| `kyoresuas-ru-bypass` | 8800 | 714 | 0 | 0 | 0 |
| `kyoresuas-essential` | 313 | 76 | 0 | 0 | 0 |
| `pincetgore-ip-list` | 1373 | 208 | 0 | 0 | 0 |
| `kozlov-amnezia` | 0 | 0 | 858 | 7 | 19 |
| `egkodin-ru-sites` | 12843 | 1291 | 1105 | 638 | 88 |
| `supertico-domains` | 0 | 0 | 2 | 0 | 1 |
| `pvd-dog-no-vpn` | 1029 | 284 | 0 | 0 | 0 |
| `opencck-iplist` | 1449 | 261 | 0 | 0 | 0 |
| `rockblack-ru` | 334 | 78 | 0 | 0 | 0 |

После объединения внутри проверенных диапазонов IP→ASN принято сетей: **1000** (потолок 1000).

⚠️ Потолок срезал **460** сетей, прошедших проверку. Подними `--limit`, если Amnezia переваривает список, или сузь источники.

## Почему отсеяно

| Причина | Сетей |
|---|---|
| не российская сеть | 24378 |
| ASN не обслуживает ни один сервис каталога | 13335 |
| нет в таблице IP→ASN или сеть не анонсируется | 5894 |
| сеть пересекает разные ASN | 4296 |
| уже покрыто снапшотом | 2908 |
| адресное пространство оператора связи | 2860 |
| глобальный CDN или облако | 1453 |
| не публичная сеть | 19 |
| шире допустимой /12 | 8 |

Зарубежные сети по странам: US — 5227, GB — 1882, TR — 1753, DE — 1628, FR — 1197, NL — 1014, IT — 991, CH — 946, SE — 714, ES — 605, AT — 570, PL — 466. Именно ради этих записей и написан фильтр: попади они в direct, часть трафика ушла бы мимо VPN с домашнего адреса.

## Российские ASN, которых нет в каталоге

Сети этих ASN отклонены, потому что ни один сервис каталога на них не живёт. Если среди них окажется CDN российского сервиса — его место в `config/asn-expand.json`, а не здесь. ASN операторов связи не добавляем никогда: их адресное пространство огромно и в direct не нужно.

| ASN | Имя | Сетей |
|---|---|---|
| AS25513 | ASN-MGTS-USPD | 92 |
| AS49063 | DTLN | 84 |
| AS25227 | ASN-AVANTEL-MSK Located in Moscow, Russia. | 83 |
| AS6789 | CRELCOM-NET | 75 |
| AS8641 | NAUKANET-AS BACKBONE AS of Nauka-Svyaz | 70 |
| AS56340 | UMNYESETI-AS | 69 |
| AS5563 | URAL Ural Regional Net | 69 |
| AS48282 | VDSINA-AS | 67 |
| AS48642 | FOR-AS Russia | 67 |
| AS201776 | MIRANDA-AS Miranda-Media LLC | 63 |
| AS210079 | EUROBYTE | 62 |
| AS15774 | TTK-RTL Retail | 59 |
| AS25532 | MASTERHOST-AS Moscow, Russia | 59 |
| AS39238 | OKBPROGRESS Moscow, Russia | 58 |
| AS29076 | CITYTELECOM-AS Filanco LTD | 58 |
| AS48096 | ITGRAD | 51 |
| AS61400 | NETRACK-AS | 51 |
| AS31363 | MOSCOW-AS | 51 |
| AS211183 | ADMINVPS | 50 |
| AS206805 | T1CLOUD-AS | 49 |
| AS20632 | PETERSTAR-AS Saint-Petersburg | 49 |
| AS29124 | ISKRATELECOM-AS SEVEN-SKY | 45 |
| AS56694 | SMARTAPE | 45 |
| AS12494 | ASN-POSTLTD | 43 |
| AS204720 | CDNETWORKS | 37 |
| AS38917 | KOMTEL-AS | 37 |
| AS51522 | ONLINE | 36 |
| AS34665 | PINDC-AS | 35 |
| AS42610 | NCNET-AS OJSC National Cable Networks | 35 |
| AS15552 | CK | 34 |
| AS39264 | METROMAX-AS | 34 |
| AS8732 | COMCOR-AS Moscow | 34 |
| AS41733 | ZTELECOM-AS | 32 |
| AS56981 | TOMSK-AS | 32 |
| AS3226 | MARK-ITT-AS | 31 |
| AS51219 | K2_INT | 31 |
| AS204144 | COMFORT-AS | 31 |
| AS8402 | CORBINA-AS OJSC Vimpelcom | 30 |
| AS8369 | INTERSVYAZ-AS 38-B, Komsomolsky prospekt | 30 |
| AS196695 | NETONERUS | 30 |

## Корневые домены — принято 1207

Домены вне каталога из источников с флагом `roots`. Корень принимается, только если у него есть IPv4 и все адреса российские и не принадлежат глобальным CDN; такие корни идут только в полный список, не в lite. Потолок — 2500. Отказы по каждому домену — в `external-candidates.json`, поле `reason`.

| Причина отказа | Доменов |
|---|---:|
| зарубежный адрес | 320 |
| не резолвится (NXDOMAIN или нет A-записей) | 246 |
| глобальный CDN или облако | 157 |
| нет ответа DNS | 12 |
| не публичный адрес | 6 |
| адрес вне таблицы IP→ASN | 3 |

## Домены вне каталога — 924

Новые поддомены сервисов каталога и принятые корни добавлены в полный список автоматически; их источники указаны в `data/external.json`. Ниже — остальные кандидаты для ручной проверки. Полный список без обрезки, с происхождением каждой записи: [`external-candidates.json`](external-candidates.json).

```
1018213540.rsc.cdn77.org
1c-fresh.com
220volt.ru
2gis.biz
2gis.com.cy
2gis.cz
2gis.io
2gis.kz
2gis.net
2gis.qa
2gis.sa
2gis.tech
2ip.ru
4pda.ru
4pda.to
abbyy.com
accesspoint.uz
activate.activation-v2.kaspersky.com
activation-v2.geo.kaspersky.com
activation-v2.kaspersky.com
adfox.ru
admetrica.ru
ads.dahlmessenger.com
ads.yandex
ads.yango.com
adsadvisor.io
adsapp.dahlmessenger.com
adsapp.stage.telega.info
agent.ru
akamaized.net
aliexpress.ru
ankb.ru
antiphishing.nl
antiphishing.ru
anytimeviewru.com
aodahl.com
aoglonass.ru
api-eu.carrotquest.app
api-eu.carrotquest.io
api-js.mindbox.ru
api-ru.mindbox.cloud
api.dashly.app
api.dashlytrack.app
api.dobro.ru
api.evotor.ru
api.hrlink.ru
api.lizaalert.org
api.mindbox.cloud
api.perplexity.ai
api.roskachestvo.gov.ru
app.hrlink.ru
appmetrica.yango.com
arkhangelsk.ru
asiangooglenetwork.com
asusrouter.com
attachmy.com
autoscout24.ru
aviasales.com
avito.net
avitocargo.ru
avitopro.ru
avitorealty.ru
avs.io
avtodor-tr.ru
b2c-ticket-sentry.onelya.ru
b37mrtl.ru
baikal-electronics.ru
bank-credit-suisse-moscow.ru
bank131.com
beeline-cloud.ru
berizaryad.ru
bfa.ru
bitrix.info
bizmrg.com
bk6bba-resources.com
bk6bba-resources.ru
bkvet.ru
blog.perplexity.ai
booking.com
bookmate.com
bps-sberbank.by
buryatia.ru
busuu.com
cabconnect.org
cabinet.evotor.ru
carrot-mail.io
carrottrack.app
cas-bridge.xethub.hf.co
cdn-lfs-eu-1.hf.co
cdn-lfs-us-1.hf.co
cdn-lfs.hf.co
cdn-lfs.huggingface.co
cdn-vk.net
cdn-vk.ru
cdn1.ozonusercontent.com
cdnmail.ru
cert-gib.com
cert-gib.ru
cesarsmart.ru
chat.perplexity.ai
che.tv
chelyabinsk-sgo-edu-74.ru
clck.ru
clck.yango.com
cloudru.cn
clstorage.net
cms1.dzvr.ru
coddy.academy
codeforces.com
codeseason.by
codewars.com
commerzbank.ru
comss.club
comss.info
comss.me
comss.news
comss.one
console.perplexity.ai
coursera.org
cplsb.ru
credit-zenit.ru
crl.kaspersky.com
crrintegro.ru
csat.ru
cybercrimecon.com
dahlmessenger.com
dashly.app
dashly.help
dashly.io
dashly.me
dashlytrack.app
datacloudmy.com
dc1-cert.ksn.kaspersky-labs.com
dc1-file.ksn.kaspersky-labs.com
dc1-pp.ksn.kaspersky-labs.com
dc1-st.ksn.kaspersky-labs.com
dc1.ksn.kaspersky-labs.com
deliveryclub.ru
deltacredit.ru
dev-my.games
dnl-00.geo.kaspersky.com
dnl-01.geo.kaspersky.com
dnl-02.geo.kaspersky.com
dnl-03.geo.kaspersky.com
dnl-04.geo.kaspersky.com
dnl-05.geo.kaspersky.com
dnl-06.geo.kaspersky.com
dnl-07.geo.kaspersky.com
dnl-08.geo.kaspersky.com
dnl-09.geo.kaspersky.com
dnl-10.geo.kaspersky.com
dnl-11.geo.kaspersky.com
dnl-12.geo.kaspersky.com
dnl-13.geo.kaspersky.com
dnl-14.geo.kaspersky.com
dnl-15.geo.kaspersky.com
dnl-16.geo.kaspersky.com
dnl-17.geo.kaspersky.com
dnl-18.geo.kaspersky.com
dnl-19.geo.kaspersky.com
dns-com.ru
dobro.ru
docs.perplexity.ai
dodois.com
dodois.io
dodostatic.net
dom-kino.tv
driveawaytaxi.org
drom.com
drweb-av.es
drweb.cn
drweb.co.jp
drweb.fr
drweb.kz
dumatv.ru
duolingo.com
durovscode.com
dv.team
dzeninfra.ru
dzvr.ru
e.mindbox.ru
eadaily.org
edadeal.ru
edge.geo.kaspersky.com
edge.perplexity.ai
edu.sirius.online
edx.org
eligens.cl
eligens.com.br
eligens.io
elle.ru
englishdom.com
enterprise.perplexity.ai
eopp-portal.ru
epam.com
epd-portal.ru
epp.genproc.gov.ru
esforce.ru
etna.ai
etp-torgi.ru
… ещё 724
```
