# Внешние источники — отчёт импорта

Сборка 2026-09-08. Файл генерируется `tools/import_external.py`, правки руками бессмысленны.

## Источники

| Источник | Уникальных IP/CIDR | Принято IP/CIDR | Домены | Новые поддомены |
|---|---:|---:|---:|---:|
| `mobile-whitelist-cidr` | 30228 | 290 | 0 | 0 |
| `mobile-whitelist-domains` | 0 | 0 | 910 | 788 |
| `operator-whitelist-cidr` | 88 | 20 | 0 | 0 |
| `unrkn-vpn-domains` | 0 | 0 | 480 | 0 |
| `itdog-russia-only` | 0 | 0 | 39 | 6 |
| `lib4u-amnezia` | 1535 | 275 | 1954 | 110 |

После объединения внутри проверенных диапазонов IP→ASN принято сетей: **248** (потолок 1600).

## Почему отсеяно

| Причина | Сетей |
|---|---|
| не российская сеть | 22819 |
| нет в таблице IP→ASN или сеть не анонсируется | 2674 |
| ASN не обслуживает ни один сервис каталога | 1510 |
| адресное пространство оператора связи | 1380 |
| сеть пересекает разные ASN | 1193 |
| уже покрыто снапшотом | 895 |
| глобальный CDN или облако | 795 |

Зарубежные сети по странам: US — 5059, GB — 1745, TR — 1718, DE — 1526, FR — 1164, IT — 968, CH — 932, NL — 930, SE — 683, ES — 561, AT — 557, PL — 452. Именно ради этих записей и написан фильтр: попади они в direct, часть трафика ушла бы мимо VPN с домашнего адреса.

## Российские ASN, которых нет в каталоге

Сети этих ASN отклонены, потому что ни один сервис каталога на них не живёт. Если среди них окажется CDN российского сервиса — его место в `config/asn-expand.json`, а не здесь. ASN операторов связи не добавляем никогда: их адресное пространство огромно и в direct не нужно.

| ASN | Имя | Сетей |
|---|---|---|
| AS25513 | ASN-MGTS-USPD | 26 |
| AS204720 | CDNETWORKS | 22 |
| AS12683 | STATEL-AS PJSC Rostelecom. Stavropol branch | 19 |
| AS41560 | UT-SVR | 19 |
| AS210079 | EUROBYTE | 18 |
| AS5523 | CREDO-TELECOM | 18 |
| AS20533 | SAKHTEL-AS | 17 |
| AS47193 | LAN-OPTIC | 17 |
| AS20632 | PETERSTAR-AS Saint-Petersburg | 17 |
| AS56340 | UMNYESETI-AS | 16 |
| AS56981 | TOMSK-AS | 16 |
| AS25532 | MASTERHOST-AS Moscow, Russia | 16 |
| AS38917 | KOMTEL-AS | 15 |
| AS15974 | VTT-AS ISP, Saratov, Russia. | 15 |
| AS8402 | CORBINA-AS OJSC Vimpelcom | 14 |
| AS20807 | CREDOLINK-ASN St.-Petersburg | 14 |
| AS31163 | MF-KAVKAZ-AS | 13 |
| AS20597 | ELTEL-AS | 13 |
| AS30822 | MAGEAL-AS | 13 |
| AS8752 | ASVT-NETWORK Russia | 13 |
| AS25490 | STC-AS OJSC Southern Telecommunications Company | 12 |
| AS3226 | MARK-ITT-AS | 12 |
| AS13174 | MTSNET Moscow, Russia | 12 |
| AS31359 | FORATEC-AS Foratec Net | 11 |
| AS31200 | NTK IPv6 customers | 11 |
| AS8615 | CNT-AS Moscow, Russia | 11 |
| AS15868 | NALTEL-AS | 10 |
| AS3253 | SOVINTEL-EF-AS Uralrelcom Net | 10 |
| AS200928 | RTTV | 10 |
| AS31261 | GARS-AS Moscow, Russia | 9 |
| AS15774 | TTK-RTL Retail | 9 |
| AS48096 | ITGRAD | 9 |
| AS41575 | INTERCITY-AS | 9 |
| AS6789 | CRELCOM-NET | 9 |
| AS49063 | DTLN | 9 |
| AS34665 | PINDC-AS | 8 |
| AS15552 | CK | 8 |
| AS39238 | OKBPROGRESS Moscow, Russia | 8 |
| AS61400 | NETRACK-AS | 8 |
| AS20764 | RASCOM-AS CJSC RASCOM ISP | 8 |

## Домены вне каталога — 1842

Новые поддомены сервисов каталога добавлены в полный список автоматически; их источники указаны в `data/external.json`. Ниже — остальные кандидаты для ручной проверки. Полный список без обрезки, с происхождением каждой записи: [`external-candidates.json`](external-candidates.json).

```
1018213540.rsc.cdn77.org
1917live.red
1prime.ru
21-school.ru
24h.tv
2gis.ae
2gis.am
2gis.az
2gis.biz
2gis.by
2gis.com.cy
2gis.cz
2gis.ge
2gis.io
2gis.kg
2gis.kz
2gis.net
2gis.qa
2gis.sa
2gis.tech
2gis.tj
2gis.uz
2ip.ru
2w.ru
3dnews.ru
3ebra.net
4c.ru
4epenaxa.com
5post.market
a.auth-nsdi.ru
a.res-nsdi.ru
abonementx5.ru
abr.ru
accesspoint.uz
acmvid.com
activate.activation-v2.kaspersky.com
activation-v2.geo.kaspersky.com
activation-v2.kaspersky.com
actualidad-rt.com
ad-cdek.ru
adfox.ru
admetrica.ru
adriver.ru
ads-integration.rustore.ru
ads.dahlmessenger.com
ads.icq.com
ads.rustore.ru
ads.viqeo.tv
ads.x5media.ru
ads.yandex
ads.yango.com
adsadvisor.io
adsapp.dahlmessenger.com
adsapp.stage.telega.info
adsapp.telega.info
adv.rustore.ru
adygeya.ru
adygtelecom.com
agent.ru
ahilesva.info
aiesa.ru
alefbank.com
alfa.me
alfabank.st
aliexpress.ru
alt-r.my.com
altai.ru
altaiobr04.ru
amic.ru
amur.ru
ankb.ru
antiphishing.nl
antiphishing.ru
anytimeviewru.com
aodahl.com
aoglonass.ru
api-eu.carrotquest.app
api-eu.carrotquest.io
api-js.mindbox.ru
api-ru.carrotquest.app
api-ru.carrotquest.io
api-ru.mindbox.cloud
api-secure.carrotquest.app
api-secure.carrottrack.app
api-staging.mindbox.ru
api.carrotquest.app
api.carrotquest.io
api.carrottrack.app
api.dashly.app
api.dashlytrack.app
api.dobro.ru
api.evotor.ru
api.hrlink.ru
api.lizaalert.org
api.mindbox.cloud
api.mindbox.ru
api.roskachestvo.gov.ru
apiauto.ru
apiok.ru
app.hrlink.ru
appmetrica.yango.com
appsmail.ru
apptracer.ru
apptrackpets.com
apteka-april.ru
aptekiplus.ru
arabicrt.ru
arctic.ru
arkhangelsk.ru
armgs.team
artel.watch
arteldoc.com
arteldoc.tv
asia-pay.ru
asiangooglenetwork.com
astrakhan.ru
asusrouter.com
at.ua
atb.su
atomyze.ru
atomyze.tech
attachmail.ru
attachmy.com
audiohead.ru
autokreditbank.ru
autoru.me
avangard.ru
aversbank.ru
aviasales.com
avito.net
avitocargo.ru
avitopro.ru
avitorealty.ru
avs.io
avto.ru
avtodor-tr.ru
avtovokzaly.ru
azbukainterneta.ru
b.auth-nsdi.ru
b.res-nsdi.ru
b17.ru
b2c-digest.ru
b2c-ticket-sentry.onelya.ru
b37mrtl.ru
babki.ru
baltnews.com
baltnews.lt
bananacall.ru
bank-arzamas.ru
bank-credit-suisse-moscow.ru
bank131.com
bankermak.ru
bankline.ru
baranky.com
bargipsy.com
bashkiria.ru
bbr.ru
bcs-bank.ru
beeline.tv
beesbfl.ru
beescrm.ru
beget.ru
belgorod.ru
belkacar.ru
berizaryad.ru
best2pay.net
betboom.ru
bfa.ru
bimsaas.ru
bir.ru
bitrix.info
bizmrg.com
bk.ru
bk6bba-resources.com
bk6bba-resources.ru
bkvet.ru
blablacar.ru
blanc.ru
bm-bank.ru
book-catalog.ru
book1917.live
booking-tec.ru
boom.ru
boosty.to
botmechanic.io
bps-sberbank.by
broker.ru
bryansk.ru
buryatia.ru
cabconnect.org
cabinet.evotor.ru
callbackkiller.com
cap.ru
capitalt.ru
cardsmobile.ru
carrot-mail.io
carrotquest-mail.io
carrotquest.app
carrotquest.io
carrottrack.app
… ещё 1642
```
