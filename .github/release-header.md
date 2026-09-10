**Российские сайты без VPN — готовый список для Amnezia VPN.** Собирается
автоматически каждый день. С этим списком Госуслуги, банки, Ozon, Wildberries,
Avito, Яндекс, VK и другие российские сервисы открываются напрямую, а YouTube,
Instagram и весь остальной интернет — через VPN. Выключать VPN больше не нужно.

📅 **Сборка от {{DATE}}**

### 📥 Какой файл скачать

| Ваше устройство | Файл |
|---|---|
| 🤖 Android · 💻 Windows | **amnezia-ru-direct.json** |
| 🍏 iPhone · iPad · Mac · 🐧 Linux | **amnezia-ru-direct-ip.json** |
| 🐢 Слабый или старый телефон | **amnezia-ru-direct-lite.json** |

👇 Файлы — внизу страницы, в разделе **Assets**.

### 🛠️ Как добавить в Amnezia (1 минута)

1. Скачайте файл для своего устройства.
2. Откройте **AmneziaVPN** → **Настройки** → **Раздельное туннелирование сайтов**.
3. Выберите **«Адреса из списка не должны открываться через VPN»**.
4. Нажмите **⋮** → **«Заменить список с сайтами»** → выберите скачанный файл.
5. Переподключите VPN.

✅ **Проверка:** откройте [yandex.ru/internet](https://yandex.ru/internet) — там должен
быть ваш обычный IP, а не адрес VPN-сервера.

⚠️ Нужен **Amnezia Premium** или **свой сервер**: в бесплатной Amnezia Free
раздельного туннелирования нет.

🪟 **Windows в один клик:** скачайте **install-windows.bat** из Assets, дважды
щёлкните и нажмите «Да» — установщик сам поставит список и будет обновлять его
каждые 6 часов.

💡 На Windows и Mac можно не обновлять список руками —
[скрипт](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling#установка-скрипта-с-автообновлением)
сам ставит свежую сборку каждые 6 часов.

<details>
<summary>🧰 Файлы для роутеров, Xray, Happ и WireGuard</summary>

| Файл | Для чего |
|---|---|
| `ru-direct-domains.txt` | домены построчно (AdGuard, Xray, свои скрипты) |
| `ru-direct-ipv4.txt` | сети IPv4 построчно |
| `wg-allowed-ips.txt` | готовая строка `AllowedIPs` для WireGuard/AmneziaWG |
| `happ-ru-direct.json` | правила `DirectSites` / `DirectIp` для Happ |
| `manifest.json` | счётчики и контрольные суммы |

</details>

---

