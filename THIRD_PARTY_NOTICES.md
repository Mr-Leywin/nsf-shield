# Üçüncü taraf bileşenler / Third-party notices

NSF Shield, aşağıdaki açık kaynak bileşenleri **değiştirmeden** birlikte dağıtır. NSF Shield'in kendi kaynak kodu MIT lisanslıdır (Copyright (c) 2026 Nightshift (Osman Barış MEDİNE); bkz. `LICENSE`); bu bileşenler kendi lisanslarına tabidir. Lisans metinlerinin tamamı `third_party/<bileşen>/licenses/` klasörlerinde ve dağıtılan paketin `licenses/` klasöründedir.

NSF Shield bu projelerin geliştiricileriyle bağlantılı değildir ve onlar tarafından desteklenmez.

NSF Shield bundles the following open-source components **unmodified**. NSF Shield's own source code is MIT-licensed; these components remain under their own licenses (full texts in `third_party/<component>/licenses/` and in the `licenses/` folder of the package). NSF Shield is not affiliated with or endorsed by their authors.

## Motor 1 – GoodbyeDPI (`bin\x86_64`, `bin\x86`)

| Bileşen / Component | Sürüm | Lisans | Telif / Copyright | Kaynak kod / Source |
|---|---|---|---|---|
| GoodbyeDPI (`goodbyedpi.exe`) | 0.2.3rc3 | Apache License 2.0 | © ValdikSS | https://github.com/ValdikSS/GoodbyeDPI |
| WinDivert (`WinDivert.dll`, `WinDivert32.sys`, `WinDivert64.sys`) | 2.2 (GoodbyeDPI 0.2.3rc3 ile gelen) | GNU LGPL v3 (ya da GPL v2) | © basil00 | https://github.com/basil00/WinDivert |
| uthash (goodbyedpi.exe içinde) | – | BSD (revised) | © Troy D. Hanson | https://github.com/troydhanson/uthash |
| getline (goodbyedpi.exe içinde) | – | BSD 2-Clause | © The NetBSD Foundation | https://github.com/ValdikSS/GoodbyeDPI |

## Motor 2 – Zapret / winws (`bin\zapret`, yalnızca 64 bit)

| Bileşen / Component | Sürüm | Lisans | Telif / Copyright | Kaynak kod / Source |
|---|---|---|---|---|
| zapret – `winws.exe` ve sahte paketler (`payloads\*.bin`) | v72.13 | MIT | © 2016-2024 bol-van | https://github.com/bol-van/zapret |
| Cygwin DLL (`cygwin1.dll`) | 3.4.10 | GNU LGPL v3 veya sonrası (GPL v3 metni dahil) | © Red Hat, Inc. ve Cygwin katkıcıları | https://cygwin.com/pub/cygwin/x86_64/release/cygwin/cygwin-3.4.10-1-src.tar.xz |
| WinDivert (`WinDivert.dll`, `WinDivert64.sys`) | 2.2.2-A (zapret ile gelen) | GNU LGPL v3 (ya da GPL v2) | © basil00 | https://github.com/basil00/WinDivert/releases/tag/v2.2.2 |
| zlib (winws.exe içinde, statik) | 1.3.1 | zlib | © Jean-loup Gailly, Mark Adler | https://zlib.net |
| kavl (winws.exe içinde) | – | MIT | © Attractive Chaos | https://github.com/attractivechaos/klib |
| uthash (winws.exe içinde) | – | BSD (revised) | © Troy D. Hanson | https://github.com/troydhanson/uthash |
| RFC 6234 SHA-2/HMAC/HKDF kodu (winws.exe içinde) | – | BSD 3-Clause (IETF Trust) | © IETF Trust ve yazarları | https://www.rfc-editor.org/rfc/rfc6234 |
| AES / GCM kodu (winws.exe içinde) | – | Kamu malı / public domain | Steven M. Gibson (GRC) | https://github.com/bol-van/zapret/tree/master/nfq/crypto |

## Motor 3 – ByeDPI / ciadpi (`bin\byedpi`, yalnızca 64 bit)

| Bileşen / Component | Sürüm | Lisans | Telif / Copyright | Kaynak kod / Source |
|---|---|---|---|---|
| ByeDPI (`ciadpi.exe`) | 0.17.3 | MIT | © 2024 hufrea | https://github.com/hufrea/byedpi |
| MinGW-w64 çalışma zamanı (ciadpi.exe içinde, statik) | – | MinGW-w64 runtime lisansları (ZPL 2.1 tarzı, kamu malı ve getopt bildirimi) | © mingw-w64 projesi | https://github.com/mingw-w64/mingw-w64 |

## Notlar / Notes

- Dosyalar resmi sürüm paketlerinden alınmıştır: GoodbyeDPI `goodbyedpi-0.2.3rc3-2.zip`, zapret `zapret-v72.13.zip`, ByeDPI `byedpi-17.3-x86_64-w64.zip`. Paketlerin ve dosyaların SHA-256 özetleri `third_party/*/README.md` dosyalarında listelenmiştir ve programa gömülüdür; her başlatmada doğrulanır.
- **WinDivert ve Cygwin (LGPL):** Ayrı dosyalar (DLL ve sürücü) olarak, değiştirilmeden dağıtılırlar; kullanıcılar bunları uyumlu başka bir sürümle değiştirebilir. Karşılık gelen kaynak kodlarının yeri yukarıdaki bağlantılarda ve `licenses/LICENSE-cygwin.txt`, `licenses/LICENSE-windivert*.txt` dosyalarındadır.
- **WinDivert sürümleri:** GoodbyeDPI WinDivert 2.2.0 ile, zapret WinDivert 2.2.2-A ile gelir. İkisi de Microsoft donanım uyumluluğu imzalı ama farklı dosyalardır; bu yüzden her motor kendi klasöründeki sürücüyü kullanır ve motor değiştirilirken önceki sürücü durdurulup bırakılır.
- **GoodbyeDPI (Apache 2.0), zapret (MIT), ByeDPI (MIT):** Dosyalar değiştirilmemiştir. NSF Shield bu programları ayrı işlemler olarak, izinli parametrelerle çalıştırır.
- "GoodbyeDPI", "WinDivert", "zapret", "ByeDPI" ve "Cygwin" adları yalnızca uyumluluğu belirtmek için kullanılmıştır.
- Discord, Discord Inc.'in ticari markasıdır; NSF Shield Discord ile bağlantılı değildir.
