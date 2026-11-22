# Değişiklik günlüğü / Changelog

## [1.0.0] — İlk Sürüm (Initial Release)

**NSF Shield — by Nightshift** ilk sürümü. Windows 10/11 için GoodbyeDPI, Zapret ve ByeDPI motorlarını tek, iki dilli (Türkçe / İngilizce) bir arayüzden yöneten internet erişim kalkanı.

### Dağıtım
- **Kurulum paketi (önerilen):** `NSF-Shield-1.0.0-Setup.exe` – `Program Files\NSF Shield` klasörüne kurulur; arka plan hizmeti (`NSFShield`) ve Windows açılışında başlatma (`NSF Shield` görevi) yalnızca bu korumalı kurulumda açılır. Kurulu kopya kendini yalnızca SHA-256 ile doğrulanmış kurulum paketiyle günceller.
- **Taşınabilir ZIP:** `NSF-Shield-1.0.0.zip` – herhangi bir klasörden uygulama modunda çalışır ve kendini ZIP ile yerinde günceller (önceki sürüm `data\previous-version` klasörüne yedeklenir, paket bildirimi zorunludur). **Ayarlar → Kurulum paketine geç** ayarları koruyarak kurulumlu sürüme geçirir.
- `NSF-Shield-1.0.0.SHA256SUMS.txt` önce ZIP'in, sonra Setup'ın, ardından paketteki tüm dosyaların özetlerini listeler; yayın dosyaları GitHub Actions'ta derlenir ve derleme kaynağı kanıtıyla (build provenance) yayımlanır. Derleme tekrarlanabilirdir (`build.ps1 -VerifyReproducible`).

### Özellikler
- **Üç motor:** GoodbyeDPI 0.2.3rc3 (WinDivert; DNS yönlendirme), Zapret v72.13 `winws` (TCP, QUIC ve Discord sesi kuralları) ve sürücüsüz ByeDPI 0.17.3 `ciadpi` (127.0.0.1 üzerinde yerel SOCKS). Motor dosyaları her başlatmada gömülü SHA-256 ile doğrulanır; parametreler motorun izin listesinden geçer.
- **38 hazır profil** (GoodbyeDPI 22, Zapret 9, ByeDPI 7), **Önerilen / Uzman** katmanları ve deneme senaryosu etiketleri; **Basit / Orta / Detaylı** arayüz düzeyleri.
- **Akıllı tarayıcı:** adaylar yalıtılmış çalışır, şifreli DNS ile karşılaştırılır, HTTPS ölçümleri genel IP'ye sabitlenir ve tam sertifika denetimiyle yapılır; Discord Gateway sınırlı bir WebSocket açılışıyla denetlenir; bitince önceki durum geri gelir.
- **Site listeleri:** Dahil et (hedefli mod, üç motorda) ve Hariç tut (Zapret ve ByeDPI).
- **Salt okunur teşhis:** DPI süreçlerinin sahibi, WinDivert sürücü kayıtları, Riot Vanguard / FACEIT / EasyAntiCheat / BattlEye ve VPN/WARP ayrı bulgular olarak gösterilir; hiçbir şey kapatılmaz ya da değiştirilmez.
- **Ağ değişimi izleyicisi:** DNS çipi ve bağdaştırıcı özeti güncellenir; ağ olayı test, onarım ya da tarama başlatmaz.
- **DNS ve proxy:** Windows DNS'i ve şifreli DNS (DoH) tamamen geri alınabilir; HTTP/SOCKS5 proxy, program bazlı proxy ve yerel kimlik doğrulama köprüsü. Windows proxy'si tek bir doğrulanmış kurtarma kaydıyla korunur; elektrik kesintisinden sonra oturum açılışında yönetici istemeyen küçük bir yardımcı (`bin\NSFShieldProxyRecovery.exe`) yalnızca NSF Shield'in yazdığı değerleri geri alır.
- **Profil paylaşımı:** `NSF1:` kodları (yalnızca yöntem; boyut, XML ve izin listesi sınırlarıyla).
- **Sorun Giderme:** tam kontrol, 10 kategoride `NSF-xxx` hata kodları, tek tıkla düzeltmeler ve kişisel bilgileri gizlenmiş destek paketi.
- **Görünüm:** hazır temalar, özel palet, tepsi durum simgesi; `locales/` klasörüne dosya ekleyerek yeni dil eklenebilir.
- **Temiz kaldırma:** hizmet, açılış görevi, WinDivert kayıtları, Windows proxy'si, DNS ve DoH değişiklikleri önceki hâline döndürülür.

### English
First release of **NSF Shield — by Nightshift**: a bilingual (English / Turkish) Windows 10/11 control panel for the GoodbyeDPI, Zapret (winws) and driverless ByeDPI (ciadpi) engines. Two distributions: `NSF-Shield-1.0.0-Setup.exe` (recommended; protected install with the background service and start with Windows, updated only with the verified Setup) and the portable `NSF-Shield-1.0.0.zip` (updates itself in place; can switch to the installed version). Every release ships `NSF-Shield-1.0.0.SHA256SUMS.txt` and a GitHub build provenance attestation. Features: 38 built-in profiles in Recommended / Specialized layers, Simple / Standard / Advanced UI levels, the smart scanner with isolated candidate trials, include/exclude site lists, a read-only conflict / anti-cheat / VPN diagnosis, a network-change watcher, reversible DNS/DoH, per-program proxy and a verified Windows proxy recovery (also after a power loss, via `bin\NSFShieldProxyRecovery.exe`), `NSF1:` profile codes, `NSF-xxx` error codes, a privacy-preserving support package, themes and a clean uninstall.

> Bu yazılım MIT lisansı ile 'olduğu gibi' (AS IS) sunulur; ağ sürücüsü, DNS ve sistem proxy ayarlarında değişiklik yapar. Belirli bir İSS'de, oyunda veya hile koruma sisteminde çalışma garantisi vermez; kullanım sorumluluğu kullanıcıya aittir.
