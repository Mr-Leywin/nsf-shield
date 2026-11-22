### Kurulum
- **Yeni kurulum (önerilen):** **{SETUP}** dosyasını indirip çalıştırın; Program Files'a kurulur, arka plan hizmeti ve Windows açılışında başlatma kullanılabilir. Windows uyarı verirse **Ek bilgi → Yine de çalıştır**.
- **Taşınabilir ZIP ({ZIP}):** kurulum yapmadan çalıştırmak içindir; bir klasöre çıkarıp **NSFShield.exe**'yi çalıştırın. Taşınabilir kopya kendini ZIP ile yerinde günceller ve **Ayarlar → Kurulum paketine geç** ile kurulumlu sürüme geçebilir.
- Kurulu bir kopya kendini yalnızca doğrulanmış kurulum paketiyle günceller (Ayarlar → Güncellemeler).

### Doğrulama
ZIP, Setup ve paketteki tüm dosyaların özetleri **{SUMS}** içindedir. Derleme kaynağı kanıtı: `gh attestation verify <dosya> -R {REPO}`

### Sorumluluk reddi / Disclaimer
Bu yazılım MIT lisansı ile 'olduğu gibi' (AS IS) sunulur; ağ sürücüsü, DNS ve sistem proxy ayarlarında değişiklik yapar. Belirli bir İSS'de, oyunda veya hile koruma sisteminde çalışma garantisi vermez; kullanım sorumluluğu kullanıcıya aittir.
This software is provided 'as is' under the MIT License; it changes network driver, DNS and system proxy settings. It is not guaranteed to work with any particular ISP, game or anti-cheat system; you use it at your own responsibility.
