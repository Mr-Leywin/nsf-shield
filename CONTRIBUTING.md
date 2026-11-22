# Katkıda bulunma

Katkılarınız memnuniyetle karşılanır: hata bildirimleri, öneriler, çeviri düzeltmeleri ya da kod.

## Hata bildirme
- Önce uygulamada **Sorun Giderme → Tam kontrolü başlat**'ı deneyin.
- Uygulamadaki **Sorun bildir** düğmesi, sürüm ve hata kodu doldurulmuş bir sorun formu açar.
- **Destek paketi** eklemek çözümü hızlandırır. Pakette IP adresleri, kullanıcı adı, e-posta ve proxy bilgileri gizlenir.
- Güvenlik açıklarını herkese açık sorun olarak değil, [SECURITY.md](SECURITY.md) dosyasındaki yolla bildirin.

## Kod katkısı
1. Depoyu çatallayın (fork) ve bir dal açın.
2. Derleyin ve testleri çalıştırın (gereksinimler: README → Kaynaktan derleme):
   ```powershell
   powershell -ExecutionPolicy Bypass -File build.ps1 -Preview
   $p = Start-Process build\NSFShield.preview.exe -ArgumentList '--selftest', "$pwd\build\selftest-yeni.txt" -Wait -PassThru
   $p.ExitCode   # 0 olmalı
   ```
   Öz-test yalnızca tam, boş olmayan ve hatasız bir koşuda `0` döner (`1` başarısız kontrol, `3` istisna, `4` rapor yazılamadı, `5` boş, `6` eksik koşu, `64` çıktı dosyası verilmedi). Her koşu için yeni bir rapor dosyası adı kullanın; eski bir raporu başarı kanıtı saymayın. Arayüz değişikliklerini `build\screens` altındaki ekran görüntülerinden kontrol edin (uzun Türkçe metinler dahil). Derleme ya da paketlemeyi değiştirdiyseniz `build.ps1 -VerifyReproducible` ile EXE, ZIP ve Setup'ın iki taze imzasız derlemede aynı çıktığını doğrulayın.
3. Çekme isteği (pull request) açın. GitHub Actions derlemeyi ve testleri otomatik çalıştırır.

## Kurallar
- **Arayüz metinleri kodda değil, `locales/` içindedir:** her yeni metin hem `en.json` hem `tr.json` içine aynı anahtar ve aynı `{n}` yer tutucularıyla eklenir (öz-test denetler; kodda sabit Türkçe metin bulunmamalı).
- **Yeni dil:** `locales/en.json`'ı `locales/<kod>.json` olarak kopyalayın (UTF-8), `_meta.code`/`name`/`nativeName` alanlarını doldurun, yalnızca değerleri çevirin (anahtarlar, yer tutucular ve liste uzunlukları aynı kalır). Uygulama dosyayı çalışırken kendisi bulur, eksik anahtarlarda İngilizce'ye döner; `build.ps1` tüm `locales\*.json` dosyalarını paketler. Ayrıntı: README → Yeni bir dil ekleme.
- **Renkleri doğrudan yazmayın:** `Theme` sınıfındaki renkleri kullanın, böylece tüm temalarda doğru görünür.
- **Yeni hata durumu:** `src/Core/Errors.cs` içindeki kataloğa bir `NSF-xxx` kodu ekleyin.
- **`third_party/` klasörüne dokunmayın:** Buradaki GoodbyeDPI, Zapret ve ByeDPI dosyaları değiştirilmez. Güncellenirlerse SHA-256 listelerini (`third_party/*/README.md`) ve programa gömülü özetleri (`Integrity.Known`) birlikte güncelleyin; testler gömülü özetleri `third_party` dosyalarıyla karşılaştırır.
- **Yeni motor parametresi:** ilgili motorun izin listesine (`src/Core/Security.cs` → `ArgPolicy`, `src/Core/EnginePolicy.cs`) tam adıyla ve değer aralığıyla ekleyin.
- **Profil kodu biçimi:** `NSF1` şeması `src/Core/ProfileShare.cs` içinde belgelidir; biçimi değiştiren bir alan yeni bir sürüm numarası (`NSF2:`) ve okuyucu testleriyle birlikte eklenir.
- **Betik yorumlayıcısı yok:** Uygulama PowerShell ya da benzerini çalıştırmaz; Windows araçlarını `Sys.Run` ile System32'den çağırın.
- **Kişisel bilgi eklemeyin:** IP adresi, kullanıcı adı ya da e-posta içeren test verisi, ekran görüntüsü veya günlük eklemeyin.
