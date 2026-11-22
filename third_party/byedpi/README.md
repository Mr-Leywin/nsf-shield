# ByeDPI 0.17.3 – ciadpi (değiştirilmemiş)

Bu klasördeki dosya ByeDPI'ın resmi sürümünden **olduğu gibi** alınmıştır:

- Sürüm sayfası: https://github.com/hufrea/byedpi/releases/tag/v0.17.3 (22.09.2025)
- Paket: `byedpi-17.3-x86_64-w64.zip` (69.809 bayt), SHA-256 `70d2c94147193cb915f9c6eb5144b8d404dacbcfa90bda2383b6b211afafa456`
  (GitHub'ın yayın özetiyle aynı)
- `x86_64/ciadpi.exe` → paketteki `ciadpi.exe` (paketteki .bat dosyaları alınmadı)
- Lisanslar: `licenses/` (ByeDPI – MIT; ciadpi.exe'ye statik bağlı MinGW-w64 çalışma zamanı bildirimleri)

ciadpi bir yerel SOCKS proxy'sidir ve **sürücü yüklemez**. NSF Shield onu her zaman yalnızca `127.0.0.1` üzerinde
dinleyecek şekilde başlatır (ciadpi'nin kendi varsayılanı `0.0.0.0`'dır). `build.ps1` dosyayı paketin `bin\byedpi\`
klasörüne kopyalar; özeti `src/Core/Security.cs` içine gömülüdür ve her başlatmada doğrulanır.

## SHA-256

```
eb53ceeeb981cc6735ac24bb1e51e725280b86630e80fdf19ddc4ee4a5b54ef4  x86_64/ciadpi.exe
```
