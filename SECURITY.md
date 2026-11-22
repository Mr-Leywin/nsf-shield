# Güvenlik politikası

## Desteklenen sürümler

Güvenlik düzeltmeleri yalnızca [son sürüme](https://github.com/Mr-Leywin/nsf-shield/releases/latest) yapılır. Uygulamanın otomatik güncellemesini açık tutmanız önerilir.

## Güvenlik açığı bildirme

Bir güvenlik açığı bulduysanız lütfen **herkese açık sorun kaydı (issue) açmayın**. GitHub'ın gizli bildirim özelliğini kullanın:
**Security → Report a vulnerability** – https://github.com/Mr-Leywin/nsf-shield/security/advisories/new

Bildirime şunları eklemeniz çözümü hızlandırır: etkilenen sürüm, Windows sürümü, açığın nasıl tetiklendiği (adım adım), beklenen ve gerçekleşen davranış. Bildiriminiz en kısa sürede incelenir; düzeltme yayımlanana kadar ayrıntılar gizli tutulur.

**Kapsam dışı:**
- GoodbyeDPI, WinDivert, zapret ya da ByeDPI'ın kendisindeki açıklar: lütfen [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI), [WinDivert](https://github.com/basil00/WinDivert), [zapret](https://github.com/bol-van/zapret) ve [ByeDPI](https://github.com/hufrea/byedpi) projelerine bildirin.
- Antivirüs programlarının GoodbyeDPI/Zapret/WinDivert'i "HackTool/RiskTool" olarak işaretlemesi (bkz. README → Antivirüs, SmartScreen ve doğrulama).
- Hile önleyici sistemlerin (Vanguard, FACEIT, EasyAntiCheat, BattlEye) WinDivert'e verdiği tepkiler: NSF Shield bunları yalnızca okuyarak bildirir; uyumluluk vaat etmez.

## Güvenlik modeli

### Korumalı kurulum
- NSF Shield her zaman yönetici yetkisiyle çalışır (manifest: `requireAdministrator`), kurulumlu da taşınabilir de olsa: WinDivert sürücüsü ve Windows DNS/proxy ayarları bunu gerektirir. "Taşınabilir" yalnızca klasörün korumalı olmadığı anlamına gelir. Discord'u, rehberi ve program bazlı proxy ile açılan programları normal kullanıcı yetkisiyle (Explorer üzerinden) başlatır; yükseltilmiş bir tarayıcıya geri dönülmez.
- **SYSTEM yetkili arka plan hizmeti** ve **izin sormadan yönetici olarak açılan başlangıç görevi** yalnızca kurulum klasörü korumalıysa kullanılabilir: klasörün, alt klasörlerinin, dosyaların ve tüm üst klasörlerin yalnızca Yöneticiler, SYSTEM ve TrustedInstaller tarafından değiştirilebilmesi gerekir (kurulum paketiyle Program Files). Uygulama bu denetimi yalnızca okuyarak yapar; hiçbir izni değiştirmez.
- Taşınabilir (zip) sürüm uygulama modunda çalışır. Korumasız bir klasörü gösteren NSF Shield hizmeti ya da başlangıç görevi açılışta kaldırılır.

### Bütünlük
- Birlikte dağıtılan GoodbyeDPI 0.2.3rc3, Zapret v72.13 (winws, Cygwin DLL, WinDivert 2.2.2, 11 sahte paket) ve ByeDPI 0.17.3 dosyaları resmi sürümlerden değiştirilmeden alınmıştır (özetler: `third_party/*/README.md`). Her başlatmada (tarama adayları dahil) programa gömülü SHA-256 özetleriyle karşılaştırılır ve motor durana kadar yazmaya kapalı tutulur; uyuşmazsa motor başlatılmaz (NSF-105).
- Her motorun parametreleri kendi izin listesinden geçer: yalnızca bilinen seçenekler tam adlarıyla, değerler aralıklarıyla kabul edilir; yol, kabuk, dosya yazan ya da dinleme adresini değiştiren seçenekler ve komut satırı karakterleri reddedilir.
- **Profil kodları:** `NSF1` kodları kopyalama, Base64 çözme ve açmadan önce sınırlanır (metin 128 Ki karakter, paketli ve açılmış veri 64 KiB), DTD ve dış çözümleyici kapalı okunur, bilinmeyen/yinelenen/çelişen alanlar reddedilir ve motorun izin listesinden geçmeden gösterilmez. Kod yalnızca yöntemi taşır; ayar, yol, port, liste içeriği ya da proxy sırrı içermez. İçe aktarma onaysız hiçbir şey eklemez, motor başlatmaz, dosya yazmaz.
- **Teşhisler salt okunurdur:** çakışma, WinDivert, hile önleyici ve VPN denetimleri SCM'yi en düşük haklarla (bağlan + sorgula) ve süreçleri yalnızca sınırlı sorgu hakkıyla okur; hiçbir süreç, hizmet ya da sürücü durdurulmaz. Ağ değişimi olayı yalnızca durumu okur; test, onarım, tarama ya da DNS/proxy yazımı başlatmaz.
- Uygulama PowerShell ya da başka bir betik yorumlayıcısı çalıştırmaz. Windows araçları (`sc`, `netsh`) System32'den tam yoluyla, zaman aşımıyla çağrılır. DLL arama sırası uygulama klasörü ve System32 ile sınırlıdır.

### Güncelleme
- Yalnızca bu deponun GitHub sürümlerinden ve HTTPS üzerinden indirilir; yönlendirme sonrası varılan adres de denetlenir.
- İndirilen dosyanın SHA-256 özeti GitHub'ın bildirdiği özetle karşılaştırılır; uyuşmazsa ya da özet yoksa kurulum yapılmaz. Zip paketi doğrulandığı aynı kilitli dosyadan açılır; çalıştırılacak dosyanın özeti başlatmadan hemen önce yeniden denetlenir.
- İndirme klasörü uygulamanın kendi `data\update` klasörüdür (kurulumlu sürümde yalnızca yöneticiler yazabilir).
- Kod imzalama sertifikası alındığında güncellemenin yayıncı imzası da (Authenticode) denetlenecektir.

### Derleme ve doğrulama
- Sürümler GitHub Actions'ta derlenir. Eylemler commit SHA'sıyla, Inno Setup sürüm ve özetiyle, .NET SDK `global.json` ile sabitlenmiştir; runner etiketi GitHub'ın güncellediği değişken bir imajdır.
- Derleme tekrarlanabilirdir: CI her derlemede EXE, ZIP ve Setup'ı iki taze imzasız derlemede ayrı ayrı karşılaştırır. İmzalama açıksa zaman damgalı imzalı çıktılar bu kanıttan sonra ayrıca üretilir.
- `NSF-Shield-<sürüm>.SHA256SUMS.txt` önce ZIP'i, sonra Setup'ı, ardından paketteki tüm dosyaları listeler; derleme sırasında paket ağacı ve ZIP ile birebir doğrulanır. Öz-test, yalnızca tam ve hatasız bir koşuda `0` döner; CI çıkış kodunu ve o koşuya ait raporu denetler.
- Her sürümde `NSF-Shield-<sürüm>.SHA256SUMS.txt` ve tam olarak o sürümün ZIP, Setup ve SHA256SUMS dosyaları için GitHub derleme kaynağı kanıtı (build provenance) yayımlanır:
  ```powershell
  gh attestation verify .\NSF-Shield-<sürüm>-Setup.exe -R Mr-Leywin/nsf-shield
  ```

### Diğer
- Yerel proxy köprüsü yalnızca `127.0.0.1` adresini dinler; ağdaki diğer cihazlardan erişilemez.
- Proxy şifreleri Windows DPAPI ile yalnızca aynı Windows kullanıcısının çözebileceği şekilde saklanır.
- Destek paketi IP adreslerini, kullanıcı klasörü adını, hesap adlarını ve e-posta adreslerini gizler; kayıtlı proxy'lerin adresi, ana makine adı, adı ve kullanıcı adı ile program kurallarının adı ve yolu her metin dosyasında (günlük dâhil) "Proxy #n" / "App #n" olarak görünür. Ayar dosyası yerine yalnızca izin verilen tanı alanlarından üretilen `settings-summary.xml` içerir (proxy adı/adresi, kullanıcı adı, program yolu, ek argüman ve site listesi yok).
- Windows proxy'si değiştirilmeden önce dört değerin önceki ve yazılan hâli (var/yok bilgisiyle) tek bir kurtarma kaydına yazılıp geri okunur; hazırlanamazsa canlı ayara dokunulmaz. Geri yükleme her değer için ayrı karar verir: NSF Shield'in yazdığı değer geri alınır, kullanıcının değiştirdiği korunur. Elektrik kesintisinden sonra oturum açılışında bunu, betik barındırıcısı kullanmayan, yönetici yetkisi istemeyen (`asInvoker`) ve özeti ana programa gömülü küçük bir yardımcı (`bin\NSFShieldProxyRecovery.exe`) yapar; NSF Shield çalışıyorsa hiçbir şeyi değiştirmez.
- Kurulum paketi hedef klasörü, kendi geçici klasöründen çalıştırdığı yeni program ile denetler (fiziksel yol, bağlantı, sahip ve yazma izinleri); güvensiz ya da okunamayan bir hedefe hiçbir şey kurmaz ve oradaki programı çalıştırmaz. Kaldırmada temizleme programı yalnızca kurulumda kaydedilen SHA-256 ile aynıysa, değiştirilmeye kapalı tutulurken çalıştırılır.
- Paketler henüz kod imzalı değildir: güncelleme ve kurulum paketi başlatılmadan önce GitHub'ın yayımladığı SHA-256 (yazmaya kapalı aynı dosya tanıtıcısından) ve sürüm bilgisi denetlenir; yayımcı (Authenticode) denetimi yapılıyormuş gibi gösterilmez.
- Ayrıcalıklı işlemlerden (hizmet, yükseltilmiş başlangıç görevi, kurulu sürüme geçiş) hemen önce klasör yeniden denetlenir; bağlantı noktası (junction) ya da sembolik bağlantı içeren yollar reddedilir.
- Temiz kaldırma (`--uninstall`) hizmeti, başlangıç görevini, WinDivert kaydını, Windows proxy'sini, DNS sunucularını ve şifreli DNS kayıtlarını NSF Shield'den önceki hâline döndürür.
