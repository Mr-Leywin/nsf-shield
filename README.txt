NSF SHIELD 1.0.0
================
NSF Shield — by Nightshift

DISCLAIMER: This software is provided 'as is' under the MIT License; it
changes network driver, DNS and system proxy settings. It is not guaranteed
to work with any particular ISP, game or anti-cheat system; you use it at your
own responsibility.

SORUMLULUK REDDİ: Bu yazılım MIT lisansı ile 'olduğu gibi' (AS IS) sunulur;
ağ sürücüsü, DNS ve sistem proxy ayarlarında değişiklik yapar. Belirli bir
İSS'de, oyunda veya hile koruma sisteminde çalışma garantisi vermez; kullanım
sorumluluğu kullanıcıya aittir.

English (Türkçe metin aşağıdadır)
---------------------------------

An easy interface for three DPI bypass engines: GoodbyeDPI, Zapret (winws) and
ByeDPI (ciadpi). It gets around access blocks that internet providers apply
with DNS and DPI (deep packet inspection), e.g. for Discord. It is not a VPN:
your traffic is not encrypted and your IP address does not change.

>>> The detailed guide is "Guide.html" (English and Turkish; switch the
>>> language at the top of the page). The Start menu and the app's About page
>>> open it in your language.

REQUIREMENTS
------------
- Windows 10 or Windows 11 (setup package 64-bit; portable ZIP 32/64-bit;
  Zapret and ByeDPI need 64-bit Windows)
- .NET Framework 4.8 (already installed on Windows 10/11)
- Administrator rights: the program always asks for them (its manifest says
  requireAdministrator), installed or portable. "Portable" only means that the
  folder is not protected, see below.

INSTALLATION
------------
A) SETUP PACKAGE (recommended for new installations): NSF-Shield-x.y.z-Setup.exe
   Installs to C:\Program Files\NSF Shield (only administrators can change it)
   and adds Start menu entries. The background service and "Start with
   Windows" are only available in this protected installation.

B) PORTABLE ZIP: NSF-Shield-x.y.z.zip
   Extract the whole ZIP (do not run it from inside the ZIP) and run
   NSFShield.exe. Protection runs in app mode while the app stays open (also in
   the tray). A portable copy updates itself in place with the next ZIP and
   can move to the installed version with Settings -> "Switch to the setup
   package" (your settings are kept).

If "Windows protected your PC" appears: "More info" -> "Run anyway" (the app is
not digitally signed yet).

FIRST USE
---------
1. Press "Start Protection". A green shield means protection runs.
2. "Test Discord" should show "Reachable" and a correct DNS answer.
3. Still blocked? Press "Find and Connect" (Simple level): the recommended
   methods of every available engine are tried; the first one that fully works
   in two rounds is applied.
4. Troubleshooting -> "Start the full check" lists every problem with an error code
   (e.g. NSF-204) and a fix where one exists.

ENGINES
-------
- GoodbyeDPI 0.2.3rc3: WinDivert driver; the only engine that redirects DNS.
- Zapret v72.13 (winws): its own WinDivert driver; rules for TCP, QUIC and
  Discord voice. 64-bit only.
- ByeDPI 0.17.3 (ciadpi): no driver, a local SOCKS proxy on 127.0.0.1; only
  programs that use the proxy are affected. 64-bit only, app mode only.
Site lists: "Include" works with all three engines; "Exclude" works with
Zapret and ByeDPI (GoodbyeDPI has no exclude list).

INTERFACE LEVELS (Settings or Appearance)
-----------------------------------------
- Simple   : start/stop protection, Find and Connect, the recommended profiles.
- Standard : engine tabs, expert profiles on request, DNS, site lists, network
             pages, scan scope and mode.
- Advanced : engine editors, candidate matrix, scan targets and layers, log.

SMART SCANNER
-------------
"Stop at first match" applies a result only after a full success in
two rounds; "Compare all" ranks every candidate and never applies anything by
itself. Candidates run isolated (own process, port and temporary lists); your
settings and lists are not changed and the previous state is restored.
"Gateway connection" is a short WebSocket opening to Discord's Gateway (no
login, no token); it says nothing about a Discord session, voice or games.
UDP/STUN is informational and never changes the score.

FIND PROBLEMS: CONFLICTS, ANTI-CHEAT, VPN
-----------------------------------------
Read only. DPI processes are told apart by their exact file and process id
(this app's engine, a scan candidate, another copy, or owner unknown).
WinDivert driver entries are listed with their state. Riot Vanguard (vgk),
FACEIT, EasyAntiCheat and BattlEye (BEDaisy) count as an active driver only
when Windows reports a running kernel driver; "access denied" is shown as
"could not be checked". With an active anti-cheat driver next to a WinDivert
engine, a card explains the driverless ByeDPI engine. Nothing is started,
selected or closed, and no anti-cheat compatibility is promised. A VPN adapter
that is up, a running VPN service and the route actually going through the VPN
are separate findings.

NETWORK CHANGES
---------------
When the network changes the DNS chip and the adapter summary are updated
(after 2.5 s of quiet) and, if notifications are on, a short note appears. A
network change never tests, repairs, scans, restarts an engine or writes DNS
or proxy settings. The optional connection watchdog (periodic test) and the
scans you start yourself work as before.

SHARING PROFILES
----------------
Profiles -> Share -> "Copy the profile code" gives an NSF1: code; your friend
uses "Add profile from code". A code holds only the method (no settings,
lists, paths or passwords), is size-checked and validated, and importing adds
a profile only after you confirm.

DATA FOLDER
-----------
Settings, history and logs are kept in the "data" folder next to
NSFShield.exe. Updates never change it.

UPDATES
-------
An "Update" button appears on the home page when a new version is out. The
download is verified with SHA-256 and settings are kept.
- An installed copy updates only with the verified setup package.
- A portable copy is updated in place from the ZIP; the previous version is
  backed up to data\previous-version.

ANTIVIRUS AND SMARTSCREEN
-------------------------
GoodbyeDPI and Zapret use the WinDivert driver, so some antivirus programs may
flag it as "HackTool/RiskTool". The engine files are the unmodified official
releases and are checked with embedded SHA-256 values before every start. If a
file is blocked (NSF-204): verify it ("Start the full check", or the
NSF-Shield-x.y.z.SHA256SUMS.txt file of the release), report it to the vendor
as a false positive (https://www.microsoft.com/en-us/wdsi/filesubmission), and
use an exception for the NSF Shield folder only as a last resort. ByeDPI needs
no driver.

BACKUP SCRIPTS
--------------
The .cmd files in the "scripts" folder run GoodbyeDPI without the app (one per
GoodbyeDPI method). Details: scripts\README.txt

UNINSTALLING
------------
Service, startup task, WinDivert entries of this folder, Windows proxy, DNS
and encrypted DNS settings are put back as they were:
- Installed: Settings -> Apps -> NSF Shield -> Uninstall.
- Portable: Settings -> "Clean uninstall", then delete the folder.
- Command line: NSFShield.exe --uninstall

LICENSES
--------
NSF Shield – MIT License. Copyright (c) 2026 Nightshift (Osman Barış MEDİNE)
GoodbyeDPI © ValdikSS – Apache 2.0      https://github.com/ValdikSS/GoodbyeDPI
WinDivert  © basil00  – LGPLv3          https://github.com/basil00/WinDivert
zapret     © bol-van  – MIT             https://github.com/bol-van/zapret
ByeDPI     © hufrea   – MIT             https://github.com/hufrea/byedpi
Details are in the "licenses" folder (THIRD_PARTY_NOTICES.md).


Türkçe
------

Üç DPI aşma motoru için kolay arayüz: GoodbyeDPI, Zapret (winws) ve ByeDPI
(ciadpi). Servis sağlayıcıların DNS ve DPI (Derin Paket İnceleme) ile
uyguladığı erişim engellerini (ör. Discord) aşar. VPN değildir: trafiğiniz
şifrelenmez, IP adresiniz değişmez.

>>> Ayrıntılı rehber "Guide.html" dosyasıdır (Türkçe ve İngilizce; dili
>>> sayfanın üstünden değiştirin). Başlat menüsü ve uygulamanın Hakkında
>>> sayfası onu sizin dilinizde açar.

GEREKSİNİMLER
-------------
- Windows 10 veya Windows 11 (kurulum paketi 64 bit; taşınabilir ZIP 32/64 bit;
  Zapret ve ByeDPI 64 bit Windows ister)
- .NET Framework 4.8 (Windows 10/11'de zaten yüklüdür)
- Yönetici izni: program kurulumlu da taşınabilir de olsa her zaman ister
  (manifestinde requireAdministrator vardır). "Taşınabilir" yalnızca klasörün
  korumalı olmadığı anlamına gelir, aşağıya bakın.

KURULUM
-------
A) KURULUM PAKETİ (yeni kurulumlar için önerilen): NSF-Shield-x.y.z-Setup.exe
   C:\Program Files\NSF Shield klasörüne (yalnızca yöneticiler değiştirebilir)
   kurulur ve Başlat menüsüne eklenir. Arka plan hizmeti ve "Windows açılışında
   başlat" yalnızca bu korumalı kurulumda kullanılabilir.

B) TAŞINABİLİR ZIP: NSF-Shield-x.y.z.zip
   ZIP'in tamamını ayıklayın (içinden çalıştırmayın) ve NSFShield.exe'yi
   çalıştırın. Koruma, uygulama açık (tepside de olabilir) kaldığı sürece
   uygulama modunda çalışır. Taşınabilir kopya bir sonraki ZIP ile kendini
   yerinde günceller ve Ayarlar -> "Kurulum paketine geç" ile ayarlarını
   koruyarak kurulumlu sürüme geçebilir.

"Windows bilgisayarınızı korudu" uyarısı çıkarsa: "Ek bilgi" -> "Yine de
çalıştır" (uygulama henüz dijital olarak imzalı değildir).

İLK KULLANIM
------------
1. "Korumayı Başlat"a basın. Durum simgesi yeşilse koruma çalışıyordur.
2. "Discord'u Test Et" "Erişilebilir" ve doğru DNS yanıtı göstermeli.
3. Hâlâ engelliyse "Çalışan Yöntemi Bul ve Bağlan"a basın (Basit düzey):
   kullanılabilen her motorun önerilen yöntemleri denenir; iki turda tam
   çalışan ilk yöntem uygulanır.
4. Sorun Giderme -> "Tam kontrolü başlat" bulunan her sorunu hata koduyla (ör. NSF-204)
   ve varsa düzeltme düğmesiyle listeler.

MOTORLAR
--------
- GoodbyeDPI 0.2.3rc3: WinDivert sürücüsü; DNS yönlendiren tek motor.
- Zapret v72.13 (winws): kendi WinDivert sürücüsü; TCP, QUIC ve Discord sesi
  için kurallar. Yalnızca 64 bit.
- ByeDPI 0.17.3 (ciadpi): sürücü yok, 127.0.0.1 üzerinde yerel SOCKS proxy;
  yalnızca proxy kullanan programlar etkilenir. Yalnızca 64 bit, yalnızca
  uygulama modu.
Site listeleri: "Dahil" üç motorda da çalışır; "Hariç" Zapret ve ByeDPI'da
çalışır (GoodbyeDPI'ın hariç listesi yoktur).

ARAYÜZ DÜZEYLERİ (Ayarlar ya da Görünüm)
----------------------------------------
- Basit   : korumayı başlat/durdur, Çalışan Yöntemi Bul ve Bağlan, önerilen profiller.
- Orta    : motor sekmeleri, istenirse uzman profiller, DNS, site listeleri,
            ağ sayfaları, tarama kapsamı ve modu.
- Detaylı : motor düzenleyicileri, aday matrisi, tarama hedefleri ve
            katmanları, günlük.

AKILLI TARAYICI
---------------
"İlk çalışanda dur" bir sonucu yalnızca iki turda tam başarıdan sonra uygular;
"Tümünü karşılaştır" her adayı sıralar ve hiçbir şeyi kendiliğinden
uygulamaz. Adaylar yalıtılmış çalışır (kendi süreci, portu ve geçici
listeleri); ayarlarınız ve listeleriniz değişmez, önceki durum geri gelir.
"Gateway bağlantısı" Discord Gateway'e kısa bir WebSocket açılışıdır (oturum
ya da token yok); Discord oturumu, ses ya da oyun hakkında bilgi vermez.
UDP/STUN bilgi amaçlıdır ve skoru asla değiştirmez.

SORUN BUL: ÇAKIŞMALAR, HİLE ÖNLEYİCİ, VPN
-----------------------------------------
Salt okunur. DPI süreçleri tam dosya yolu ve süreç kimliğiyle ayrılır (bu
uygulamanın motoru, tarama adayı, başka bir kopya ya da sahibi belirsiz).
WinDivert sürücü kayıtları durumlarıyla listelenir. Riot Vanguard (vgk),
FACEIT, EasyAntiCheat ve BattlEye (BEDaisy) yalnızca Windows çalışan bir
çekirdek sürücüsü bildirirse etkin sürücü sayılır; "erişim reddedildi"
"denetlenemedi" olarak gösterilir. Etkin bir hile önleyici sürücüsü ile
WinDivert motoru birlikteyse bir kart sürücüsüz ByeDPI motorunu açıklar. Hiçbir
şey başlatılmaz, seçilmez ya da kapatılmaz; hile önleyici uyumluluğu vaat
edilmez. Açık bir VPN bağdaştırıcısı, çalışan bir VPN hizmeti ve rotanın
gerçekten VPN'den geçmesi ayrı bulgulardır.

AĞ DEĞİŞİMİ
-----------
Ağ değiştiğinde DNS çipi ve bağdaştırıcı özeti (2,5 saniyelik sakinlikten
sonra) güncellenir; bildirimler açıksa kısa bir not görünür. Ağ değişimi asla
test, onarım ya da tarama başlatmaz, motoru yeniden başlatmaz, DNS ya da proxy
ayarı yazmaz. İsteğe bağlı bağlantı bekçisi (düzenli test) ve sizin
başlattığınız taramalar eskisi gibi çalışır.

PROFİL PAYLAŞIMI
----------------
Profiller -> Paylaş -> "Profil kodunu kopyala" bir NSF1: kodu verir;
arkadaşınız "Koddan profil ekle"yi kullanır. Kod yalnızca yöntemi içerir
(ayar, liste, yol ya da şifre yok), boyutu ve içeriği denetlenir; içe aktarma
yalnızca siz onaylayınca profil ekler.

VERİ KLASÖRÜ
------------
Ayarlar, geçmiş ve günlükler NSFShield.exe'nin yanındaki "data" klasöründe
tutulur. Güncellemeler bu klasörü hiç değiştirmez.

GÜNCELLEME
----------
Yeni sürüm çıkınca ana sayfada "Güncelle" düğmesi görünür. İndirilen dosya
SHA-256 ile doğrulanır ve ayarlar korunur.
- Kurulu kopya yalnızca doğrulanmış kurulum paketiyle güncellenir.
- Taşınabilir kopya ZIP ile yerinde güncellenir; önceki sürüm
  data\previous-version klasörüne yedeklenir.

ANTİVİRÜS VE SMARTSCREEN
------------------------
GoodbyeDPI ve Zapret WinDivert sürücüsünü kullanır; bu yüzden bazı antivirüsler
onu "HackTool/RiskTool" olarak işaretleyebilir. Motor dosyaları resmi
sürümlerden değiştirilmeden alınmıştır ve her başlatmadan önce gömülü SHA-256
değerleriyle denetlenir. Bir dosya engellenirse (NSF-204): doğrulayın ("Tam
kontrolü başlat" ya da sürümün NSF-Shield-x.y.z.SHA256SUMS.txt dosyası),
üreticiye yanlış pozitif olarak bildirin
(https://www.microsoft.com/en-us/wdsi/filesubmission) ve istisnayı yalnızca
son çare olarak yalnızca NSF Shield klasörü için kullanın. ByeDPI sürücü
gerektirmez.

YEDEK BETİKLER
--------------
"scripts" klasöründeki .cmd dosyaları GoodbyeDPI'ı uygulama olmadan çalıştırır
(her GoodbyeDPI yöntemi için bir tane). Ayrıntı: scripts\README.txt

KALDIRMA
--------
Hizmet, açılış görevi, bu klasöre ait WinDivert kayıtları, Windows proxy'si,
DNS ve şifreli DNS ayarları önceki hâline döndürülür:
- Kurulumlu: Ayarlar -> Uygulamalar -> NSF Shield -> Kaldır.
- Taşınabilir: Ayarlar -> "Temiz kaldır", ardından klasörü silin.
- Komut satırı: NSFShield.exe --uninstall
Program bazlı proxy için oluşturulan tarayıcı profilleri %LOCALAPPDATA%\NSF Shield
klasöründedir; isterseniz onu da silebilirsiniz.

LİSANSLAR
---------
NSF Shield – MIT Lisansı. Copyright (c) 2026 Nightshift (Osman Barış MEDİNE)
GoodbyeDPI © ValdikSS – Apache 2.0      https://github.com/ValdikSS/GoodbyeDPI
WinDivert  © basil00  – LGPLv3          https://github.com/basil00/WinDivert
zapret     © bol-van  – MIT             https://github.com/bol-van/zapret
ByeDPI     © hufrea   – MIT             https://github.com/hufrea/byedpi
Ayrıntılar "licenses" klasöründedir (THIRD_PARTY_NOTICES.md).
