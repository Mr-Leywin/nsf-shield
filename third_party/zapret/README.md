# zapret v72.13 – winws (değiştirilmemiş)

Bu klasördeki dosyalar zapret'in resmi sürümünden **olduğu gibi** alınmıştır:

- Sürüm sayfası: https://github.com/bol-van/zapret/releases/tag/v72.13 (21.07.2026)
- Paket: `zapret-v72.13.zip` (7.959.200 bayt), SHA-256 `c493e33a0dc4eba23a8686efdaba55f59755ad6ade3564aebd9d13f4c65e2e0c`
  (GitHub'ın yayın özetiyle aynı)
- `x86_64/` → paketin `binaries/windows-x86_64/` klasöründen yalnızca `winws.exe`, `cygwin1.dll`, `WinDivert.dll`,
  `WinDivert64.sys` (ip2net, mdig, killall alınmadı). İkililerin özetleri sürümle gelen `sha256sum.txt` ile aynıdır.
- `payloads/` → paketin `files/fake/` klasöründen seçilmiş sahte TLS/QUIC/STUN/Discord paketleri. Resmi
  `sha256sum.txt` bu dosyaları listelemez; özetleri yukarıdaki doğrulanmış zip'ten alınmıştır.
- Lisanslar: `licenses/` (zapret – MIT; Cygwin DLL – LGPLv3+; WinDivert 2.2.2 – LGPLv3 / GPLv2; winws.exe içindeki
  zlib, kavl, uthash, RFC 6234 kodu ve kamu malı AES/GCM kodu)

NSF Shield bu dosyaları değiştirmez; `build.ps1` bunları paketin `bin\zapret\` klasörüne kopyalar. Özetler
`src/Core/Security.cs` içine gömülüdür ve her başlatmada doğrulanır.

## WinDivert sürümü

zapret WinDivert **2.2.2-A** ile gelir; GoodbyeDPI 0.2.3rc3 ise WinDivert **2.2.0** ile. İki sürücü de Microsoft
donanım uyumluluğu imzalıdır ama farklı dosyalardır (farklı EV sertifikaları). Bu yüzden ortak tek bir kopya yerine her
motor kendi klasöründeki sürücüyü kullanır; motor değiştirilirken önceki sürücü durdurulup bırakılır.

## SHA-256

```
a14bff1df6234ea555d2e0c61b589f0707c0b12d6c9b7eeccda76012154996e8  x86_64/winws.exe
103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b  x86_64/cygwin1.dll
c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2  x86_64/WinDivert.dll
8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2  x86_64/WinDivert64.sys
073e84935196ec6a9701e6ad0df21de2b5fbfb7e3fd3ce6c5d9bba8e8654eb14  payloads/discord-ip-discovery-with-port.bin
3f63c3a0cc63b90a6a8c50ffc61a32cc7d1f1b60457a96b90719256744df0e96  payloads/discord-ip-discovery-without-port.bin
5bacd8cb6bd451f2374e55bc066b632e3c88fb852e3a44f19e6246c04d127be5  payloads/dtls_clienthello_w3_org.bin
3e4fb49b1323ddf2f8e691b1cbe804207b4e849711d76f79ebf2b54247a9285e  payloads/http_iana_org.bin
d6504305e15e6f63930d24ced9045001e345d3c1aeb56b1b4c329d51c7dea274  payloads/quic_initial_facebook_com.bin
f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a  payloads/quic_initial_www_google_com.bin
9cd5469309780ca56c0bd97266524a48c7ee529d02c3179cfecb20b260a59641  payloads/stun.bin
9db8772636bb332f1970e8767bc7d628bfa640714bd0b7e699fbe92d559e666e  payloads/tls_clienthello_iana_org.bin
936c2bee4cfb80aa3c426b2dcbcc834b3fbcd1adb17172959dc569c73a14275c  payloads/tls_clienthello_www_google_com.bin
5341e6b2646979a70e57653007a1f310169421ec9bdd9f1a5648f75ade005af1  payloads/zero_256.bin
076a27c79e5ace2a3d47f9dd2e83e4ff6ea8872b3c2218f66c92b89b55f36560  payloads/zero_512.bin
```
