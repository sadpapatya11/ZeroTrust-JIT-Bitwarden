# Zero-Trust JIT (Just-In-Time) Bitwarden Architecture

Bu proje, Bitwarden Master Parolasını diskte veya RAM'de tutmadan, sadece API veya otomasyon anında **telefondan onay alarak (Macrodroid)** 1 saniyeliğine çözen ve anında imha eden siber güvenlik mimarisidir.

## Özellikler
- **Donanımsal Şifreleme (DPAPI):** Master parolanız hiçbir scriptte metin olarak yazmaz. Windows DPAPI ile donanım seviyesinde şifrelenir.
- **Macrodroid Hakemliği:** Kodlar çalışmak için telefonunuzdan manuel onay (Webhook) bekler.
- **1 Saniyelik Ömür (Zero-Trust):** Telefon onayı geldiğinde şifre Linux'a (WSL) Base64 olarak iletilir, kasa açılır, işlem yapılır ve oturum anında yok edilir.

## Kurulum
1. `dpapi_setup.ps1` dosyasını çalıştırarak Bitwarden Master Parolanızı güvenli kasaya ekleyin.
2. Telefonunuza Macrodroid kurun.
3. Bir Webhook tetikleyicisi oluşturun ve URL'sini `jit_server.py` içindeki `MACRODROID_WEBHOOK` değişkenine yapıştırın.
4. Macrodroid eylemi olarak `HTTP GET` seçip PC'nizin yerel IP adresini (`http://IP_ADRESINIZ:5050/approve`) girin.

## Kullanım
`python jit_server.py` çalıştırıldığında telefonunuza istek gelir. Onayladığınızda şifreniz 1 saniyeliğine açılır ve kapanır.
