# 🛡️ Zero-Trust JIT (Just-In-Time) Bitwarden Architecture

Bu proje, yapay zeka ajanlarının (AI Agents) veya otomatik scriptlerin, şifre kasalarına (Bitwarden) **tamamen sıfır güven (Zero-Trust)** felsefesiyle ve **sadece insan onayıyla (JIT - Just-In-Time)** erişmesini sağlayan ileri seviye bir siber güvenlik mimarisidir.

API anahtarlarınızı, sunucu şifrelerinizi veya GitHub token'larınızı diskte veya ortam değişkenlerinde (ENV) tutmak yerine; bu sistem sayesinde şifreleriniz yalnızca **ihtiyaç anında 1 saniyeliğine** var olur ve işiniz biter bitmez anında imha edilir.

## 💡 Neden Bu Mimariye İhtiyaç Var? (Sorun)
Geleneksel sistemlerde scriptler veya yapay zeka ajanları API anahtarlarına ihtiyaç duyduğunda, bu anahtarlar `.env` dosyalarına yazılır veya terminalde açıkça `TOKEN=abc...` şeklinde belirtilir. 
Bu durum, kötü amaçlı bir yazılımın veya log kayıtlarının şifreleri sızdırmasına (Secret Leakage) yol açar.

## 🚀 Çözüm: "Kör Ajan" (Blind Agent) ve JIT Onay Mekanizması
Bu proje, şifreyi bilgisayarınızın herhangi bir yerinde açıkça tutmak yerine **Telefonunuzu (Macrodroid)** bir donanımsal güvenlik anahtarı (Hardware Key) olarak kullanır.

### Sistem Şöyle Çalışır:
1. **Şifre Kasası (DPAPI):** Bitwarden Master Parolanız diskte metin (plain-text) olarak saklanmaz. Windows'un donanımsal şifreleme altyapısı (DPAPI) ile şifrelenir.
2. **Nöbetçi Sunucu (Python):** Kodlarınız bir şifreye ihtiyaç duyduğunda yerel ağda bir dinleyici açar ve telefonunuza Macrodroid üzerinden sessiz bir Webhook sinyali yollar.
3. **Fiziksel Hakem Onayı (Telefon):** Telefonunuzun ekranına "Kasa açılsın mı?" uyarısı düşer. Siz "Onayla" demeden sistem sonsuza kadar kilitli kalır.
4. **1 Saniyelik Hayalet Operasyon:** Onay verdiğiniz milisaniye içinde:
   - PC şifreyi DPAPI'den çözer ve Linux (WSL) ortamına Base64 ile gizlice aktarır.
   - WSL, Bitwarden kilidini açar ve Oturum Anahtarını (Session Token) alır.
   - Scriptiniz (veya Yapay Zeka) bu anahtarı kullanarak API token'ini çeker ve işlemini yapar.
   - İşlem bittiği an (ortalama 1 saniye sonra) oturum anahtarı tamamen yok edilir.

---

## 🛠️ Kurulum Rehberi

### 1. Windows Tarafı (DPAPI Kurulumu)
Öncelikle Master Parolanızı Windows'un güvenli kasasına gömmemiz gerekiyor.
1. Projedeki `dpapi_setup.ps1` dosyasına sağ tıklayıp **"PowerShell ile Çalıştır"** deyin.
2. Açılan mavi ekrana Bitwarden Master Parolanızı girin (yazarken ekranda hiçbir şey görünmez, bu bir güvenlik önlemidir).
3. Şifreniz artık yalnızca sizin oturumunuzun çözebileceği şekilde `C:\Users\<KullanıcıAdınız>\.bw_master_dpapi.txt` dosyasına şifrelenmiş olarak kaydedildi.

### 2. Telefon Tarafı (MacroDroid Kurulumu)
Telefonunuzu bir güvenlik cihazına dönüştürüyoruz:
1. Android telefonunuza **MacroDroid** uygulamasını indirin.
2. Yeni bir Makro oluşturun.
3. **Tetikleyici (Trigger):** `Webhook (URL)` seçin. Ekranda size verilen `https://trigger.macrodroid.com/YOUR_UUID/...` şeklindeki linki kopyalayın.
4. **Eylemler (Actions):** 
   - Öncelikle bir **Onay İletişim Kutusu (Confirmation Dialog)** ekleyin (Başlık: "Ajan Onay İstiyor").
   - Ardından bir **HTTP İsteği (HTTP Request)** ekleyin. Yöntem: `GET`, URL: `http://PC_YEREL_IP_ADRESINIZ:5050/approve` (Örn: 192.168.1.x:5050).
5. Makroyu kaydedin.

### 3. Sunucuyu Ayarlama
`jit_server.py` dosyasını bir metin editörü ile açın ve şu kısmı az önce Macrodroid'den aldığınız link ile değiştirin:
```python
MACRODROID_WEBHOOK = "https://trigger.macrodroid.com/BURAYA_KENDI_LINKINIZ_GELECEK"
```

## 🎮 Kullanım / Test Etme
Terminalinizi açın ve sunucuyu başlatın:
```bash
python jit_server.py
```
* Sunucu telefonunuza tetiklemeyi gönderecek ve beklemeye geçecektir. 
* Telefonunuzdaki uyarıdan "Onayla" dediğinizde terminalde işlemin 1 saniye içinde tamamlanıp kasanın geri kapandığını görebilirsiniz!
