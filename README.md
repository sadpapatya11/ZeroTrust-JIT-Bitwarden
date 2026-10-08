# 🛡️ Zero-Trust JIT (Just-In-Time) Bitwarden Architecture

Bu proje, yapay zeka ajanlarının (AI Agents) veya otomatik scriptlerin, şifre kasalarına (Bitwarden) **tamamen sıfır güven (Zero-Trust)** felsefesiyle ve **sadece insan onayıyla (JIT - Just-In-Time)** erişmesini sağlayan ileri seviye bir siber güvenlik mimarisidir.

API anahtarlarınızı, sunucu şifrelerinizi veya GitHub token'larınızı diskte veya ortam değişkenlerinde (ENV) tutmak yerine; bu sistem sayesinde şifreleriniz yalnızca **ihtiyaç anında milisaniyeler içinde havada (RAM'de bile değil)** var olur ve işiniz biter bitmez anında imha edilir.

---

## 💡 Eski Sorunlar ve "Hayalet Değişken" (Ghost Variable) Devrimi
İlk sürümlerde scriptler, Bitwarden'a şifreyi aktarmak için Linux'un Sanal RAM diskinde (`/dev/shm`) geçici bir dosya oluşturuyordu. Ancak siber güvenlikte "paranoyak" seviyeye ulaşmak için mimariyi tamamen değiştirdik:

**Yapılan Hata Ne İdi?**
Şifre, Windows'tan Linux'a geçerken diske (veya sanal diske) anlık bile olsa dosya olarak yazılıyordu. Bu, "Zero-Trust" kurallarını ihlal ediyordu. Ayrıca PowerShell, verinin başına görünmez UTF-8 BOM karakteri ekliyor ve Bash, şifredeki `$`, `\` gibi özel karakterleri "komut" sanıp yutuyordu.

**Yeni "Sıfır Dosya" (Zero-File) Mimarisi Nasıl Çalışır?**
Bütün dosya oluşturma mantığı çöpe atıldı! 
Windows (DPAPI) şifreyi çözdüğü an, bunu Base64 kılığında doğrudan Linux işletim sisteminin çekirdeğine (Pipe üzerinden) gönderir. Linux `tr -cd` ile çöpleri ve görünmez karakterleri temizler ve şifreyi doğrudan Bitwarden'ın mikroskobik çalışma belleğine **(Hayalet Ortam Değişkeni - BW_PASSWORD)** enjekte eder.
Yani şifreniz hiçbir zaman SSD'nizde, Harddiskinizde veya Sanal Linux RAM diskinde 1 byte bile yer kaplamaz. Yalnızca kasanın açıldığı 1 milisaniye boyunca "elektron" olarak var olur ve program kapandığında uzay boşluğuna karışarak silinir.

---

## 🚀 Sistem Şöyle Çalışır:
1. **Şifre Kasası (DPAPI):** Bitwarden Master Parolanız diskte metin olarak saklanmaz. Windows'un donanımsal şifreleme altyapısı (DPAPI) ile kilitlenerek saklanır.
2. **Nöbetçi Sunucu (Python):** Kodlarınız bir şifreye ihtiyaç duyduğunda yerel ağda dinleyici açar ve telefonunuza Macrodroid üzerinden sessiz bir Webhook sinyali yollar.
3. **Fiziksel Hakem Onayı (Telefon):** Ekranınıza "Kasa açılsın mı?" uyarısı düşer. Siz "Onayla" demeden sistem kilitli kalır.
4. **Milisaniyelik Hayalet Operasyon:** Onay verdiğiniz an PC şifreyi çözer, sıfır dosya mimarisiyle (BW_PASSWORD) Bitwarden'a fısıldar, token'i alır ve işlemi milisaniyeler içinde kapatır.

---

## 🌍 Mobil Veri & Uzaktan Erişim (Tailscale)
Eğer dışarıdayken (Mobil Veri) bilgisayarınıza onay göndermek isterseniz, güvenlik sebebiyle modeminizden Port Açmak (Port Forwarding) **kesinlikle önerilmez**. Bunun yerine **Tailscale (VPN)** kullanmalısınız.
- PC ve telefonunuza Tailscale kurun.
- Macrodroid'deki URL'ye, PC'nizin `192.168...` olan yerel IP'si yerine, Tailscale IP'sini (`100.x.x.x`) yazın. 

## 🛑 Özel DNS (Reklam Engelleyici) ve VPN Çakışmasını Çözme
Android sistemler aynı anda birden fazla VPN/Özel DNS çalışmasına izin vermez. Tailscale'i açtığınızda AdGuard devre dışı kalabilir. 
**Çözüm (Tailscale İçine DNS Gömmek):**
1. `login.tailscale.com` adresine girin ve **DNS** sekmesini açın.
2. **Nameservers -> Custom Nameserver** kısmına Reklam Engelleyici IP'nizi girin (Örn. AdGuard: `94.140.14.14`).
3. **"Override local DNS"** butonunu aktif edin.
*Bu sayede Tailscale bağlıyken hem reklamlar engellenir, hem de PC'nizle olan gizli bağlantınız kesintisiz çalışır.*

---

## 🤖 Arkadaşın İçin: Yapay Zeka Kurulum Promptu
Bu projeyi bir arkadaşına önermek istiyorsan, arkadaşının manuel kodlamayla uğraşmasına gerek yok. Arkadaşının kullanacağı Yapay Zekaya (Claude, Gemini, ChatGPT) aşağıdaki "Prompt" metnini kopyalayıp yapıştırması yeterlidir. Ajan tüm kurulumu otonom olarak devralacaktır:

> **[YAPAY ZEKAYA KOPYALANACAK PROMPT]**
> "Merhaba Yapay Zeka. Ben, arkadaşımın bana gönderdiği 'Zero-Trust JIT Bitwarden' mimarisini bilgisayarıma kurmak istiyorum. Benim manuel olarak kod dosyalarıyla, repo okumakla veya PowerShell komutlarıyla uğraşmamı istemiyorum. Tüm süreci sen devralacaksın.
> 1. İlk olarak arka planda benim için Bitwarden Master parolamı DPAPI ile donanımsal olarak şifreleyecek PowerShell komutunu (`ConvertTo-SecureString` mantığıyla) çalıştır ve benden şifremi güvenli ekrana girmemi bekle.
> 2. DPAPI dosyası oluştuktan sonra, repodaki `jit_server.py` dosyasını benim Tailscale IP'me ve beraber belirleyeceğimiz gizli bir şifreye (Token) göre düzenle.
> 3. Telefonuma indireceğim Macrodroid uygulamasında tam olarak nereye hangi URL'yi gireceğimi bana çok basit, teknik olmayan bir dille, adım adım anlat.
> 4. Kurulum bitince arka planda Python sunucusunu çalıştır ve ilk füzeyi (testi) ateşle. Olası PowerShell BOM veya escape hatalarına karşı 'Sıfır Dosya (Hayalet Ortam Değişkeni)' kullandığımızı unutma. Her şeyi otonom olarak yönet."
