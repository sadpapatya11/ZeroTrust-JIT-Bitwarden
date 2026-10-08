# Mobil Onaylı JIT Bitwarden Mimarisi

Bu proje, otomatik yazılımların ve yapay zeka ajanlarının parola yönetim sistemlerine (Bitwarden) güvenli erişimini sağlamak için tasarlanmıştır. "Zero-Trust" (Sıfır Güven) prensibi üzerine kurulan bu sistem, parolaların disk üzerinde veya açık ortam değişkenlerinde (ENV) saklanmasını engeller. Erişim, donanımsal olarak şifrelenmiş bir altyapı ile başlar ve ancak fiziksel bir kullanıcı onayı (Mobil Webhook) sağlandığında saniyeler içinde yetkilendirilir.

---

## Mimari Geliştirme: Zero-File (Dosyasız) İşlem ve Bellek İçi Enjeksiyon

Projenin temel amacı, parolaların ve API anahtarlarının kalıcılığını (persistence) tamamen ortadan kaldırmaktır. Önceki iterasyonlarda karşılaşılan, verilerin Linux sanal disk alanlarına (`/dev/shm`) geçici olarak yazılması (I/O) riski bu sürümle birlikte tamamen kaldırılmıştır.

**Zero-File Süreci Nasıl İşler?**
1. Disk tabanlı hiçbir geçici dosya kullanılmaz.
2. Windows DPAPI (Data Protection API) tarafından donanımsal olarak korunan parola çözüldüğü an, veriler doğrudan bir kanal (Pipe) aracılığıyla alt sisteme (WSL) aktarılır.
3. Çapraz platform veri aktarımında oluşan karakter uyuşmazlıkları (UTF-8 BOM, CRLF) işletim sistemi seviyesinde filtrelenir (`tr -cd`).
4. Temizlenen veri, doğrudan hedeflenen Bitwarden uygulamasının izole bellek alanına (Process Environment Variable: `BW_PASSWORD`) enjekte edilir.
5. İşlem (Process) tamamlandığı an tahsis edilen bellek bloğu işletim sistemi tarafından sıfırlanır ve parola verisi fiziksel veya sanal diskte hiçbir iz bırakmadan silinir.

---

## Operasyonel İşleyiş

1. **Donanımsal Şifreleme (DPAPI):** Master parolanız standart metin dosyalarında tutulmaz; yerel Windows oturumunuza zimmetlenerek DPAPI ile kriptolanır.
2. **Yerel Dinleyici Servis (Python):** Script veya otomasyon aracı parolaya ihtiyaç duyduğunda, Python servisi mobil cihaza HTTPS üzerinden asenkron bir istek gönderir.
3. **Mobil Webhook Onayı:** Kullanıcı mobil cihazından onay vermediği sürece mimari kendini kilitli tutar (JIT - Just-In-Time yetkilendirme).
4. **Bellek İçi (In-Memory) Yürütme:** Onay alındığı an, DPAPI kilidi çözülür ve parola Zero-File mimarisi üzerinden Bitwarden'a iletilip erişim anlık olarak sağlanır.

---

## Uzaktan Erişim ve Tünelleme (Tailscale VPN)

Sistemin yalnızca yerel ağda (LAN) değil, hücresel veri (Mobil) üzerinden de güvenle yönetilebilmesi için port yönlendirme (Port Forwarding) yerine **Tailscale** kullanımı zorunludur.
- Tailscale istemcisi hem ana makineye hem de mobil cihaza kurulmalıdır.
- MacroDroid Webhook URL'si yapılandırılırken yerel IP adresi yerine, makinenin Tailscale VPN IP adresi (`100.x.x.x`) kullanılmalıdır.

### Ağ Çakışmalarının Giderilmesi (Özel DNS / AdGuard)
Android platformu birden fazla VPN/Özel DNS profilinin eşzamanlı çalışmasına izin vermez. Tailscale etkinleştirildiğinde reklam engelleyicilerin (AdGuard vb.) devre dışı kalmasını önlemek için:
1. `login.tailscale.com` yönetim paneline erişin.
2. **DNS -> Nameservers -> Custom Nameserver** bölümüne Özel DNS sağlayıcınızın IP adresini (Örn: AdGuard: `94.140.14.14`) tanımlayın.
3. **"Override local DNS"** seçeneğini etkinleştirin.
Bu konfigürasyon, güvenli JIT tünelini korurken cihaz genelindeki DNS filtrelemesinin devam etmesini sağlar.

---

## Yapay Zeka (AI) Entegrasyon Promptu

Sistemi tamamen sıfırdan yapılandırmak ve bir Yapay Zeka asistanı (Claude, Gemini, ChatGPT vb.) aracılığıyla otonom olarak kurmak için aşağıdaki komut setini (Prompt) kullanabilirsiniz:

> **[AI KURULUM PROMPTU]**
> "Merhaba. Bu repodaki 'Mobil Onaylı JIT Bitwarden' mimarisini sistemime entegre etmek istiyorum. Manuel işlem yapmak istemiyorum, tüm kurulum adımlarını sıfırdan ve otonom olarak yönetmeni talep ediyorum:
> 1. İlk olarak sistemimde WSL (Windows Subsystem for Linux) kurulu olup olmadığını denetle; kurulu değilse arka planda otomatik olarak kur.
> 2. WSL aktif edildikten sonra, Linux ortamına resmi Bitwarden CLI (`bw`) aracını kur (npm veya standalone binary ile) ve çalıştığını teyit et.
> 3. Windows DPAPI altyapısını kullanarak Bitwarden Master parolamı donanımsal olarak şifreleyecek PowerShell betiğini arka planda çalıştır ve benden güvenli terminal ekranına şifremi girmemi bekle.
> 4. DPAPI blob dosyası oluştuktan sonra, `jit_server.py` yapılandırmasını Tailscale IP adresim ve benzersiz bir güvenlik token'i ile güncelle.
> 5. Kurulumun mobil tarafı için: MacroDroid uygulamasını nasıl yapılandıracağımı, Webhook URL mantığını ve onay butonunu nasıl ekleyeceğimi bana adım adım, basit yönergeler halinde ilet.
> 6. Her şey tamamlandığında Python dinleyici servisini başlat ve uçtan uca bir test gerçekleştir. Sistem mimarisi gereği 'Zero-File (Dosyasız / In-Memory)' yapılandırmalarının korunduğundan emin ol."
