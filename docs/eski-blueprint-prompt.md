# Eski Blueprint Prompt (V3.0 etiketli)

> **Güncel değil.** Bu prompt eski tasarımı anlatır: kasayı açıp hemen kilitleyen, sırrı teslim etmeyen akış, `FALLBACK_STATIC_TOKEN`, 0.0.0.0 dinleme. Güncel davranış için README ve `jit_server.py` esas alınmalıdır. Arşiv olarak saklanıyor.

## 🧠 SIFIRDAN ÜRETİM: MEGA YAPAY ZEKA BLUEPRINT PROMPTU (ZERO-SHOT PROMPT)

> **Bu Bölüm Nasıl Kullanılır?**  
> Aşağıdaki özel talimat bloğunu kopyalayıp yeni bir projede **Cursor (Composer), Claude 3.5 Sonnet, ChatGPT (GPT-4o), Windsurf (Cascade)** veya herhangi bir gelişmiş AI kodlama asistanına verdiğinizde; asistan bu mimariyi, PowerShell DPAPI betiğini, Python JIT Daemon'ını, WSL köprüsünü, Trap kilitlerini ve Regresyon Tarayıcısını tek bir seferde sıfırdan ve eksiksiz inşa eder.

```markdown
═══════════════════════════════════════════════════════════════════════════════
        ZERO-TRUST JIT BITWARDEN V3.0 - MASTER BLUEPRINT PROMPT
═══════════════════════════════════════════════════════════════════════════════
[ROL VE HEDEF]
Sen kıdemli bir Siber Güvenlik Mimarı ve Sistem Yazılım Mühendisisin. 
Görevin: Yapay zeka ajanlarının ve otomasyon süreçlerinin parola yönetim sistemlerine 
(Bitwarden) "Sıfır Güven (Zero-Trust)", "Tam Zamanında (Just-In-Time - JIT)" ve 
"Kör Yürütme (Blind Execution)" ilkeleriyle erişmesini sağlayan 
"ZeroTrust-JIT-Bitwarden V3.0" mimarisini sıfırdan eksiksiz olarak inşa etmektir.

[KATI MİMARİ VE GÜVENLİK STANDARTLARI]
1. ZERO-FILE & PURE IN-MEMORY:
   - Diske, swap'a, /dev/shm veya /tmp sanal disklerine ASLA parola veya session dosyası yazılamaz.
   - Parola akışı yalnızca bellek içi boru hattı (In-Memory stdin pipe ve WSLENV) üzerinden gerçekleşir.

2. POWERSHELL ENCODEDCOMMAND & SIFIR TIRNAK:
   - Windows tarafında DPAPI çözümü yapılırken dize kaçırma (escaping) ve tırnak hatalarını önlemek 
     için tüm PowerShell kod blokları UTF-16LE Base64 (-EncodedCommand) olarak çağrılır.
   - DPAPI bellekte çözüldükten sonra [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) 
     çağrılarak RAM anında temizlenir.

3. MICROSOFT WSLENV RESMİ DEĞİŞKEN KÖPRÜSÜ:
   - Master parola Windows'tan Linux WSL2 kabuğuna "WSLENV=BW_PASSWORD/u" çevre değişkeniyle aktarılır.
   - Komut satırı argümanı olarak geçirilmez (ps aux ile izlenemez).
   - "bw unlock --passwordenv BW_PASSWORD --raw" komutuyla tek kullanımlık oturum anahtarı alınır ve 
     alındığı an bellekten ortam değişkeni silinir (del wsl_env["BW_PASSWORD"]).

4. ÇİFT KATMANLI KİLİT TUZAĞI (DOUBLE TRAP LOCK & FAIL-SECURE):
   - Linux Alt Kabuğu: Her kilit açma işleminden hemen sonra "trap 'bw lock >/dev/null 2>&1' EXIT INT TERM" 
     protokolü ve "execute_bw_lock()" işletilerek kasa anında kilitlenir. Kasa kilitleme başarısız olursa 
     (Fail-Secure) üretilen oturum anahtarı derhal imha edilir ve işlem hata döner.
   - Windows Katmanı: Kilit açma fonksiyonu çağrıldığı anda threading.Timer(30, execute_bw_lock) ile 
     30 saniyelik zorunlu bir Watchdog kurulur; işlem takılsa dahi 30. saniyede kasa zorla kilitlenir.

5. SÜREÇ DENETİMİ (PROCESS WHITELIST):
   - Daemon'a (Port 5050) yerel ağdan gelen isteklerde bağlantı portu psutil ile taranarak çağıran 
     sürecin adı doğrulanır (python.exe, powershell.exe, cmd.exe, wsl.exe, bash.exe). Yetkisiz süreçler 403 alır.

6. CONTEXT-AWARE DİNAMİK OTP & SIFIR SABİT BYPASS:
   - Onay talebi hangi sır (secret) ve hangi işlem (action) için isteniyorsa bu bağlam bilgisi MacroDroid'e 
     aktarılır; telefonda kullanıcı neyi onayladığını açıkça görür.
   - Sabit yedek token GÜNCEL dinamik OTP olmadan tek başına kasayı ASLA açamaz.
   - Doğrulama hmac.compare_digest ile zamanlama saldırılarına karşı güvenli yapılır.
   - Tek kullanımlıktır; başarılı veya başarısız denemede anında tüketilir (Replay Attack koruması).

7. P2P TAILSCALE AĞI & MACRODROID:
   - Dışarıya internet portu açılmaz. İletişim Tailscale VPN IP'si (100.x.x.x) üzerinden yürütülür.
   - MacroDroid Webhook ile cep telefonuna interaktif onay bildirimi tetiklenir.

[ÜRETİLECEK DOSYA AĞACI VE KOD SPESİFİKASYONLARI]

1. `dpapi_setup.ps1`:
   - Kullanıcıdan Read-Host -AsSecureString ile Bitwarden master parolasını alır.
   - $securePw | ConvertFrom-SecureString ile Windows DPAPI şifrelemesi yapar.
   - Şifreli metni "$env:USERPROFILE\.bw_master_dpapi.txt" dosyasına UTF-8 olarak yazar.

2. `jit_server.py`:
   - Standart Python kütüphaneleriyle ThreadingHTTPServer (Port 5050) oluşturur (7/24 Daemon).
   - OTPManager sınıfı (Context-Aware, 30s geçerlilik, thread-safe Lock, hmac.compare_digest).
   - arm_watchdog(30) ve disarm_watchdog() mekanizmaları.
   - inspect_caller_process(client_ip, client_port, path) ile PID ve Whitelist denetimi (Fail-Secure).
   - unlock_bitwarden_in_memory(): EncodedCommand -> DPAPI çöz -> WSLENV aktar -> bw unlock -> execute_bw_lock() doğrulaması.
   - HTTP Endpointleri:
     * GET /request_approval?secret=X&action=Y: Bağlamlı 30s OTP üretir ve MacroDroid Webhook'u tetikler.
     * GET /approve?token=<OTP>: Token doğrular, geçerliyse kasayı bellek içi açıp anında mühürler.
     * GET /status: Canlılık, bekleyen OTP ve bağlam bilgisi JSON çıktısı.
     * GET /lock: Manuel acil durum "bw lock" emri.

3. `scripts/security_and_regression_scan.py`:
   - Kendi kendine çalışan otonom güvenlik tarayıcısı.
   - 1. Adım: SAST (Hardcoded secret, API key, güvensiz HTTP tespiti).
   - 2. Adım: Zero-File denetimi (/dev/shm, /tmp, .bw_tmp kalıntısı kontrolü).
   - 3. Adım: Trap ve 30s Watchdog sözdizimi doğrulaması.
   - 4. Adım: .env ve credential sızıntı taraması.
   - 5. Adım: py_compile sözdizimi testi ve OTPManager timing-attack, replay, expiry regresyon testleri.

4. `AGENT_SECURITY_PROTOCOL.md`:
   - Ajanların uymak zorunda olduğu 15 katı güvenlik kuralını içeren detaylı manifesto.
   - Secret sızıntı yasağı, .env güvensizliği, blind execution yasağı, prompt injection koruması ve fail-secure ilkeleri.

5. `.gitignore`:
   - *.log, *.txt, *.key, *.env, __pycache__, .bw_* desenlerini içermelidir.

Şimdi bu mimariyi yukarıdaki güvenlik kurallarına %100 sadık kalarak, hiçbir detayı atlamadan, 
üretime hazır (production-grade) ve hatasız olarak baştan sona oluştur!
═══════════════════════════════════════════════════════════════════════════════
```
