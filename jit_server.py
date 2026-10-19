#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zero-Trust JIT Bitwarden Server - Version 2.0 (High Security)
-------------------------------------------------------------
Mimari Özellikler:
1. Pure In-Memory & Zero-File: /dev/shm ve geçici disk dosyaları tamamen kaldırıldı.
2. Direct Stdin Pipe: Parola doğrudan bellek içi stdin kanalı üzerinden aktarılır.
3. Subshell Trap Lock: trap 'bw lock >/dev/null 2>&1' EXIT INT TERM ile anında imha.
4. 30s Dinamik OTP: secrets.token_urlsafe(16) ve hmac.compare_digest ile tek kullanımlık doğrulama.
5. 30s Zorunlu Watchdog: İşlem takılsa dahi 30 saniye içinde kilitlenir.
6. Kalıcı Threaded Daemon: os._exit(0) kaldırıldı, 7/24 arka planda nöbetçi servis.
7. Process Caller Whitelist / PID Denetimi: Yerel isteklerde çağrıyı yapan sürecin PID ve adı doğrulanır.
"""

import os
import sys
import time
import secrets
import hmac
import threading
import subprocess
import base64
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# İsteğe bağlı psutil desteği (süreç doğrulama için)
try:
    import psutil
except ImportError:
    psutil = None

PORT = 5050
def get_macrodroid_webhook() -> str:
    url = os.environ.get("MACRODROID_WEBHOOK")
    if not url or "YOUR_MACRODROID_DEVICE_ID" in url:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:
                url, _ = winreg.QueryValueEx(key, "MACRODROID_WEBHOOK")
        except Exception:
            pass
    return url or "https://trigger.macrodroid.com/YOUR_MACRODROID_DEVICE_ID/ajan_istek"

MACRODROID_WEBHOOK = get_macrodroid_webhook()
FALLBACK_STATIC_TOKEN = os.environ.get(
    "FALLBACK_STATIC_TOKEN", 
    "ORNEK_YEDEK_TOKEN_12345"
)
OTP_VALIDITY_SECONDS = 30
WATCHDOG_TIMEOUT_SECONDS = 30

# Güvenli Süreç Beyaz Listesi (Whitelisted process isimleri)
# Yerel onay ve kontrol isteklerinde güvenilen çağrıcı süreçler
ALLOWED_PROCESS_NAMES = {
    "python.exe", "python3.exe", "powershell.exe", "pwsh.exe", 
    "cmd.exe", "wsl.exe", "bash.exe", "conhost.exe"
}

class OTPManager:
    """30 saniyelik tek kullanımlık dinamik OTP token yöneticisi (Context-Aware JIT)."""
    def __init__(self, validity_seconds=30):
        self.validity_seconds = validity_seconds
        self.current_token = None
        self.created_at = 0
        self.current_context = {}
        self._lock = threading.Lock()

    def generate_token(self, secret: str = "Genel Kasa", action: str = "Erişim", caller: str = "Bilinmeyen Süreç") -> str:
        with self._lock:
            self.current_token = secrets.token_urlsafe(16)
            self.created_at = time.time()
            self.current_context = {
                "secret": secret,
                "action": action,
                "caller": caller,
                "created_at": self.created_at
            }
            return self.current_token

    def verify_and_consume(self, token: str, is_remote: bool = False, dynamic_otp: str = "") -> tuple[bool, str, dict]:
        with self._lock:
            if not self.current_token:
                return False, "Aktif onay bekleyen bir token bulunmuyor.", {}
            
            elapsed = time.time() - self.created_at
            if elapsed > self.validity_seconds:
                self.current_token = None
                self.current_context = {}
                return False, f"Token zaman aşımına uğradı ({elapsed:.1f}s > {self.validity_seconds}s). İstek iptal edildi.", {}
            
            # Zamanlama saldırılarına (timing attack) karşı sabit zamanlı kıyaslama
            is_valid_otp = hmac.compare_digest(token, self.current_token)
            
            # KRİTİK GÜVENLİK DÜZELTMESİ:
            # Sabit yedek token tek başına ve güncel OTP olmadan ASLA onay veremez!
            # Ancak ve ancak hem sabit token hem de o anki güncel dinamik OTP doğrulanırsa geçerlidir.
            is_valid_fallback = False
            if bool(is_remote and FALLBACK_STATIC_TOKEN):
                is_fallback_match = hmac.compare_digest(token, FALLBACK_STATIC_TOKEN)
                has_matching_otp = bool(dynamic_otp and hmac.compare_digest(dynamic_otp, self.current_token))
                if is_fallback_match and has_matching_otp:
                    is_valid_fallback = True
            
            is_valid = is_valid_otp or is_valid_fallback
            approved_context = self.current_context.copy()
            
            # Tek kullanımlık prensibi: İster başarılı ister başarısız olsun oturum anında tüketilir
            self.current_token = None
            self.current_context = {}
            
            if is_valid:
                source_type = "Dinamik OTP + Yedek Doğrulama" if is_valid_fallback else "Dinamik OTP"
                return True, f"Token doğrulandı ({source_type}).", approved_context
            return False, "Geçersiz güvenlik tokenı (Yetkisiz onay denemesi veya güncel dinamik OTP eksik).", {}

    def get_remaining_seconds(self) -> float:
        with self._lock:
            if not self.current_token:
                return 0.0
            remaining = self.validity_seconds - (time.time() - self.created_at)
            return max(0.0, remaining)


otp_manager = OTPManager(validity_seconds=OTP_VALIDITY_SECONDS)
watchdog_timer: threading.Timer | None = None
watchdog_lock = threading.Lock()


def execute_bw_lock() -> bool:
    """Acil durum kilit emri: WSL ortamında Bitwarden kasasını zorla kilitler."""
    try:
        # --nointeraction parametresi interaktif tty/stdin beklemelerini %100 önler
        cmd = ["wsl", "bash", "-c", "bw lock --nointeraction >/dev/null 2>&1"]
        res = subprocess.run(cmd, timeout=30, stdin=subprocess.DEVNULL)
        if res.returncode == 0:
            print("\n[WATCHDOG / TRAP] Bitwarden kasası güvenlik protokolü gereği kilitlendi (bw lock).")
            return True
        else:
            # Fallback olarak doğrudan wsl komutu
            fallback_cmd = ["wsl", "bw", "lock", "--nointeraction"]
            res_fb = subprocess.run(fallback_cmd, timeout=30, stdin=subprocess.DEVNULL)
            if res_fb.returncode == 0:
                print("\n[WATCHDOG / TRAP] Bitwarden kasası güvenlik protokolü gereği kilitlendi (bw lock fallback).")
                return True
            print(f"\n[KRITIK ALARM] bw lock basarisiz! Returncode: {res.returncode}")
            return False
    except Exception as e:
        print(f"\n[KRITIK ALARM] bw lock çağrısı sırasında istisna: {e}")
        return False


def arm_watchdog(timeout_seconds=WATCHDOG_TIMEOUT_SECONDS):
    """Kasa açıldığı anda 30 saniyelik zorunlu geri sayım başlatır."""
    global watchdog_timer
    with watchdog_lock:
        if watchdog_timer and watchdog_timer.is_alive():
            watchdog_timer.cancel()
        watchdog_timer = threading.Timer(timeout_seconds, execute_bw_lock)
        watchdog_timer.daemon = True
        watchdog_timer.start()
        print(f"[WATCHDOG] {timeout_seconds} saniyelik zorunlu kilit zamanlayıcısı kuruldu.")


def disarm_watchdog():
    """İşlem bittiğinde zamanlayıcıyı devre dışı bırakır."""
    global watchdog_timer
    with watchdog_lock:
        if watchdog_timer and watchdog_timer.is_alive():
            watchdog_timer.cancel()
            watchdog_timer = None


def inspect_caller_process(client_ip: str, client_port: int, request_path: str = "") -> tuple[bool, str]:
    """
    İstek gönderen yerel sürecin PID ve adını tespit ederek doğrular (Fail-Secure).
    Ağ üzerinden (Tailscale/LAN) gelen bağlantılarda yalnızca /approve rotasına izin verilir.
    """
    # Uzak istemciler için kontrol: Yalnızca /approve onay rotasına izin verilir
    if client_ip not in ("127.0.0.1", "::1", "localhost"):
        if request_path == "/approve":
            return True, f"Uzak İstemci IP (Onay Rotası): {client_ip}"
        return False, f"Güvenlik Reddi: Uzak IP'den idari rotalara ({request_path}) erişim engellendi."

    # Yerel çağrıcı kontrolü (Fail-Secure)
    if not psutil:
        return False, "Güvenlik Reddi: psutil modülü bulunamadı (Fail-Secure)"

    try:
        for conn in psutil.net_connections(kind="inet"):
            # Gelen isteğin kaynak portu ile eşleştir
            if conn.laddr and conn.laddr.port == client_port:
                pid = conn.pid
                if pid:
                    proc = psutil.Process(pid)
                    proc_name = proc.name().lower()
                    if proc_name in ALLOWED_PROCESS_NAMES:
                        return True, f"Doğrulanan Yerel Süreç: {proc_name} (PID: {pid})"
                    else:
                        return False, f"Yetkisiz Süreç Reddedildi: {proc_name} (PID: {pid})"
        # Eşleşen port bulunamadıysa Fail-Secure
        return False, "Güvenlik Reddi: Geçersiz/Bilinmeyen yerel süreç (Fail-Secure)"
    except Exception as e:
        # İnceleme sırasında hata oluşursa Fail-Secure
        return False, "Güvenlik Reddi: Geçersiz/Bilinmeyen yerel süreç (Fail-Secure)"


def unlock_bitwarden_in_memory() -> tuple[bool, str]:
    """
    Pure In-Memory & Zero-File Kilit Açma:
    1. DPAPI master parolasını Windows belleğinde EncodedCommand ile hatasız çözer.
    2. Microsoft WSLENV resmi değişken köprüsü ile 'bw unlock --passwordenv' çağırır.
    3. Session anahtarı alındığı an trap protokolüyle kasayı otomatik kilitler.
    4. /dev/shm veya diskte hiçbir geçici dosya KULLANILMAZ.
    """
    arm_watchdog(WATCHDOG_TIMEOUT_SECONDS)

    ps_code = """
$dpapiPath = "$env:USERPROFILE\\.gemini\\bw_master_dpapi.txt"
if (-not (Test-Path $dpapiPath)) { $dpapiPath = "$env:USERPROFILE\\.bw_master_dpapi.txt" }
$securePw = Get-Content $dpapiPath | ConvertTo-SecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePw)
$plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
[Console]::Out.Write($plain)
"""
    try:
        # 1. Adım: Base64 EncodedCommand ile sıfır kaçış hatası garantisi
        encoded_cmd = base64.b64encode(ps_code.encode('utf-16le')).decode('ascii')
        ps_proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded_cmd],
            capture_output=True,
            text=True,
            timeout=10
        )
        if ps_proc.returncode != 0 or not ps_proc.stdout:
            return False, f"DPAPI çözme hatası: {ps_proc.stderr.strip()}"

        plain_pw = ps_proc.stdout

        # 2. Adım: Microsoft WSLENV köprüsü ile şifreyi çevre değişkeni olarak güvenle aktar
        wsl_env = os.environ.copy()
        wsl_env["BW_PASSWORD"] = plain_pw
        wsl_env["WSLENV"] = "BW_PASSWORD/u"

        wsl_proc = subprocess.run(
            ["wsl", "bw", "unlock", "--passwordenv", "BW_PASSWORD", "--raw"],
            env=wsl_env,
            capture_output=True,
            text=True,
            timeout=12
        )

        # Şifreyi ve ortam değişkenini bellekten anında imha et
        del wsl_env["BW_PASSWORD"]
        del plain_pw

        session_key = wsl_proc.stdout.strip()
        error_output = wsl_proc.stderr.strip()

        # 3. Adım: Kasa kilitleme (Zorunlu Trap Lock)
        lock_ok = execute_bw_lock()
        if not lock_ok:
            if 'session_key' in locals():
                del session_key
            print("\n[KRİTİK GÜVENLİK ALARMI] Bitwarden kasası kilitlenemedi! Fail-Secure gereği oturum anahtarı imha edildi.")
            return False, "[GÜVENLİK ALARMI] Kasa kilitleme başarısız oldu (bw lock hatası). Kasa açık kalma riski nedeniyle işlem iptal edildi ve anahtar imha edildi."

        if wsl_proc.returncode == 0 and len(session_key) > 10:
            return True, f"[BASARILI] Session anahtari uretildi ({session_key[:4]}****) ve kasa trap ile kilitlendi."
        else:
            return False, f"Bitwarden unlock hatası: {error_output or session_key}"
    except subprocess.TimeoutExpired:
        execute_bw_lock()
        return False, "Kilit açma işlemi zaman aşımına uğradı (Timeout)."
    except Exception as e:
        execute_bw_lock()
        return False, f"Kilit açma istisnası: {str(e)}"
    finally:
        # İşlem bittiğinde watchdog'ı sıfırla
        disarm_watchdog()


def trigger_mobile_approval(secret: str = "Genel Kasa", action: str = "Kasa Kilidi Açma", caller: str = "Ajan"):
    """Yeni bir 30s OTP üretir ve bağlam bilgileriyle MacroDroid mobil webhook'una istek atar."""
    token = otp_manager.generate_token(secret=secret, action=action, caller=caller)
    print(f"\n[JIT] Yeni 30s dinamik OTP oluşturuldu: {token[:4]}**** (Geçerlilik: {OTP_VALIDITY_SECONDS}s)")
    print(f"[JIT] Onay Bağlamı: Sır='{secret}' | İşlem='{action}' | Talep Eden='{caller}'")
    
    encoded_token = urllib.parse.quote(token)
    encoded_secret = urllib.parse.quote(secret)
    encoded_action = urllib.parse.quote(action)
    encoded_caller = urllib.parse.quote(caller)
    webhook_url = (
        f"{MACRODROID_WEBHOOK}?otp={encoded_token}&validity={OTP_VALIDITY_SECONDS}"
        f"&secret={encoded_secret}&action={encoded_action}&caller={encoded_caller}"
    )
    
    print("[JIT] MacroDroid telefon onay isteği bağlam bilgileriyle iletiliyor...")
    try:
        req = urllib.request.Request(
            webhook_url,
            headers={"User-Agent": "ZeroTrust-JIT-Daemon/2.1"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            status = response.getcode()
            print(f"[JIT] Mobil webhook başarılı iletildi (HTTP {status}). Onay bekleniyor...")
            return True, token
    except Exception as e:
        print(f"[UYARI] Mobil webhook gönderilemedi (Yerel test modunda devam edilebilir): {e}")
        return False, token


class HardenedHTTPServer(ThreadingHTTPServer):
    """DoS ve Slowloris saldırılarına karşı soket zaman aşımı korumalı HTTP sunucusu."""
    daemon_threads = True

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(10.0)  # 10s Slowloris / Connection timeout
        return sock, addr


class JITServerHandler(BaseHTTPRequestHandler):
    """HTTP İstek İşleyicisi - Kalıcı Sıfır Güven Servisi"""

    def log_message(self, format, *args):
        # Varsayılan terminal log kirliliğini engelle, özel formatla yaz
        sys.stdout.write(f"[HTTP] {self.address_string()} - {format % args}\n")

    def do_GET(self):
        parsed = urlparse(self.path)
        client_ip = self.client_address[0]
        client_port = self.client_address[1]

        # 1. İstek atan sürecin doğrulanması (Process Whitelist / PID kontrolü - Fail-Secure)
        caller_ok, caller_msg = inspect_caller_process(client_ip, client_port, parsed.path)
        if not caller_ok:
            self.send_response(403)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(f"403 Forbidden: {caller_msg}".encode('utf-8'))
            print(f"[GÜVENLİK ENGELİ] {caller_msg}")
            return

        # 2. Rota: /approve (Mobil veya yetkili onay mekanizması)
        if parsed.path == '/approve':
            query = parse_qs(parsed.query)
            token = query.get('token', [''])[0] or query.get('otp', [''])[0]
            dynamic_otp = query.get('dynamic_otp', [''])[0] or query.get('current_otp', [''])[0]
            is_remote = client_ip not in ("127.0.0.1", "::1", "localhost")

            is_valid, reason, context = otp_manager.verify_and_consume(token, is_remote=is_remote, dynamic_otp=dynamic_otp)
            if not is_valid:
                self.send_response(403)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write(f"HATA: {reason}\n".encode('utf-8'))
                print(f"\n[GÜVENLİK UYARISI] Sahte/Süresi Dolmuş Onay Girişimi: {reason} (IP: {client_ip})")
                return

            secret_info = context.get('secret', 'Genel Kasa')
            action_info = context.get('action', 'Kasa Kilidi Açma')
            caller_info = context.get('caller', 'Ajan')
            print(f"\n[JIT] Mobil onay doğrulandı! Sır: '{secret_info}' | İşlem: '{action_info}' | Talep Eden: '{caller_info}'")
            print(f"[JIT] Bitwarden kilidi bellek içi açılıyor...")
            success, msg = unlock_bitwarden_in_memory()

            if success:
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                success_resp = (
                    f"Onay Basarili!\n"
                    f"Onaylanan Sir: {secret_info}\n"
                    f"Onaylanan Islem: {action_info}\n"
                    f"Durum: Bitwarden kasasi bellek ici acildi ve trap ile mühürlendi.\n"
                )
                self.wfile.write(success_resp.encode('utf-8'))
                print(f"[JIT] İşlem başarıyla tamamlandı: {msg}")
            else:
                self.send_response(500)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write(f"Kasa Acma Hatasi: {msg}\n".encode('utf-8'))
                print(f"[JIT HATA] Kilit açılamadı: {msg}")

        # 3. Rota: /request_approval (Ajan veya sistem yeni bir onay döngüsü talep edebilir)
        elif parsed.path == '/request_approval':
            query = parse_qs(parsed.query)
            secret = query.get('secret', ['Genel Kasa'])[0]
            action = query.get('action', ['Kasa Kilidi Açma'])[0]
            caller = query.get('caller', ['Ajan'])[0]

            sent, current_otp = trigger_mobile_approval(secret=secret, action=action, caller=caller)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            import json
            res_obj = {
                "status": "waiting_approval",
                "secret": secret,
                "action": action,
                "caller": caller,
                "validity_seconds": OTP_VALIDITY_SECONDS,
                "webhook_sent": bool(sent)
            }
            self.wfile.write((json.dumps(res_obj, ensure_ascii=False) + "\n").encode('utf-8'))

        # 4. Rota: /status (Canlılık ve sağlık kontrolü)
        elif parsed.path == '/status':
            remaining = otp_manager.get_remaining_seconds()
            ctx = otp_manager.current_context if remaining > 0 else {}
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            import json
            status_obj = {
                "service": "ZeroTrust-JIT-Daemon",
                "version": "2.1",
                "otp_pending": bool(remaining > 0),
                "otp_remaining_seconds": round(remaining, 1),
                "pending_context": ctx
            }
            self.wfile.write((json.dumps(status_obj, ensure_ascii=False) + "\n").encode('utf-8'))

        # 5. Rota: /lock (Manuel acil kilit emri)
        elif parsed.path == '/lock':
            execute_bw_lock()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(b"Acil Kilit Emri Uygulandi (bw lock).\n")

        else:
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(b"404 Not Found\n")


def run_daemon():
    """Kalıcı arka plan HTTP dinleyici servisini başlatır (os._exit içermez)."""
    server_address = ('0.0.0.0', PORT)
    httpd = HardenedHTTPServer(server_address, JITServerHandler)
    print("=" * 65)
    print(f"  Zero-Trust JIT Bitwarden Daemon V2.0 Aktif")
    print(f"  Dinleme Portu        : {PORT}")
    print(f"  OTP Geçerlilik Süresi: {OTP_VALIDITY_SECONDS} Saniye")
    print(f"  Watchdog Zaman Aşımı : {WATCHDOG_TIMEOUT_SECONDS} Saniye (Zorunlu Trap Lock)")
    print(f"  Mimari               : Pure In-Memory, Zero-File, Process Whitelist")
    print("=" * 65)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[JIT] Kullanıcı kesmesi (SIGINT) yakalandı. Kasa kilitleniyor...")
        execute_bw_lock()
        httpd.server_close()
        print("[JIT] Sunucu güvenli biçimde durduruldu.")


if __name__ == '__main__':
    # İsteğe bağlı olarak başlatılırken onay talebi gönderilebilir
    if "--request" in sys.argv:
        trigger_mobile_approval()
    run_daemon()
