#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zero-Trust JIT Bitwarden Server - Version 3.0
---------------------------------------------
Akış:
1. Ajan (yerel süreç) /request_approval?item=<ad> ile tek bir sır ister.
   Sadece JIT_ALLOWED_ITEMS listesindeki kayıtlar istenebilir.
2. Daemon 30 sn geçerli tek kullanımlık bir OTP üretir ve telefona (MacroDroid) yollar.
   Telefonda görünen "çağıran süreç" bilgisi ajanın beyanı değil, daemon'un
   doğruladığı süreç adıdır.
3. Kullanıcı telefondan onaylayınca /approve?token=<OTP> çağrılır (yalnızca Tailscale IP'lerinden).
4. Daemon DPAPI ile master parolayı çözer, TEK bir WSL bash çağrısı içinde
   bw unlock -> bw get -> bw lock yapar (bash trap ile garantili kilit).
   Session key WSL dışına hiç çıkmaz.
5. Ajan /fetch?id=<request_id> ile sırrı TEK SEFER alır (30 sn içinde, bellekten).

Disk izi yok: parola/sır dosyaya yazılmaz, komut satırına konmaz, loglanmaz.
Sınırlar için README'deki "Tehdit modeli" bölümüne bakın.
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# Süreç doğrulaması için gerekli (yoksa yerel rotalar Fail-Secure reddedilir)
try:
    import psutil
except ImportError:
    psutil = None

VERSION = "3.0"
PORT = int(os.environ.get("JIT_PORT", "5050"))
# Varsayılan: sadece loopback. Telefonun erişmesi için Tailscale IP'sini ekleyin:
#   JIT_BIND=127.0.0.1,100.x.y.z
BIND_ADDRS = [a.strip() for a in os.environ.get("JIT_BIND", "127.0.0.1").split(",") if a.strip()]
OTP_VALIDITY_SECONDS = 30
RESULT_TTL_SECONDS = 30
WATCHDOG_TIMEOUT_SECONDS = 30
MAX_NOTE_LENGTH = 80

WEBHOOK_PLACEHOLDER = "https://trigger.macrodroid.com/YOUR_MACRODROID_DEVICE_ID/ajan_istek"

# Windows tarafında yerel çağrıcı olarak kabul edilen süreçler.
# UYARI: Bu liste ajanı durdurmaz (ajanlar da python/powershell kullanır). Gerçek ayrım için
# README'deki "ajanı ayrı Windows kullanıcısında / container'da çalıştır" önerisine bakın.
ALLOWED_PROCESS_NAMES = {
    "python.exe", "python3.exe", "pythonw.exe", "powershell.exe", "pwsh.exe",
    "cmd.exe", "wsl.exe", "bash.exe", "conhost.exe", "curl.exe",
}

# Uzak onay yalnızca Tailscale adres bloklarından kabul edilir (CGNAT 100.64.0.0/10)
TAILSCALE_NETWORKS = (ipaddress.ip_network("100.64.0.0/10"),)

# WSL çağrı öneki. Testlerde [] yapılır (doğrudan yerel bash).
WSL_PREFIX = ["wsl", "--exec"]

ALLOWED_FIELDS = ("password", "username", "notes")


# --------------------------------------------------------------------------- #
# Yapılandırma
# --------------------------------------------------------------------------- #
def get_macrodroid_webhook() -> str:
    url = os.environ.get("MACRODROID_WEBHOOK")
    if not url:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:
                url, _ = winreg.QueryValueEx(key, "MACRODROID_WEBHOOK")
        except Exception:
            url = None
    return url or WEBHOOK_PLACEHOLDER


def load_allowed_items(raw: str | None = None) -> dict[str, tuple[str, str]]:
    """
    JIT_ALLOWED_ITEMS="OpenAI Key,Hetzner:notes,<uuid>" -> {anahtar: (bw_item, alan)}.
    ':password|username|notes' eki istenen alanı seçer (varsayılan password).
    Liste boşsa hiçbir sır istenemez (Fail-Secure). Mümkünse ad yerine item UUID'si kullanın.
    """
    if raw is None:
        raw = os.environ.get("JIT_ALLOWED_ITEMS", "")
    items: dict[str, tuple[str, str]] = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        name, sep, field = part.rpartition(":")
        if sep and field in ALLOWED_FIELDS and name:
            items[part] = (name.strip(), field)
        else:
            items[part] = (part, "password")
    return items


def sanitize_note(note: str) -> str:
    """Telefonda gösterilecek serbest metni kısaltır ve kontrol karakterlerinden arındırır."""
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", note or "").strip()
    return cleaned[:MAX_NOTE_LENGTH]


def strip_query(text: str) -> str:
    """Log satırlarındaki ?query kısmını gizler (OTP / request id sızmasın)."""
    return re.sub(r"\?\S*", "?…", text)


# --------------------------------------------------------------------------- #
# Onay yöneticisi
# --------------------------------------------------------------------------- #
class ApprovalManager:
    """
    Tek aktif onay isteğini ve sonucunu bellekte tutar.
    - OTP telefona gider, request_id ajanda kalır; ikisi ayrı sırlardır.
    - Aktif bir istek varken yenisi kabul edilmez (OTP ezme / bildirim spamı engeli).
    - OTP tek kullanımlıktır: doğru ya da yanlış her denemede tüketilir.
    - Sonuç (sır) tek sefer okunur ve RESULT_TTL_SECONDS sonra bellekten silinir.
    """

    def __init__(self, validity_seconds=OTP_VALIDITY_SECONDS,
                 result_ttl_seconds=RESULT_TTL_SECONDS, clock=time.time):
        self.validity_seconds = validity_seconds
        self.result_ttl_seconds = result_ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._reqs: dict[str, dict] = {}

    def _purge(self, now: float):
        for rid in [rid for rid, r in self._reqs.items() if now > r["expires"]]:
            r = self._reqs.pop(rid)
            r["value"] = None

    def _has_active(self) -> bool:
        return any(r["state"] in ("waiting", "processing") for r in self._reqs.values())

    def create(self, item_key: str, caller: str, note: str = "") -> dict | None:
        """Yeni istek açar. Aktif istek varsa None döner."""
        with self._lock:
            now = self._clock()
            self._purge(now)
            if self._has_active():
                return None
            req_id = secrets.token_urlsafe(16)
            otp = secrets.token_urlsafe(16)
            self._reqs[req_id] = {
                "state": "waiting", "otp": otp, "item": item_key, "caller": caller,
                "note": note, "created_at": now, "expires": now + self.validity_seconds,
                "value": None, "error": "",
            }
            return {"request_id": req_id, "otp": otp}

    def cancel(self, req_id: str):
        with self._lock:
            self._reqs.pop(req_id, None)

    def approve(self, token: str) -> tuple[bool, str, dict]:
        """OTP'yi doğrular ve tüketir. Başarılıysa isteği 'processing' durumuna alır."""
        with self._lock:
            now = self._clock()
            self._purge(now)
            waiting = [(rid, r) for rid, r in self._reqs.items() if r["state"] == "waiting"]
            if not waiting:
                return False, "Onay bekleyen aktif bir istek yok (süresi dolmuş olabilir).", {}
            rid, r = waiting[0]
            # bytes ile karşılaştır: ASCII olmayan girdi TypeError atmasın
            valid = hmac.compare_digest(token.encode("utf-8"), r["otp"].encode("utf-8"))
            r["otp"] = None  # tek kullanımlık: başarılı da başarısız da tüketilir
            if not valid:
                self._reqs.pop(rid, None)
                return False, "Geçersiz onay kodu. İstek iptal edildi.", {}
            r["state"] = "processing"
            r["expires"] = now + 60  # kilit açma/okuma süresi için üst sınır
            return True, "Onay doğrulandı.", {
                "request_id": rid, "item": r["item"], "caller": r["caller"], "note": r["note"],
            }

    def complete(self, req_id: str, value: str | None = None, error: str = ""):
        with self._lock:
            r = self._reqs.get(req_id)
            if not r:
                return
            r["expires"] = self._clock() + self.result_ttl_seconds
            if error:
                r["state"], r["error"], r["value"] = "failed", error, None
            else:
                r["state"], r["value"] = "ready", value

    def fetch(self, req_id: str) -> tuple[str, str]:
        """('waiting'|'ready'|'failed'|'gone', içerik). 'ready' ve 'failed' tek sefer döner."""
        with self._lock:
            self._purge(self._clock())
            r = self._reqs.get(req_id)
            if not r:
                return "gone", ""
            if r["state"] in ("waiting", "processing"):
                return "waiting", ""
            self._reqs.pop(req_id, None)
            if r["state"] == "ready":
                return "ready", r["value"] or ""
            return "failed", r["error"]

    def pending_info(self) -> dict:
        """/status için: bekleyen isteğin OTP içermeyen özeti."""
        with self._lock:
            now = self._clock()
            self._purge(now)
            for r in self._reqs.values():
                if r["state"] == "waiting":
                    return {
                        "item": r["item"], "caller": r["caller"],
                        "remaining_seconds": round(max(0.0, r["expires"] - now), 1),
                    }
            return {}


approvals = ApprovalManager()
watchdog_timer: threading.Timer | None = None
watchdog_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# WSL / Bitwarden
# --------------------------------------------------------------------------- #
# Tek bir bash oturumu: unlock -> get -> lock. Kilit, EXIT/INT/TERM trap'iyle garanti edilir.
# Sırlar komut satırında değil ortam değişkenlerinde (WSLENV köprüsü) taşınır.
BW_FETCH_SCRIPT = r'''
BW="${JIT_BW_BIN:-bw}"
trap '"$BW" lock --nointeraction </dev/null >/dev/null 2>&1' EXIT INT TERM
export BW_PASSWORD="$(printf %s "$JIT_PW_B64" | base64 -d)" || exit 10
unset JIT_PW_B64
S="$("$BW" unlock --passwordenv BW_PASSWORD --raw --nointeraction </dev/null 2>/dev/null)" || exit 11
unset BW_PASSWORD
[ -n "$S" ] || exit 12
"$BW" get "$JIT_BW_FIELD" "$JIT_BW_ITEM" --session "$S" --raw --nointeraction </dev/null 2>/dev/null || exit 13
'''

BW_LOCK_SCRIPT = r'''
BW="${JIT_BW_BIN:-bw}"
"$BW" lock --nointeraction </dev/null >/dev/null 2>&1
'''

BW_EXIT_MESSAGES = {
    10: "Master parola WSL'e aktarılamadı.",
    11: "Bitwarden kilidi açılamadı (parola yanlış ya da bw giriş yapmamış).",
    12: "Bitwarden boş oturum anahtarı döndürdü.",
    13: "Kayıt okunamadı (ad/ID yanlış, birden fazla eşleşme ya da alan boş).",
}


def run_wsl_script(script: str, env_extra: dict[str, str] | None = None, timeout: int = 20):
    """
    Betiği WSL içinde `bash -s` ile çalıştırır: betik stdin'den gider (komut satırında tırnak
    sorunu yok, `ps` ile görünmez), sırlar WSLENV köprüsüyle ortam değişkeni olarak taşınır.
    """
    env_extra = dict(env_extra or {})
    env = os.environ.copy()
    env.update(env_extra)
    names = list(env_extra)
    if "JIT_BW_BIN" in env:
        names.append("JIT_BW_BIN")
    env["WSLENV"] = ":".join(f"{n}/u" for n in names)
    return subprocess.run(
        WSL_PREFIX + ["bash", "-s"], env=env, input=script, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout,
    )


def execute_bw_lock() -> bool:
    """Acil durum kilit emri: Bitwarden kasasını WSL içinde kilitler."""
    try:
        res = run_wsl_script(BW_LOCK_SCRIPT, timeout=20)
        if res.returncode == 0:
            print("[LOCK] Bitwarden kasası kilitlendi.")
            return True
        print(f"[KRITIK ALARM] bw lock başarısız! Returncode: {res.returncode}")
        return False
    except Exception as e:
        print(f"[KRITIK ALARM] bw lock çağrısı sırasında istisna: {type(e).__name__}")
        return False


def arm_watchdog(timeout_seconds=WATCHDOG_TIMEOUT_SECONDS):
    """Son çare: işlem takılırsa belirtilen sürede kasayı zorla kilitler."""
    global watchdog_timer
    with watchdog_lock:
        if watchdog_timer and watchdog_timer.is_alive():
            watchdog_timer.cancel()
        watchdog_timer = threading.Timer(timeout_seconds, execute_bw_lock)
        watchdog_timer.daemon = True
        watchdog_timer.start()


def disarm_watchdog():
    global watchdog_timer
    with watchdog_lock:
        if watchdog_timer and watchdog_timer.is_alive():
            watchdog_timer.cancel()
        watchdog_timer = None


# DPAPI parolasını çözer ve BASE64(UTF-8) olarak yazar: konsol kod sayfası (örn. cp1254)
# yüzünden ş/ğ/ı gibi karakterlerin bozulmasını önler.
PS_DECRYPT_SCRIPT = r'''
$p = $env:JIT_DPAPI_FILE
if (-not $p) { $p = Join-Path $env:USERPROFILE ".bw_master_dpapi.txt" }
if (-not (Test-Path $p)) { [Console]::Error.Write("dpapi dosyasi yok"); exit 2 }
$secure = (Get-Content -Raw $p).Trim() | ConvertTo-SecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($plain)))
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}
'''


def fetch_secret_from_vault(item: str, field: str) -> tuple[bool, str]:
    """
    DPAPI -> WSL(bw unlock -> bw get -> bw lock) zincirini çalıştırır, sırrı döndürür.
    Session key WSL dışına çıkmaz. Kasa kilitlenemezse sır atılır (Fail-Secure).
    """
    arm_watchdog(WATCHDOG_TIMEOUT_SECONDS)
    try:
        encoded = base64.b64encode(PS_DECRYPT_SCRIPT.encode("utf-16le")).decode("ascii")
        ps = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=10, stdin=subprocess.DEVNULL,
        )
        pw_b64 = ps.stdout.strip()
        if ps.returncode != 0 or not pw_b64:
            return False, "DPAPI parolası çözülemedi."

        res = run_wsl_script(
            BW_FETCH_SCRIPT,
            {"JIT_PW_B64": pw_b64, "JIT_BW_ITEM": item, "JIT_BW_FIELD": field},
            timeout=20,
        )
        del pw_b64  # Not: Python str'i bellekten güvenle silmek mümkün değil, referans bırakılır.

        value = res.stdout
        if value.endswith("\n"):
            value = value[:-1]

        # Kemer + pantolon: trap zaten kilitledi, yine de doğrula.
        if not execute_bw_lock():
            value = ""
            return False, "GÜVENLİK ALARMI: Kasa kilitlenemedi, sır atıldı."

        if res.returncode != 0:
            return False, BW_EXIT_MESSAGES.get(res.returncode, f"Bitwarden hatası (kod {res.returncode}).")
        if not value:
            return False, "Kayıt boş döndü."
        return True, value
    except subprocess.TimeoutExpired:
        execute_bw_lock()
        return False, "Kilit açma/okuma zaman aşımına uğradı."
    except Exception as e:
        execute_bw_lock()
        return False, f"İstisna: {type(e).__name__}"
    finally:
        disarm_watchdog()


# --------------------------------------------------------------------------- #
# Çağıran denetimi
# --------------------------------------------------------------------------- #
def _normalize_ip(ip: str):
    addr = ipaddress.ip_address(ip.split("%")[0])
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    return addr


def is_loopback(ip: str) -> bool:
    try:
        return _normalize_ip(ip).is_loopback
    except ValueError:
        return False


def is_tailscale_ip(ip: str) -> bool:
    try:
        addr = _normalize_ip(ip)
    except ValueError:
        return False
    return any(addr in net for net in TAILSCALE_NETWORKS if addr.version == net.version)


def inspect_caller_process(client_ip: str, client_port: int, request_path: str = "") -> tuple[bool, str, str]:
    """
    (izinli mi, mesaj, süreç adı) döndürür. Her durumda Fail-Secure.
    - Uzak istemci: yalnızca Tailscale adreslerinden ve yalnızca /approve.
    - Yerel istemci: bağlantıyı açan sürecin adı ALLOWED_PROCESS_NAMES içinde olmalı.
    """
    if not is_loopback(client_ip):
        if request_path == "/approve" and is_tailscale_ip(client_ip):
            return True, f"Tailscale istemcisi: {client_ip}", "remote"
        return False, f"Reddedildi: {client_ip} adresinden {request_path or '/'} erişimine izin yok.", ""

    if not psutil:
        return False, "Reddedildi: psutil yok (Fail-Secure).", ""
    try:
        for conn in psutil.net_connections(kind="inet"):
            if (conn.laddr and conn.laddr.port == client_port
                    and conn.raddr and conn.raddr.port == PORT and conn.pid):
                name = psutil.Process(conn.pid).name().lower()
                if name in ALLOWED_PROCESS_NAMES:
                    return True, f"Yerel süreç: {name} (PID {conn.pid})", name
                return False, f"Yetkisiz süreç reddedildi: {name} (PID {conn.pid})", name
        return False, "Reddedildi: çağıran süreç bulunamadı (Fail-Secure).", ""
    except Exception:
        return False, "Reddedildi: süreç denetimi başarısız (Fail-Secure).", ""


# --------------------------------------------------------------------------- #
# Telefon bildirimi
# --------------------------------------------------------------------------- #
def send_mobile_approval(otp: str, item: str, caller: str, note: str) -> bool:
    """OTP'yi ve bağlamı MacroDroid webhook'una yollar. (OTP üçüncü taraf sunucudan geçer!)"""
    url = get_macrodroid_webhook()
    if url == WEBHOOK_PLACEHOLDER or not url.startswith("https://"):
        print("[UYARI] MACRODROID_WEBHOOK ayarlı değil ya da https değil.")
        return False
    query = urllib.parse.urlencode({
        "otp": otp, "validity": OTP_VALIDITY_SECONDS, "item": item, "caller": caller, "note": note,
    })
    try:
        req = urllib.request.Request(f"{url}?{query}", headers={"User-Agent": f"ZeroTrust-JIT-Daemon/{VERSION}"})
        with urllib.request.urlopen(req, timeout=5) as response:
            print(f"[JIT] Telefon bildirimi iletildi (HTTP {response.getcode()}).")
            return True
    except Exception as e:
        print(f"[UYARI] Telefon bildirimi gönderilemedi: {type(e).__name__}")
        return False


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
class HardenedHTTPServer(ThreadingHTTPServer):
    """Slowloris'e karşı soket zaman aşımı korumalı sunucu."""
    daemon_threads = True

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(10.0)
        return sock, addr


class JITServerHandler(BaseHTTPRequestHandler):
    server_version = "ZeroTrustJIT"
    sys_version = ""

    def log_message(self, format, *args):
        sys.stdout.write(f"[HTTP] {self.address_string()} - {strip_query(format % args)}\n")

    # -- yardımcılar -- #
    def _send(self, code: int, body: str, ctype: str = "text/plain; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code: int, obj: dict):
        self._send(code, json.dumps(obj, ensure_ascii=False) + "\n", "application/json; charset=utf-8")

    # -- rotalar -- #
    def do_GET(self):
        parsed = urlparse(self.path)
        client_ip, client_port = self.client_address[0], self.client_address[1]

        ok, msg, proc_name = inspect_caller_process(client_ip, client_port, parsed.path)
        if not ok:
            print(f"[GÜVENLİK ENGELİ] {msg}")
            self._send(403, f"403 Forbidden: {msg}")
            return

        query = parse_qs(parsed.query)
        route = parsed.path
        if route == "/approve":
            self._route_approve(query, client_ip)
        elif route == "/request_approval":
            self._route_request_approval(query, proc_name)
        elif route == "/fetch":
            self._route_fetch(query)
        elif route == "/status":
            self._json(200, {"service": "ZeroTrust-JIT-Daemon", "version": VERSION,
                             "pending": approvals.pending_info()})
        elif route == "/lock":
            ok_lock = execute_bw_lock()
            self._send(200 if ok_lock else 500, "Kasa kilitlendi.\n" if ok_lock else "Kilitleme başarısız!\n")
        else:
            self._send(404, "404 Not Found\n")

    def _route_request_approval(self, query, proc_name: str):
        allowed = load_allowed_items()
        if not allowed:
            self._send(503, "JIT_ALLOWED_ITEMS boş: hiçbir sır istenemez.\n")
            return
        item_key = query.get("item", [""])[0]
        if item_key not in allowed:
            self._send(403, "Bu kayıt izinli listede değil.\n")
            return
        note = sanitize_note(query.get("note", [""])[0])

        created = approvals.create(item_key, caller=proc_name or "bilinmiyor", note=note)
        if created is None:
            self._send(429, "Zaten bekleyen bir onay isteği var. Süresinin dolmasını bekleyin.\n")
            return
        sent = send_mobile_approval(created["otp"], item_key, proc_name or "bilinmiyor", note)
        if not sent:
            approvals.cancel(created["request_id"])  # kimse onaylayamayacak, slotu boşalt
            self._send(502, "Telefon bildirimi gönderilemedi; istek iptal edildi.\n")
            return
        print(f"[JIT] Onay isteği: kayıt='{item_key}' çağıran='{proc_name}'")
        self._json(200, {"status": "waiting_approval", "request_id": created["request_id"],
                         "item": item_key, "validity_seconds": OTP_VALIDITY_SECONDS})

    def _route_approve(self, query, client_ip: str):
        token = query.get("token", [""])[0] or query.get("otp", [""])[0]
        valid, reason, ctx = approvals.approve(token)
        if not valid:
            print(f"[GÜVENLİK UYARISI] Onay reddedildi: {reason} (IP: {client_ip})")
            self._send(403, f"HATA: {reason}\n")
            return

        allowed = load_allowed_items()
        item_key = ctx["item"]
        if item_key not in allowed:  # liste çalışırken değiştiyse
            approvals.complete(ctx["request_id"], error="Kayıt artık izinli listede değil.")
            self._send(403, "Kayıt izinli listede değil.\n")
            return

        bw_item, field = allowed[item_key]
        print(f"[JIT] Onaylandı: kayıt='{item_key}' çağıran='{ctx['caller']}'. Kasa açılıyor...")
        success, result = fetch_secret_from_vault(bw_item, field)
        if success:
            approvals.complete(ctx["request_id"], value=result)
            self._send(200, f"Onaylandı: {item_key}. Ajan sırrı {RESULT_TTL_SECONDS} sn içinde alabilir.\n")
        else:
            approvals.complete(ctx["request_id"], error=result)
            print(f"[JIT HATA] {result}")
            self._send(500, f"Hata: {result}\n")

    def _route_fetch(self, query):
        req_id = query.get("id", [""])[0]
        state, payload = approvals.fetch(req_id)
        if state == "ready":
            self._send(200, payload)
        elif state == "waiting":
            self._json(202, {"status": "waiting"})
        elif state == "failed":
            self._json(502, {"status": "failed", "error": payload})
        else:
            self._json(404, {"status": "gone"})


def make_servers(addrs=None, port=None) -> list[HardenedHTTPServer]:
    return [HardenedHTTPServer((a, port if port is not None else PORT), JITServerHandler)
            for a in (addrs or BIND_ADDRS)]


def run_daemon():
    servers = make_servers()
    print("=" * 65)
    print(f"  Zero-Trust JIT Bitwarden Daemon V{VERSION}")
    print(f"  Dinleme            : {', '.join(f'{a}:{PORT}' for a in BIND_ADDRS)}")
    print(f"  İzinli kayıt sayısı: {len(load_allowed_items())}")
    print(f"  OTP / Sonuç süresi : {OTP_VALIDITY_SECONDS}s / {RESULT_TTL_SECONDS}s")
    print("=" * 65)
    if any(a in ("0.0.0.0", "::") for a in BIND_ADDRS):
        print("[UYARI] 0.0.0.0'a bağlısınız: servis tüm ağa açık. Tailscale IP'sine bağlamanız önerilir.")
    if not load_allowed_items():
        print("[UYARI] JIT_ALLOWED_ITEMS boş: hiçbir sır istenemez.")

    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for t in threads:
        t.start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[JIT] Kesme alındı. Kasa kilitleniyor...")
        execute_bw_lock()
        for s in servers:
            s.shutdown()
            s.server_close()
        print("[JIT] Sunucu durduruldu.")


if __name__ == "__main__":
    run_daemon()
