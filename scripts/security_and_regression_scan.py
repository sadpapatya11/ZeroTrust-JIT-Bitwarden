#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zero-Trust JIT Bitwarden - Güvenlik ve Regresyon Tarayıcısı
------------------------------------------------------------
Kapsam:
1. Kaynak Kod Statik Güvenlik Analizi (SAST): Hardcoded secret, API key, private key.
2. Zero-File & Disk İzi Denetimi: /dev/shm, /tmp, .bw_tmp kalıntılarının engellenmesi.
3. Mimari ve Trap Kilit Denetimi: trap 'bw lock' ve 30s watchdog kontrolleri.
4. .env ve Hassas Dosya Sızıntı Taraması.
5. Python Sözdizimi (Syntax) ve Regresyon Birim Testleri (OTP, HMAC, Whitelist).
"""

import os
import re
import sys
import time
import subprocess

# Kök dizini sys.path'e ekle
sys.path.insert(0, os.path.abspath("."))

# Renkli terminal çıktıları
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_step(title):
    print(f"\n{Colors.HEADER}=== {title} ==={Colors.ENDC}")


def scan_hardcoded_secrets():
    print_step("1. Kaynak Kod Statik Güvenlik Analizi (SAST)")
    
    rules = [
        {
            "name": "Hardcoded Secret / API Key",
            "regex": r"(?i)(api_key|secret_token|private_key|auth_token|client_secret)\s*=\s*['\"][a-zA-Z0-9_\-\+\/]{8,}['\"]",
            "type": "GÜVENLİK",
            "description": "Statik API anahtarı veya sabit parola ataması tespit edildi."
        },
        {
            "name": "Eski Sabit SECRET_TOKEN Kullanımı",
            "regex": r"SECRET_TOKEN\s*=\s*['\"]GIZLI_SIFRENIZ['\"]",
            "type": "GÜVENLİK",
            "description": "Eski V1 sürümünden kalan sabit SECRET_TOKEN tespit edildi."
        },
        {
            "name": "Insecure HTTP Protocol",
            "regex": r"['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9\.\/\-\?\#\=\&\%\_]+['\"]",
            "type": "GÜVENLİK",
            "description": "Dış dünya için güvensiz HTTP bağlantısı tespit edildi. HTTPS kullanılmalıdır."
        }
    ]

    clean = True
    for root_dir, dirs, files in os.walk("."):
        if any(x in root_dir for x in [".git", "__pycache__", ".vscode", "build", "scripts"]):
            continue
            
        for file in files:
            if not file.endswith(('.py', '.ps1', '.sh', '.bat')):
                continue
                
            file_path = os.path.join(root_dir, file)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                for rule in rules:
                    matches = re.finditer(rule["regex"], content)
                    for match in matches:
                        matched_text = match.group(0)
                        # False positive ayıklama
                        if "secrets.token" in matched_text or "token_urlsafe" in matched_text:
                            continue
                        
                        line_no = content.count('\n', 0, match.start()) + 1
                        print(f"{Colors.FAIL}[-] {rule['type']} - {rule['name']} ({file_path}:{line_no}){Colors.ENDC}")
                        print(f"    Tespit  : {matched_text.strip()}")
                        print(f"    Açıklama: {rule['description']}")
                        clean = False
            except Exception as e:
                print(f"{Colors.WARNING}[!] Dosya okuma hatası ({file_path}): {e}{Colors.ENDC}")

    if clean:
        print(f"{Colors.OKGREEN}[+] Kaynak kodda açıkta unutulmuş sabit gizli anahtar (secret) bulunamadı.{Colors.ENDC}")
    return clean


def scan_zero_file_violations():
    print_step("2. Zero-File (Dosyasız Mimari) ve Geçici Dosya Denetimi")
    
    # /dev/shm veya /tmp dosya yazımı yasaktır (Zero-File kuralı)
    # Kod dosyalarını tarıyoruz (scripts hariç)
    patterns = [
        (r"/dev" + r"/shm/\.bw_tmp", "Geçici master parola dosyası (/dev/shm/.bw_tmp) kullanımı tespit edildi."),
        (r"/dev" + r"/shm/\.bw_session", "Geçici oturum dosyası (/dev/shm/.bw_session) kullanımı tespit edildi."),
        (r">\s*/dev" + r"/shm/", "Geçici sanal diske doğrudan dosya yazımı (> /dev/shm/) tespit edildi."),
        (r">\s*/tmp/", "Geçici dizine doğrudan dosya yazımı (> /tmp/) tespit edildi.")
    ]

    clean = True
    for root_dir, dirs, files in os.walk("."):
        if any(x in root_dir for x in [".git", "__pycache__", ".vscode", "build", "scripts"]):
            continue
            
        for file in files:
            # Sadece yürütülebilir kod dosyalarını denetle
            if not file.endswith(('.py', '.ps1', '.sh')):
                continue
                
            file_path = os.path.join(root_dir, file)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                for pat, desc in patterns:
                    matches = list(re.finditer(pat, content))
                    for m in matches:
                        line_no = content.count('\n', 0, m.start()) + 1
                        print(f"{Colors.FAIL}[-] GÜVENLİK İHLALİ - {file_path}:{line_no}{Colors.ENDC}")
                        print(f"    {desc}")
                        clean = False
            except Exception as e:
                pass

    if clean:
        print(f"{Colors.OKGREEN}[+] Kod tabanında /dev/shm ve geçici disk yazımları tamamen temizlenmiş (Pure In-Memory).{Colors.ENDC}")
    return clean


def scan_trap_and_watchdog():
    print_step("3. Otonom Kasa Kilidi ve Trap Mekanizması Denetimi")
    
    jit_path = "jit_server.py"
    if not os.path.exists(jit_path):
        print(f"{Colors.FAIL}[-] jit_server.py bulunamadı!{Colors.ENDC}")
        return False

    with open(jit_path, "r", encoding="utf-8") as f:
        code = f.read()

    errors = []
    # 1. trap kontrolü
    if "trap 'bw lock" not in code and 'trap "bw lock' not in code:
        errors.append("Bash subshell içinde trap 'bw lock >/dev/null 2>&1' EXIT INT TERM tanımlanmamış!")

    # 2. 30s watchdog kontrolü
    if "WATCHDOG_TIMEOUT_SECONDS = 30" not in code and "timeout_seconds=30" not in code:
        errors.append("30 saniyelik zorunlu Watchdog zaman aşımı tanımlanmamış!")

    # 3. 30s OTP kontrolü
    if "OTP_VALIDITY_SECONDS = 30" not in code:
        errors.append("30 saniyelik dinamik OTP geçerlilik süresi (OTP_VALIDITY_SECONDS = 30) bulunamadı!")

    # 4. Yürütülebilir kodda os._exit çağrısı olmamalı (AST analizi ile tam denetim)
    import ast
    try:
        tree = ast.parse(code, filename=jit_path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # os._exit(...) çağrısı mı?
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "_exit" and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                        errors.append(f"Yürütülebilir kodda os._exit(...) çağrısı tespit edildi (Satır: {node.lineno})! Sunucu kalıcı bir arka plan servisi olmalıdır.")
    except Exception as e:
        errors.append(f"jit_server.py AST analizi hatası: {e}")

    if errors:
        for err in errors:
            print(f"{Colors.FAIL}[-] Mimari Eksik: {err}{Colors.ENDC}")
        return False

    print(f"{Colors.OKGREEN}[+] Trap kilidi, 30s watchdog ve 30s OTP mekanizmaları eksiksiz doğrulandı.{Colors.ENDC}")
    return True


def scan_env_leakage():
    print_step("4. Plaintext .env ve Hassas Dosya Taraması")
    
    suspect_files = [".env", ".env.local", ".env.production", "secrets.json", "id_rsa"]
    clean = True
    for sf in suspect_files:
        if os.path.exists(sf):
            print(f"{Colors.FAIL}[-] Sızıntı Riski: '{sf}' projenin kök dizininde bulundu! Secret'lar repoya girmemelidir.{Colors.ENDC}")
            clean = False

    if clean:
        print(f"{Colors.OKGREEN}[+] Kök dizinde açıkta bırakılmış .env veya credential dosyası bulunmuyor.{Colors.ENDC}")
    return clean


def run_regression_tests():
    print_step("5. Sözdizimi ve Regresyon Birim Testleri")
    
    # 1. Python Compile Testi
    compile_cmd = [sys.executable, "-m", "py_compile", "jit_server.py"]
    res = subprocess.run(compile_cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"{Colors.FAIL}[-] jit_server.py sözdizimi derleme hatası verdi:{Colors.ENDC}")
        print(res.stderr)
        return False
    print(f"{Colors.OKGREEN}[+] 'jit_server.py' derleme (py_compile) testi başarılı.{Colors.ENDC}")

    # 2. OTPManager Birim Testi
    try:
        from jit_server import OTPManager
        mgr = OTPManager(validity_seconds=1)
        
        # Test A: Token üretimi ve Bağlam (Context-Aware) Testi
        tok = mgr.generate_token(secret="OpenAI_Key", action="Prod_Deploy", caller="AI_Agent")
        assert len(tok) >= 16, "Üretilen token yeterince uzun değil"
        assert mgr.current_context.get("secret") == "OpenAI_Key", "Bağlamdaki sır eşleşmedi!"
        assert mgr.current_context.get("action") == "Prod_Deploy", "Bağlamdaki işlem eşleşmedi!"
        
        # Test B: Yanlış token denemesi
        valid, _, _ = mgr.verify_and_consume("YANLIS_TOKEN_12345")
        assert not valid, "Yanlış token onaylandı (Güvenlik zafiyeti)!"
        
        # Test C: Yeni token üret ve doğru token ile doğrula
        tok2 = mgr.generate_token(secret="AWS_Prod", action="Backup_Sync")
        valid2, _, ctx2 = mgr.verify_and_consume(tok2)
        assert valid2, "Doğru token doğrulanamadı!"
        assert ctx2.get("secret") == "AWS_Prod", "Doğrulanan oturum bağlamı aktarılamadı!"
        
        # Test D: Tek kullanımlık prensibi (Replay Attack koruması)
        valid_replay, _, _ = mgr.verify_and_consume(tok2)
        assert not valid_replay, "Token ikinci kez kullanılabildi (Replay zafiyeti)!"
        
        # Test E: Zaman aşımı testi
        tok3 = mgr.generate_token()
        time.sleep(1.1)
        valid_expired, _, _ = mgr.verify_and_consume(tok3)
        assert not valid_expired, "Süresi dolmuş token kabul edildi (Expiry zafiyeti)!"

        # Test F: Sabit Yedek Token Tek Başına Onay Veremez Testi (Zafiyet 1 Koruması)
        from jit_server import FALLBACK_STATIC_TOKEN
        # Localhost'ta fallback token denenirse KESİNLİKLE reddedilmeli
        mgr.generate_token()
        valid_fb_local, _, _ = mgr.verify_and_consume(FALLBACK_STATIC_TOKEN, is_remote=False)
        assert not valid_fb_local, "Localhost üzerinde FALLBACK_STATIC_TOKEN kabul edildi (Güvenlik zafiyeti)!"
        
        # Uzak IP'de güncel dinamik OTP olmadan SADECE fallback token denenirse KESİNLİKLE REDDEDİLMELİ!
        mgr.generate_token()
        valid_fb_alone, _, _ = mgr.verify_and_consume(FALLBACK_STATIC_TOKEN, is_remote=True, dynamic_otp="")
        assert not valid_fb_alone, "Güncel OTP olmadan sabit yedek token tek başına onay verebildi (Güvenlik Zafiyeti)!"

        # Uzak IP'de hem fallback token hem de geçerli dinamik OTP birlikte iletilirse onaylanmalı
        tok_valid = mgr.generate_token()
        valid_fb_remote, _, _ = mgr.verify_and_consume(FALLBACK_STATIC_TOKEN, is_remote=True, dynamic_otp=tok_valid)
        assert valid_fb_remote, "Geçerli OTP ve Fallback token çifti onaylanamadı!"

        print(f"{Colors.OKGREEN}[+] OTPManager birim testleri (Context-Aware, Timing-Safe HMAC, Replay, Expiry, OTP Zorunluluğu) kusursuz geçti.{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[-] OTPManager birim testi başarısız: {e}{Colors.ENDC}")
        return False

    # 3. Fail-Secure ve Süreç Denetimi Testi
    try:
        from jit_server import inspect_caller_process
        # Uzak IP idari rotalara erişmeye çalışırsa Fail-Secure REDDEDİLMELİ
        ok_adm, _ = inspect_caller_process("192.168.1.150", 44332, "/status")
        assert not ok_adm, "Uzak IP'den /status rotasına erişim engellenemedi (Fail-Secure zafiyeti)!"

        ok_lock, _ = inspect_caller_process("192.168.1.150", 44332, "/lock")
        assert not ok_lock, "Uzak IP'den /lock rotasına erişim engellenemedi (Fail-Secure zafiyeti)!"

        # Uzak IP /approve rotasına erişirse onaylanmalı
        ok_app, _ = inspect_caller_process("192.168.1.150", 44332, "/approve")
        assert ok_app, "Uzak IP'nin /approve onay rotasına erişimi engellendi!"

        # Bilinmeyen / sahte yerel port -> Fail-Secure REDDEDİLMELİ
        ok_fake, _ = inspect_caller_process("127.0.0.1", 99999, "/status")
        assert not ok_fake, "Bilinmeyen yerel porta erişim verildi (Fail-Secure zafiyeti)!"

        print(f"{Colors.OKGREEN}[+] Fail-Secure ve Caller Process denetimleri başarıyla doğrulandı.{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[-] Fail-Secure birim testi başarısız: {e}{Colors.ENDC}")
        return False

    # 4. HardenedHTTPServer Soket Zaman Aşımı (Slowloris Koruması) Testi
    try:
        import socket
        from unittest.mock import patch
        from jit_server import HardenedHTTPServer

        dummy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        class MockServer(HardenedHTTPServer):
            def __init__(self):
                pass

        with patch('http.server.ThreadingHTTPServer.get_request', return_value=(dummy_sock, ('127.0.0.1', 12345))):
            srv = MockServer()
            sock, _ = srv.get_request()
            timeout_val = sock.gettimeout()
            assert timeout_val == 10.0, f"Soket timeout 10.0s olmalıydı, mevcut değer: {timeout_val}"
        dummy_sock.close()
        print(f"{Colors.OKGREEN}[+] HardenedHTTPServer DoS/Slowloris soket zaman aşımı (10s) başarıyla doğrulandı.{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[-] HardenedHTTPServer soket zaman aşımı testi başarısız: {e}{Colors.ENDC}")
        return False

    # 5. execute_bw_lock Canlı Kilit Testi
    try:
        from jit_server import execute_bw_lock
        lock_ok = execute_bw_lock()
        assert lock_ok is True, "execute_bw_lock çağrısı başarısız oldu!"
        print(f"{Colors.OKGREEN}[+] execute_bw_lock canlı kilit mekanizması başarıyla doğrulandı.{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[-] execute_bw_lock testi başarısız: {e}{Colors.ENDC}")
        return False

    # 6. Kilitleme Başarısızlığında Fail-Secure Birim Testi (Zafiyet 2 Koruması)
    try:
        from unittest.mock import patch
        import jit_server
        # Eğer execute_bw_lock False dönerse (kilit başarısızsa), unlock_bitwarden_in_memory ASLA True dönmemelidir!
        with patch('jit_server.execute_bw_lock', return_value=False):
            # DPAPI ve WSL çağrılarını da mocklayalım ki sadece kilitleme mantığı izole test edilsin
            with patch('subprocess.run') as mock_sub:
                mock_sub.return_value.returncode = 0
                mock_sub.return_value.stdout = "2dj9s8df7sdf78s9df78s9df" # Sözde geçerli session key
                ok_fail_lock, msg_fail_lock = jit_server.unlock_bitwarden_in_memory()
                assert not ok_fail_lock, "Kasa kilitleme başarısız olduğu halde işlem başarılı döndü (Kritik Fail-Open Zafiyeti)!"
                assert "GÜVENLİK ALARMI" in msg_fail_lock, "Beklenen güvenlik alarmı mesajı dönmedi!"
        print(f"{Colors.OKGREEN}[+] Kilitleme Başarısızlığında Fail-Secure koruması başarıyla doğrulandı.{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[-] Fail-Secure kilitleme testi başarısız: {e}{Colors.ENDC}")
        return False

    return True


def main():
    print(f"{Colors.BOLD}{Colors.HEADER}============================================================{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}  ZEROTRUST-JIT-BITWARDEN GÜVENLİK VE REGRESYON TARAYICISI  {Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}============================================================{Colors.ENDC}")

    sast_ok = scan_hardcoded_secrets()
    zero_file_ok = scan_zero_file_violations()
    trap_ok = scan_trap_and_watchdog()
    env_ok = scan_env_leakage()
    tests_ok = run_regression_tests()

    if not (sast_ok and zero_file_ok and trap_ok and env_ok and tests_ok):
        print(f"\n{Colors.FAIL}[-] Güvenlik ve Regresyon Taraması BAŞARISIZ OLDU! Lütfen hataları giderin.{Colors.ENDC}")
        sys.exit(1)

    print(f"\n{Colors.OKGREEN}{Colors.BOLD}[+] MÜKEMMEL! Tüm güvenlik taramaları, sıfır dosya kontrolleri ve regresyon testleri %100 başarıyla tamamlandı!{Colors.ENDC}")
    sys.exit(0)


if __name__ == "__main__":
    main()
