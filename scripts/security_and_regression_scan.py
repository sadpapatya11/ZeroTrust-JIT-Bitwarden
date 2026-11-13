#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zero-Trust JIT Bitwarden - Güvenlik ve Regresyon Tarayıcısı
------------------------------------------------------------
Proje kökünden çalıştırın:  python scripts/security_and_regression_scan.py

1. SAST: sabit gizli anahtar ve güvensiz (şifrelenmemiş, dış) HTTP adresi.
2. Zero-File: koddaki /dev/shm ve /tmp yazımları.
3. Mimari: jit_server.py'nin ÇALIŞAN kodunda (docstring/yorum değil) bash trap'i,
   watchdog ve 30 sn OTP'nin gerçekten bulunduğu. Ayrıca yasak kalıplar (os._exit,
   sabit yedek token, loga OTP yazma).
4. Kök dizinde .env / credential dosyası var mı.
5. tests/ altındaki birim ve entegrasyon testleri.
"""

import ast
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JIT_PATH = os.path.join(ROOT, "jit_server.py")
SKIP_DIRS = {".git", "__pycache__", ".vscode", ".idea", "build", "venv", ".venv"}


class Colors:
    HEADER = "\033[95m"
    OK = "\033[92m"
    WARN = "\033[93m"
    FAIL = "\033[91m"
    END = "\033[0m"
    BOLD = "\033[1m"


def step(title):
    print(f"\n{Colors.HEADER}=== {title} ==={Colors.END}")


def ok(msg):
    print(f"{Colors.OK}[+] {msg}{Colors.END}")


def fail(msg):
    print(f"{Colors.FAIL}[-] {msg}{Colors.END}")


def iter_code_files(exts):
    for root_dir, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if name.endswith(exts):
                yield os.path.join(root_dir, name)


def read(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def line_of(content, pos):
    return content.count("\n", 0, pos) + 1


# --------------------------------------------------------------------------- #
def scan_hardcoded_secrets():
    step("1. Statik analiz (SAST)")
    rules = [
        ("Sabit gizli anahtar / token",
         r"(?i)(api_key|secret_token|private_key|auth_token|client_secret|static_token)\s*=\s*['\"][A-Za-z0-9_\-+/]{8,}['\"]"),
        ("Sabit yedek token varsayılanı",
         r"(?i)FALLBACK_STATIC_TOKEN"),
        ("Dış dünyaya şifresiz HTTP",
         r"['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[A-Za-z0-9./\-?#=&%_]+['\"]"),
    ]
    clean = True
    for path in iter_code_files((".py", ".ps1", ".sh", ".bat")):
        # Bu dosyanın kendisi kural metinlerini içerir
        if os.path.abspath(path) == os.path.abspath(__file__):
            continue
        content = read(path)
        for name, regex in rules:
            for m in re.finditer(regex, content):
                # tests/ içindeki örnek değerler hariç
                if os.sep + "tests" + os.sep in path and name.startswith("Sabit gizli"):
                    continue
                fail(f"{name}: {os.path.relpath(path, ROOT)}:{line_of(content, m.start())} -> {m.group(0).strip()[:80]}")
                clean = False
    if clean:
        ok("Sabit gizli anahtar, yedek token ya da şifresiz dış HTTP bulunamadı.")
    return clean


def scan_zero_file_violations():
    step("2. Zero-File denetimi")
    patterns = [
        (r"/dev/shm/", "/dev/shm kullanımı"),
        (r">\s*/tmp/", "/tmp'ye yazım"),
        (r"\.bw_tmp|\.bw_session", "geçici parola/oturum dosyası adı"),
    ]
    clean = True
    for path in iter_code_files((".py", ".ps1", ".sh")):
        rel = os.path.relpath(path, ROOT)
        if rel.startswith(("scripts", "tests")):
            continue
        content = read(path)
        for pat, desc in patterns:
            for m in re.finditer(pat, content):
                fail(f"{desc}: {rel}:{line_of(content, m.start())}")
                clean = False
    if clean:
        ok("Çalışan kodda diske parola/oturum yazımı yok.")
    return clean


def executable_string_constants(tree):
    """Modül/sınıf/fonksiyon docstring'leri hariç tüm string sabitleri."""
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.body and isinstance(node.body[0], ast.Expr) \
                    and isinstance(node.body[0].value, ast.Constant) \
                    and isinstance(node.body[0].value.value, str):
                docstrings.add(id(node.body[0].value))
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings]


def scan_architecture():
    step("3. Mimari denetim (çalışan kod üzerinden)")
    if not os.path.exists(JIT_PATH):
        fail("jit_server.py bulunamadı!")
        return False
    code = read(JIT_PATH)
    try:
        tree = ast.parse(code, filename=JIT_PATH)
    except SyntaxError as e:
        fail(f"jit_server.py sözdizimi hatası: {e}")
        return False

    errors = []
    consts = executable_string_constants(tree)

    # bash trap'i: docstring'de ya da bash yorum satırında (#) değil, çalışan satırda olmalı
    trap_re = re.compile(r"^\s*trap\s+'[^']*lock[^']*'\s+EXIT\s+INT\s+TERM\s*$")
    if not any(trap_re.match(line) for c in consts for line in c.splitlines()):
        errors.append("Çalışan betikte `trap '... lock ...' EXIT INT TERM` satırı yok (sadece yorum/docstring olabilir).")

    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | \
            {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    for needed in ("arm_watchdog", "disarm_watchdog", "execute_bw_lock", "approvals"):
        if needed not in names:
            errors.append(f"Beklenen mekanizma kodda kullanılmıyor: {needed}")

    consts_assigned = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) \
                and isinstance(n.value, ast.Constant):
            consts_assigned[n.targets[0].id] = n.value.value
    if consts_assigned.get("OTP_VALIDITY_SECONDS") != 30:
        errors.append("OTP_VALIDITY_SECONDS = 30 değil.")
    if consts_assigned.get("WATCHDOG_TIMEOUT_SECONDS") != 30:
        errors.append("WATCHDOG_TIMEOUT_SECONDS = 30 değil.")

    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "_exit" \
                and isinstance(n.func.value, ast.Name) and n.func.value.id == "os":
            errors.append(f"os._exit çağrısı (satır {n.lineno}).")

    # Sır sızıntısı: OTP/parola/sır değişkenini print eden satırlar
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "print":
            src = ast.get_source_segment(code, n) or ""
            if re.search(r"\b(otp|token|pw_b64|plain_pw|session_key|value|result)\b(?!_)", src) \
                    and "{" in src and re.search(r"\{[^}]*\b(otp|pw_b64|plain_pw|session_key|value)\b", src):
                errors.append(f"print() içinde sır içerebilecek değişken (satır {n.lineno}): {src[:70]}")

    if errors:
        for e in errors:
            fail(e)
        return False
    ok("Bash trap, watchdog, 30 sn OTP ve yasak kalıp denetimleri çalışan kodda doğrulandı.")
    return True


def scan_env_leakage():
    step("4. Plaintext .env / credential dosyası taraması")
    clean = True
    for sf in (".env", ".env.local", ".env.production", "secrets.json", "id_rsa", ".bw_master_dpapi.txt"):
        if os.path.exists(os.path.join(ROOT, sf)):
            fail(f"'{sf}' proje kökünde bulundu; repoya girmemeli.")
            clean = False
    if clean:
        ok("Kökte .env ya da credential dosyası yok.")
    return clean


def run_tests():
    step("5. Birim ve entegrasyon testleri")
    res = subprocess.run([sys.executable, "-I", "-m", "unittest", "discover", "-s", "tests"],
                         cwd=ROOT, capture_output=True, text=True)
    tail = (res.stderr or res.stdout).strip().splitlines()[-3:]
    if res.returncode != 0:
        fail("Testler başarısız:")
        print((res.stderr or res.stdout)[-3000:])
        return False
    ok("Testler geçti: " + " | ".join(t for t in tail if t))
    return True


def main():
    print(f"{Colors.BOLD}{Colors.HEADER}ZEROTRUST-JIT-BITWARDEN GÜVENLİK VE REGRESYON TARAYICISI{Colors.END}")
    results = [scan_hardcoded_secrets(), scan_zero_file_violations(),
               scan_architecture(), scan_env_leakage(), run_tests()]
    if not all(results):
        print(f"\n{Colors.FAIL}Tarama BAŞARISIZ.{Colors.END}")
        sys.exit(1)
    print(f"\n{Colors.OK}{Colors.BOLD}Tüm kontroller geçti.{Colors.END}")
    print("Not: Bu tarama kod yapısını ve mantığı doğrular; gerçek Windows/WSL/Bitwarden/telefon "
          "akışını test etmez.")


if __name__ == "__main__":
    main()
