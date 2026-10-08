import os
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
import subprocess
from urllib.parse import urlparse, parse_qs

PORT = 5050
MACRODROID_WEBHOOK = "https://trigger.macrodroid.com/YOUR_UUID/ajan_istek"
SECRET_TOKEN = "GIZLI_SIFRENIZ" 

class JITHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/approve':
            query_components = parse_qs(parsed_path.query)
            token = query_components.get('token', [''])[0]
            
            if token != SECRET_TOKEN:
                self.send_response(403)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"HATA: Yetkisiz Onay Denemesi (Spoofing) Engellendi!")
                print(f"\\n[DIKKAT] Sahte bir onay istegi yakalandi ve engellendi! Gelen IP: {self.client_address[0]}")
                return

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Onay Alindi! Kimlik dogrulandi, kasa 1 Saniyeligine Aciliyor...")
            
            ps_script = """
$securePw = Get-Content "$env:USERPROFILE\\.bw_master_dpapi.txt" | ConvertTo-SecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePw)
$plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

$bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
$b64 = [Convert]::ToBase64String($bytes)

# MUKEMMEL ZERO-TRUST UYGULAMASI: Dosyaya yazmak SIFIRLANDI. 
# Base64 dogrudan WSL std-in icine aktariliyor ve tr -cd ile temizlenip RAM'e cikariliyor.
$wslCmd = "echo '$b64' | tr -cd 'A-Za-z0-9+/=' | base64 -d > /dev/shm/.bw_tmp && TOKEN=\\`$(bw unlock --passwordfile /dev/shm/.bw_tmp --raw 2>/dev/null) && rm -f /dev/shm/.bw_tmp && if [ -n \\"\\`$TOKEN\\" ]; then echo \\"\\`$TOKEN\\" > /dev/shm/.bw_session; chmod 600 /dev/shm/.bw_session; echo '[BASARILI]' > /dev/shm/jit_result.txt; rm -f /dev/shm/.bw_session; exit 0; else echo '[HATA]' > /dev/shm/jit_result.txt; exit 1; fi"

$null | wsl -e bash -c $wslCmd
"""
            subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_script])
            print("\\n[JIT] Gorev tamamlandi. RAM temizlendi. Sunucu kapaniyor.")
            os._exit(0)
        else:
            self.send_response(404)
            self.end_headers()

def request_approval():
    print("[JIT] Token gerekiyor! Macrodroid'e onay istegi gonderiliyor...")
    try:
        urllib.request.urlopen(MACRODROID_WEBHOOK)
        print("[JIT] Istek basariyla iletildi!")
    except Exception as e:
        print(f"Webhook hatasi: {e}")

if __name__ == '__main__':
    request_approval()
    print(f"[JIT] Telefon onayi bekleniyor... Lutfen telefondan onay verin.")
    server = HTTPServer(('0.0.0.0', PORT), JITHandler)
    server.serve_forever()
