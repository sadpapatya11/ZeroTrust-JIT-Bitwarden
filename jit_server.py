import os
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
import subprocess

PORT = 5050
# BURAYA KENDI MACRODROID WEBHOOK URL'NIZI YAZIN
MACRODROID_WEBHOOK = "https://trigger.macrodroid.com/YOUR_UUID/ajan_istek"

class JITHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/approve':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Onay Alindi! Kasa 1 Saniyeligine Aciliyor...")
            
            ps_script = """
$securePw = Get-Content "$env:USERPROFILE\\.bw_master_dpapi.txt" | ConvertTo-SecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePw)
$plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

$bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
$b64 = [Convert]::ToBase64String($bytes)

$shContent = @"
echo '$b64' | base64 -d > /dev/shm/.bw_tmp
TOKEN=`$(bw unlock "`$(cat /dev/shm/.bw_tmp)" --raw 2>/dev/null)
rm /dev/shm/.bw_tmp 2>/dev/null

if [ -n "`$TOKEN" ]; then
    echo "`$TOKEN" > /dev/shm/.bw_session
    chmod 600 /dev/shm/.bw_session
    
    # KOR AJAN: BURAYA KENDI GOREVINIZI/KODUNUZU YAZABILIRSINIZ
    # Ornek: GITHUB_TOKEN=`$(bw get item ... --session `$TOKEN)
    echo "[BASARILI] Kasa acildi ve islem yapildi." > /dev/shm/jit_result.txt
    
    # Islem bittikten sonra aninda imha
    rm /dev/shm/.bw_session
    exit 0
else
    echo "[HATA] Sifre yanlis veya kasa acilamadi." > /dev/shm/jit_result.txt
    exit 1
fi
"@

$tempPath = "$env:TEMP\\jit_run.sh"
$wslTemp = "/mnt/c/" + $tempPath.Substring(3).Replace('\\', '/')
[System.IO.File]::WriteAllText($tempPath, $shContent, [System.Text.Encoding]::ASCII)

$null | wsl -e bash -c "sed -i 's/\\r$//' $wslTemp"
$null | wsl -e bash $wslTemp
Remove-Item -Path $tempPath -ErrorAction SilentlyContinue
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
        print(f"Webhook hatasi (URL'yi ayarladiginizdan emin olun): {e}")

if __name__ == '__main__':
    request_approval()
    print(f"[JIT] Telefon onayi bekleniyor... Lutfen telefondan onay verin.")
    server = HTTPServer(('0.0.0.0', PORT), JITHandler)
    server.serve_forever()
