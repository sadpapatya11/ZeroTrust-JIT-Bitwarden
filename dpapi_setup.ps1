# Bitwarden master parolasını Windows DPAPI ile şifreleyip dosyaya kaydeder.
#
# ÖNEMLİ: DPAPI, dosyayı yalnızca "başka kullanıcı / başka bilgisayar"a karşı korur.
# AYNI Windows kullanıcısı olarak çalışan her süreç (yapay zeka ajanı dahil) dosyayı çözebilir.
# Ajanı da korumak istiyorsanız bu betiği, ajanın ÇALIŞMADIĞI ayrı bir Windows kullanıcısıyla
# (örn. "jitsvc") çalıştırın ve daemon'u da o kullanıcıyla başlatın (README -> Tehdit modeli).
#
# Kullanım:  .\dpapi_setup.ps1 [-Path C:\yol\bw_master_dpapi.txt]
# Daemon farklı bir yol kullanacaksa JIT_DPAPI_FILE ortam değişkenine aynı yolu yazın.
param(
    [string]$Path = (Join-Path $env:USERPROFILE ".bw_master_dpapi.txt")
)

$host.UI.RawUI.WindowTitle = "JIT DPAPI Kurulumu"
Write-Host "Bitwarden master parolanızı girin (DPAPI ile şifrelenecek, bu kullanıcıya bağlı olacak): " -ForegroundColor Cyan
$securePw = Read-Host -AsSecureString
if ($securePw.Length -eq 0) {
    Write-Host "[HATA] Parola boş olamaz." -ForegroundColor Red
    exit 1
}

$securePw | ConvertFrom-SecureString | Set-Content -Path $Path -Encoding ASCII

# Dosyayı yalnızca bu kullanıcıya (ve SYSTEM'e) okunur bırak
icacls $Path /inheritance:r /grant:r "$($env:USERNAME):(R,W)" "SYSTEM:(R)" | Out-Null

Write-Host ""
Write-Host "[BAŞARILI] Parola şifrelendi: $Path" -ForegroundColor Green
Write-Host "Not: Bu dosya yalnızca '$($env:USERNAME)' kullanıcısı altında çözülebilir." -ForegroundColor Yellow
Start-Sleep -Seconds 3
