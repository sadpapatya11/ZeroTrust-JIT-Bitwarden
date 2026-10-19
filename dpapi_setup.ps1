$host.UI.RawUI.WindowTitle = "JIT DPAPI Kurulumu"
Clear-Host
Write-Host "Bitwarden Master Parolanizi girin (DPAPI ile donanimsal sifrelenecektir): " -ForegroundColor Cyan
$securePw = Read-Host -AsSecureString
$path = "$env:USERPROFILE\.bw_master_dpapi.txt"
$securePw | ConvertFrom-SecureString | Set-Content $path
Write-Host ""
Write-Host "[BASARILI] Parolaniz Windows DPAPI ile sifrelendi ve kaydedildi." -ForegroundColor Green
Start-Sleep -Seconds 3
