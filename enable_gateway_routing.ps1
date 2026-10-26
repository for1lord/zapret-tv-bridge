# Elevate if not admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " НАСТРОЙКА WINDOWS КАК ШЛЮЗА ДЛЯ ДОМАШНЕЙ СЕТИ" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

try {
    Write-Host "[*] Включение IP-маршрутизации (IPEnableRouter = 1)..." -ForegroundColor Yellow
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1 -Force
    Write-Host "[+] IP-маршрутизация успешно включена в реестре." -ForegroundColor Green
} catch {
    Write-Host "[!] Ошибка включения IP-маршрутизации: $_" -ForegroundColor Red
}

try {
    Write-Host "[*] Настройка службы маршрутизации (RemoteAccess)..." -ForegroundColor Yellow
    Set-Service -Name RemoteAccess -StartupType Automatic
    Start-Service -Name RemoteAccess -ErrorAction SilentlyContinue
    $svc = Get-Service RemoteAccess
    Write-Host "[+] Служба RemoteAccess: $($svc.Status)" -ForegroundColor Green
} catch {
    Write-Host "[!] Ошибка настройки службы RemoteAccess: $_" -ForegroundColor Red
}

try {
    Write-Host "[*] Отключение ICMP Redirects (защита от обхода ПК)..." -ForegroundColor Yellow
    & netsh int ip set global icmpredirects=disabled
    Write-Host "[+] ICMP Redirects успешно отключены." -ForegroundColor Green
} catch {
    Write-Host "[!] Ошибка netsh: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Все параметры успешно применены!" -ForegroundColor Green
Write-Host " Теперь ПК готов принимать трафик от роутера." -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Нажмите Enter для закрытия..."
Read-Host
