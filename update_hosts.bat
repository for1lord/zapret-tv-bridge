@echo off
findstr /C:"rt.pornhub.org" "%WINDIR%\System32\drivers\etc\hosts" >nul
if %errorlevel% neq 0 (
    echo. >> "%WINDIR%\System32\drivers\etc\hosts"
    echo # Pornhub Anycast routing >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 66.254.114.40 rt.pornhub.org >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 66.254.114.40 pornhub.com >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 66.254.114.40 www.pornhub.com >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 66.254.114.40 rt.pornhub.com >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 66.254.114.40 pornhubpremium.com >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 66.254.114.40 rt.pornhubpremium.com >> "%WINDIR%\System32\drivers\etc\hosts"
)

findstr /C:"vdownload.hembed.com" "%WINDIR%\System32\drivers\etc\hosts" >nul
if %errorlevel% neq 0 (
    echo. >> "%WINDIR%\System32\drivers\etc\hosts"
    echo # Media and Video CDN Anycast routing >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 37.19.218.101 vdownload.hembed.com >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 89.222.125.209 pix-cdn77.phncdn.com >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 89.222.125.209 pix-cdn77.rdtcdn.com >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 151.101.67.52 pix-fl.phncdn.com >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 151.101.67.52 pix-fl.rdtcdn.com >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 66.254.122.18 ei.phncdn.com >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 66.254.122.18 es.phncdn.com >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 66.254.122.18 ei-ph.rdtcdn.com >> "%WINDIR%\System32\drivers\etc\hosts"
)

findstr /C:"rutracker.org" "%WINDIR%\System32\drivers\etc\hosts" >nul
if %errorlevel% neq 0 (
    echo. >> "%WINDIR%\System32\drivers\etc\hosts"
    echo # Direct DNS Poisoning Protection >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 104.21.32.39 rutracker.org >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 104.21.48.196 animevost.org >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 104.21.48.196 animevost.tv >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 104.21.48.196 animevost.top >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 104.21.48.196 animevost.me >> "%WINDIR%\System32\drivers\etc\hosts"
)

findstr /C:"cdn.battleye.com" "%WINDIR%\System32\drivers\etc\hosts" >nul
if %errorlevel% neq 0 (
    echo. >> "%WINDIR%\System32\drivers\etc\hosts"
    echo # BattlEye Anti-Cheat Global CDN >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 185.229.190.148 cdn.battleye.com >> "%WINDIR%\System32\drivers\etc\hosts"
    echo 185.229.190.148 battleye.becdn.net >> "%WINDIR%\System32\drivers\etc\hosts"
)

ipconfig /flushdns >nul
