@echo off
echo ===============================
echo Sentinel AI Edge Security Tests
echo ===============================

echo.
echo [1] Normal traffic
curl.exe -A "Mozilla/5.0" "http://127.0.0.1:8080/?q=hello"
timeout /t 2 >nul

echo.
echo [2] XSS
curl.exe -A "Mozilla/5.0" "http://127.0.0.1:8080/?q=<script>alert(1)</script>"
timeout /t 2 >nul

echo.
echo [3] Encoded XSS
curl.exe -A "Mozilla/5.0" "http://127.0.0.1:8080/?q=%3Cscript%3Ealert(1)%3C/script%3E"
timeout /t 2 >nul

echo.
echo [4] SQLi OR
curl.exe -A "Mozilla/5.0" "http://127.0.0.1:8080/?id=1%27%20OR%201=1%20--"
timeout /t 2 >nul

echo.
echo [5] SQLi UNION
curl.exe -A "Mozilla/5.0" "http://127.0.0.1:8080/?q=UNION%20SELECT%20NULL,NULL"
timeout /t 2 >nul

echo.
echo [6] SQLi comment
curl.exe -A "Mozilla/5.0" "http://127.0.0.1:8080/?user=admin%27%20--%20"
timeout /t 2 >nul

echo.
echo [7] Path traversal
curl.exe -A "Mozilla/5.0" "http://127.0.0.1:8080/?q=../../../../etc/passwd"
timeout /t 2 >nul

echo.
echo [8] Binary anomaly
curl.exe -A "Mozilla/5.0" "http://127.0.0.1:8080/?q=%00%ff%aa%bb%cc"
timeout /t 2 >nul

echo.
echo [9] Bot detection
curl.exe "http://127.0.0.1:8080/"

echo.
echo ✅ TESTING COMPLETE
pause
