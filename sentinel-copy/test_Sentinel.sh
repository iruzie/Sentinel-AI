#!/bin/bash

echo "==============================="
echo "Sentinel AI Edge Security Tests"
echo "==============================="

echo
echo "[1] Normal traffic"
curl -A "Mozilla/5.0" "http://127.0.0.1:8080/?q=hello"
sleep 2

echo
echo "[2] XSS"
curl -A "Mozilla/5.0" "http://127.0.0.1:8080/?q=<script>alert(1)</script>"
sleep 2

echo
echo "[3] Encoded XSS"
curl -A "Mozilla/5.0" "http://127.0.0.1:8080/?q=%3Cscript%3Ealert(1)%3C/script%3E"
sleep 2

echo
echo "[4] SQLi OR"
curl -A "Mozilla/5.0" "http://127.0.0.1:8080/?id=1%27%20OR%201=1%20--"
sleep 2

echo
echo "[5] SQLi UNION"
curl -A "Mozilla/5.0" "http://127.0.0.1:8080/?q=UNION%20SELECT%20NULL,NULL"
sleep 2

echo
echo "[6] SQLi comment"
curl -A "Mozilla/5.0" "http://127.0.0.1:8080/?user=admin%27%20--%20"
sleep 2

echo
echo "[7] Path traversal"
curl -A "Mozilla/5.0" "http://127.0.0.1:8080/?q=../../../../etc/passwd"
sleep 2

echo
echo "[8] Binary anomaly"
curl -A "Mozilla/5.0" "http://127.0.0.1:8080/?q=%00%ff%aa%bb%cc"
sleep 2

echo
echo "[9] Bot detection"
curl "http://127.0.0.1:8080/"

echo
echo "✅ TESTING COMPLETE"

