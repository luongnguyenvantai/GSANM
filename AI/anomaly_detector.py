# # Thêm các thư viện cần thiết:

import requests
import json
import time
import re
import joblib
import numpy as np
from collections import defaultdict
from sklearn.ensemble import RandomForestClassifier
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
from datetime import datetime, timezone
# -----------------------------
# CẤU HÌNH
# -----------------------------
GRAYLOG_URL = "http://127.0.0.1:9000"
GRAYLOG_TOKEN = "7ppsl1avn2dhaif2af84733mheirqpvndbv42rbq00lgv1501i3"
MODEL_FILE = 'rf_model.joblib'

# Cấu hình InfluxDB
INFLUX_URL = "http://127.0.0.1:8086"  
INFLUX_TOKEN = "gRGTniu9_IOXt-L5WLNZPLAZ8NRI-wKUTnZf4IModL2rXq8AzZ6byXpBDXpCPIH"
INFLUX_ORG = "NhomNghienCuu"
INFLUX_BUCKET = "log_anomaly"

# -----------------------------
# HÀM LẤY LOG TỪ GRAYLOG
# -----------------------------
def get_graylog_logs(minutes=1, limit=10000):
    api_url = f"{GRAYLOG_URL}/api/search/universal/relative"
    params = {
        "query": "*",
        "range": minutes * 60,
        "limit": limit,
        "sort": "timestamp:desc"
    }
    try:
        response = requests.get(
            api_url,
            params=params,
            auth=(GRAYLOG_TOKEN, "token"),
            headers={"Accept": "application/json"},
            verify=False
        )
        response.raise_for_status()
        messages = response.json().get("messages", [])
        logs = [msg["message"]["message"] for msg in messages if "message" in msg["message"]]
        return logs
    except Exception as e:
        print(f"[ERROR] Không thể kết nối đến Graylog API: {e}")
        return []

# -----------------------------
# HÀM LOG PARSING 
# -----------------------------
# SSH Patterns
SSH_FAILED_PATTERN = re.compile(r'sshd\[\d+\]: Failed password for (invalid user )?(.*?) from ([\d\.]+) port \d+ ssh2')
SSH_SUCCESS_PATTERN = re.compile(r'sshd\[\d+\]: Accepted password for (.*?) from ([\d\.]+) port \d+ ssh2')

# Web Attack Patterns
APACHE_ACCESS_PATTERN = re.compile(r'([\d\.]+) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+|-)')
SQLI_PATTERN = re.compile(r"(\'|\%27)\s*(OR|UNION)\s*(\'|\%27)\s*(\d+)\s*=\s*(\'|\%27)\s*(\d+)", re.IGNORECASE)

def parse_log_message(log):
    """
    Phân tách log thô (SSH và Apache) thành một dictionary có cấu trúc.
    """
    # 1. Kiểm tra SSH
    ssh_fail_match = SSH_FAILED_PATTERN.search(log)
    if ssh_fail_match:
        return {
            "type": "ssh_fail",
            "user": ssh_fail_match.group(2).strip(),
            "ip": ssh_fail_match.group(3).strip()
        }
    
    ssh_success_match = SSH_SUCCESS_PATTERN.search(log)
    if ssh_success_match:
        return {
            "type": "ssh_success",
            "user": ssh_success_match.group(1).strip(),
            "ip": ssh_success_match.group(2).strip()
        }

    # 2. Kiểm tra Log Apache
    apache_match = APACHE_ACCESS_PATTERN.search(log)
    if apache_match:
        ip = apache_match.group(1)
        request_str = apache_match.group(3)
        status_code = apache_match.group(4)

        # Kiểm tra SQLi đơn giản
        is_sqli = 1 if SQLI_PATTERN.search(request_str) else 0

        return {
            "type": "http_access",
            "ip": ip,
            "status_code": status_code,
            "is_sqli_attempt": is_sqli
        }
    
    return {"type": "unknown", "ip": None, "user": None}

# -----------------------------
# HÀM HUẤN LUYỆN MÔ HÌNH
# -----------------------------
def train_model():
    print("\n--- BAT DAU HUAN LUYEN (SUPERVISED - SSH + Web) ---")
    
    # Đặc trưng: [ssh_fail_count, ssh_distinct_users, http_404_count, sqli_attempt_count]

    # Mẫu hành vi bình thường 
    features_normal = [
        [1, 1, 10, 0],  # Hoạt động bình thường (có 10 lỗi 404)
        [0, 0, 5, 0],
        [2, 1, 15, 0],
    ]
    labels_normal = [0] * len(features_normal) # 0 = Bình thường

    # Mẫu hành vi tấn công (Attack)
    features_attack = [
        [50, 3, 2, 0],   # Kịch bản 1: SSH Brute-force
        [75, 1, 10, 0],  
        [0, 0, 150, 1],  # Kịch bản 2: Web Scanning (Lỗi 404 cao)
        [1, 1, 200, 0],
        [0, 0, 5, 10],   # Kịch bản 3: SQL Injection (Thử nghiệm SQLi)
        [0, 0, 20, 15],
    ]
    labels_attack = [1] * len(features_attack) # 1 = Bất thường
    X_train = np.array(features_normal + features_attack)
    y_train = np.array(labels_normal + labels_attack)
    
    print(f"[*] Đang huấn luyện mô hình RandomForest trên {len(X_train)} mẫu...")
    
    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    model.fit(X_train, y_train)
    
    joblib.dump(model, MODEL_FILE)
    print(f"Huấn luyện hoàn tất. Mô hình đã được lưu vào '{MODEL_FILE}'!")

# -----------------------------
# HÀM PHÁT HIỆN BẤT THƯỜNG
# -----------------------------
def detect_anomalies():
    print("\n--- STARTING DETECTION MODE (STATEFUL - SSH + Web) ---")
    print("[*] Đang tải mô hình RandomForest...")
    
    try:
        client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
        write_api = client.write_api(write_options=SYNCHRONOUS)
        model = joblib.load(MODEL_FILE)
    except Exception as e:
        print(f"[ERROR] Không thể khởi tạo. Hãy chạy chế độ TRAIN hoặc kiểm tra InfluxDB. Lỗi: {e}")
        return

    print("[*] Bắt đầu giám sát thời gian thực (Cửa sổ 1 phút). Nhấn Ctrl+C để dừng.")
    
    try:
        while True:
            print(f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} ---")
            print("[*] Đang thu thập log trong 1 phút...")

            logs = get_graylog_logs(minutes=1)

            if not logs:
                print("[!] Không có log mới trong cửa sổ này.")
                time.sleep(60)
                continue

            # Thêm các trường cho web
            ip_state = defaultdict(lambda: {
                'ssh_failed_count': 0, 
                'ssh_distinct_users': set(),
                'http_404_count': 0,
                'sqli_attempt_count': 0
            })



            for log in logs:
                if "' OR '1'='1'" in log or "%27%20OR%20%271%27%3D%271%27" in log:
                    print(f"--- DEBUG: Log goc nhan duoc co chua SQLi ---")
                    print(log) 
                    print(f"----------------------------------------")
                parsed = parse_log_message(log)
                ip = parsed.get("ip")
                if not ip:
                    continue

                if parsed['type'] == 'ssh_fail':
                    ip_state[ip]['ssh_failed_count'] += 1
                    ip_state[ip]['ssh_distinct_users'].add(parsed['user'])

                elif parsed['type'] == 'http_access':

                    if parsed['status_code'] == '404':
                        ip_state[ip]['http_404_count'] += 1
                    if parsed['is_sqli_attempt'] == 1:
                        ip_state[ip]['sqli_attempt_count'] += 1
            # === BẮT ĐẦU DEBUG ===
            print("--- DEBUG: Trang thai IP sau khi xu ly log ---")
            for ip, data in ip_state.items():
                print(f"IP: {ip}, Data: {data}")
            print("--- KET THUC DEBUG ---")
        # === KẾT THÚC DEBUG ===
            if not ip_state:
                print("Không có hoạt động nào đáng chú ý.")
                time.sleep(60)
                continue
            
            # Chuẩn bị dữ liệu để dự đoán
            feature_vectors = []
            ips_in_window = []
            for ip, data in ip_state.items():
                # Vector
                vector = [
                    data['ssh_failed_count'],
                    len(data['ssh_distinct_users']),
                    data['http_404_count'],
                    data['sqli_attempt_count']
                ]
                feature_vectors.append(vector)
                ips_in_window.append(ip)

            predictions = model.predict(np.array(feature_vectors))

            print(f"[*] Đã xử lý {len(ips_in_window)} IP. Đang đẩy lên InfluxDB...")
            
            # Vòng lặp đẩy dữ liệu lên InfluxDB
            for ip, pred, features in zip(ips_in_window, predictions, feature_vectors):
                anomaly_status = int(pred) 
                
                point = Point("behavior_metrics") \
                    .tag("source_ip", ip) \
                    .field("ssh_failed_count", int(features[0])) \
                    .field("ssh_distinct_users", int(features[1])) \
                    .field("http_404_count", int(features[2])) \
                    .field("sqli_attempt_count", int(features[3])) \
                    .field("is_anomaly", anomaly_status) \
                    .time(datetime.now(timezone.utc)) 
                write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)

                if anomaly_status == 1:
                    print(f"CẢNH BÁO ĐÃ ĐẨY: IP {ip}, Features {features}")

            print("Đã đẩy dữ liệu hoàn tất.")
            time.sleep(60)

    except KeyboardInterrupt:
        print("\n[*] Đã dừng chế độ giám sát.")
    except Exception as e:
        print(f"\n[ERROR] Lỗi nghiêm trọng trong vòng lặp chính: {e}")
    finally:
        client.close()
        print("[*] Đã đóng kết nối InfluxDB.")

# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    print("=== SABDA (SSH + Web) ===")
    print("1. Huấn luyện mô hình")
    print("2. Phát hiện bất thường")
    print("3. Thoát")
    choice = input("Chọn chế độ (1/2/3): ").strip()

    if choice == "1":
        train_model()
    elif choice == "2":
        detect_anomalies()
    elif choice == "3":
        print("Đã thoát chương trình.")
    else:
        print("Lựa chọn không hợp lệ.")





