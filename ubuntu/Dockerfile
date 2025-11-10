# Sử dụng Ubuntu image mới nhất
FROM ubuntu:latest

# Cài đặt OpenSSH Server
RUN apt-get update && \
    apt-get install -y openssh-server && \
    apt-get clean && \
    mkdir /var/run/sshd

# Cấu hình SSH
RUN echo 'root:password' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Mở cổng SSH
EXPOSE 2222

# Khởi động SSH trong chế độ foreground
CMD ["/usr/sbin/sshd", "-D"]
