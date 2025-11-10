# Sử dụng image Python cơ bản
FROM python:3.11.2

# Đặt thư mục làm việc
WORKDIR /app

# Sao chép các tệp cần thiết vào image
COPY requirements.txt .

# Cập nhật pip lên phiên bản mới nhất
RUN python -m pip install --upgrade pip

# Cài đặt các thư viện
#RUN apt-get install -y build-essential
RUN pip install --no-cache-dir -r requirements.txt

# Sao chép mã nguồn ứng dụng vào image
COPY app.py .
COPY mlp_detection.h5 .
# COPY telegrambot.py .
COPY shivanya.jpg .
COPY tfidf_vectorizer.joblib .

# Chỉ định cổng mà ứng dụng sẽ chạy
EXPOSE 5010

# Chạy ứng dụng
CMD ["python", "anomaly_detector.py"]
