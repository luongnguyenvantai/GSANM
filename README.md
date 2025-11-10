# SABDA: Stateful Anomaly Behavior Detection & Analysis

Run a real-time log anomaly detection system using Graylog, InfluxDB, Grafana, and a custom Python analysis core.

This stack gives you the ability to analyze system logs (SSH, Apache) in real-time. It leverages a stateful Machine Learning model to detect behavioral anomalies (such as Brute-force, Web Scanning, and SQL Injection) and visualizes these threats on a live Grafana dashboard.

Based on official Docker images and technologies:

* [Graylog](https://www.graylog.org/) (Assumed to be pre-installed)
* [InfluxDB](https://www.influxdata.com/)
* [Grafana](https://grafana.com/)
* [Python](https://www.python.org/) (with Scikit-learn)

## SABDA Core (Python)

* **`src/anomaly_detector.py`**: This is the 'brain' of the system. This Python script periodically pulls logs from the Graylog API, parses them, and performs **Stateful Feature Engineering** to build 4-dimensional behavior vectors for each IP. A pre-trained Random Forest model (`rf_model.joblib`) then classifies these vectors as 'normal' or 'anomaly'. All results (both normal and abnormal) are pushed to InfluxDB.

## Setup the Stack

The configuration for the InfluxDB and Grafana containers is in `docker-compose.yml`.

The configuration for the Python script (API tokens for Graylog and InfluxDB) is managed via the `.env` file. Please copy `.env.example` to `.env` and fill in your credentials.

## Notes

By default:

* The `anomaly_detector.py` script runs in a **1-minute time window**.
* It queries the Graylog API to fetch all logs from the last minute.
* It is configured to parse `sshd` logs (for Brute-force) and `apache` access logs (for Web Scanning/SQLi).
* It pushes *all* calculated behavior metrics (e.g., `ssh_failed_count`, `http_404_count`) to InfluxDB. This allows Grafana to plot both normal and abnormal behavior over time.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Fire up the stack

This guide assumes you have a **running Graylog instance** and its Docker network name.

1.  **Clone this repository**
    ```bash
    git clone <your-repo-url>
    cd SABDA_Project
    ```

2.  **Configure Infrastructure**
    * Open `docker-compose.yml`.
    * Find the `networks:` -> `graylog-net:` -> `name:` section at the bottom.
    * Change `graylog-docker_default` to the **actual network name** of your Graylog Docker stack. (You can find this with `docker network ls`).

3.  **Start Infrastructure (InfluxDB & Grafana)**
    ```console
    $ docker-compose up -d
    ```

4.  **Configure InfluxDB (First-time setup)**
    * Navigate to `http://localhost:8086`.
    * Complete the setup wizard:
        * Create Organization: (e.g., `NhomNghienCuu`)
        * Create Bucket: (e.g., `log_anomaly`)
        * Generate a **Write**-permission API Token for the `log_anomaly` bucket.
    * **Copy this new Token.**

5.  **Configure Grafana (First-time setup)**
    * Navigate to `http://localhost:3000` (default login: admin/admin).
    * **Add Data Source:**
        * Go to Connections -> Data Sources -> Add InfluxDB.
        * Query Language: `Flux`.
        * URL: `http://influxdb:8086` (This works because they are on the same Docker network).
        * Fill in your Organization, Bucket (`log_anomaly`), and the **InfluxDB Token** you just copied.
        * Click "Save & Test".
    * **Import Dashboards:**
        * Go to Dashboards -> Import.
        * Upload the `.json` files located in the `/grafana_dashboards` directory.

6.  **Configure Python Core**
    * Create a Python virtual environment:
        ```bash
        python -m venv env
        source env/bin/activate
        ```
    * Install dependencies:
        ```bash
        pip install -r requirements.txt
        ```
    * Create your environment file:
        ```bash
        cp .env.example .env
        ```
    * Edit `.env` and paste your `GRAYLOG_TOKEN` and `INFLUX_TOKEN`.

7.  **Train the Model (Run once)**
    ```console
    $ python src/anomaly_detector.py 1
    ```
    This will create the `models/rf_model.joblib` file.

8.  **Run Real-time Detection**
    ```console
    $ python src/anomaly_detector.py 2
    ```
    The script is now running, analyzing logs every minute, and pushing data to InfluxDB. Your Grafana dashboard should now be live with data.

By default, the stack exposes the following ports:
* `8086`: InfluxDB API and UI
* `3000`: Grafana UI
* (Your Graylog ports, e.g., `9000`, `5140`)

## Clean up

To stop the InfluxDB and Grafana containers created by this project:
```console
$ docker-compose down -v
