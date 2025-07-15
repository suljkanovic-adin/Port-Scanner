import socket
import threading
import requests
import json
import time
import os

from datetime import datetime

# Constants
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"User-Agent": "SimplePortScanner/1.0"}

open_ports = []
results = []

# Thread lock for safe print/output
print_lock = threading.Lock()

def scan_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except:
                    banner = "No banner"
                with print_lock:
                    print(f"[+] Open port: {port} - {banner}")
                    open_ports.append(port)
                    results.append({
                        "port": port,
                        "banner": banner,
                        "cves": query_nvd(banner)
                    })
    except Exception as e:
        pass

def query_nvd(service_name):
    """Queries NIST NVD API using part of the banner string"""
    if not service_name or service_name == "No banner":
        return []
    try:
        params = {
            "keywordSearch": service_name,
            "resultsPerPage": 3
        }
        res = requests.get(NVD_API_URL, headers=HEADERS, params=params, timeout=5)
        if res.status_code == 200:
            data = res.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve_id = item.get("cve", {}).get("id", "")
                description = item.get("cve", {}).get("descriptions", [{}])[0].get("value", "")
                cves.append({
                    "id": cve_id,
                    "description": description
                })
            return cves
    except Exception as e:
        return []
    return []

def save_results_to_json(host):
    filename = f"results_{host}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[✔] Results saved to {filename}")

def save_results_to_html(host):
    filename = f"results_{host}.html"
    with open(filename, "w") as f:
        f.write("<html><body><h2>Port Scan Results</h2><table border='1'>")
        f.write("<tr><th>Port</th><th>Banner</th><th>CVEs</th></tr>")
        for entry in results:
            cve_data = "<br>".join([f"<b>{c['id']}</b>: {c['description']}" for c in entry["cves"]]) or "None"
            f.write(f"<tr><td>{entry['port']}</td><td>{entry['banner']}</td><td>{cve_data}</td></tr>")
        f.write("</table></body></html>")
    print(f"[✔] Results saved to {filename}")

def valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except:
        return False

def main():
    print("=== Port Scanner + CVE Checker ===")
    host = input("Enter target IP or hostname: ").strip()

    try:
        target_ip = socket.gethostbyname(host)
    except:
        print("Invalid host.")
        return

    ports_input = input("Enter port range (e.g., 20-100): ").strip()
    try:
        start_port, end_port = map(int, ports_input.split("-"))
        if start_port < 1 or end_port > 65535 or start_port >= end_port:
            raise ValueError
    except:
        print("Invalid port range.")
        return

    print(f"\n[Scanning] Host: {host} ({target_ip}) | Ports: {start_port}-{end_port}")
    time.sleep(1)

    threads = []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(target_ip, port))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if not results:
        print("⚠ No open ports found.")
        return

    save_results_to_json(host)
    save_results_to_html(host)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
