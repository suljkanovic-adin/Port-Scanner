# Port Scanner + CVE Checker

This is a simple Python tool that scans open TCP ports on a host and checks for known vulnerabilities (CVEs) related to the services running on those ports. It uses the NIST NVD API to look up CVEs.

## What this project does

- Scans a host for open TCP ports
- Grabs basic service banners from open ports
- Looks up CVEs related to the services using the NVD API
- Saves the results in both JSON and HTML formats
- Uses multithreading to scan faster

## How to use it

### 1. Install dependencies

Make sure Python 3 is installed, then run:

```bash
pip install -r requirements.txt
```

The only dependency is:

```
requests
```

### 2. Run the script

```bash
python portscanner.py
```

You’ll be asked for:
- A hostname or IP (like `127.0.0.1` or `scanme.nmap.org`)
- A port range to scan (like `20-100`)

Example:

```bash
Enter target IP or hostname: 127.0.0.1
Enter port range (e.g., 20-100): 20-100
```

If it finds open ports, it will show them and fetch possible CVEs for services running there.

### 3. Results

After scanning, it saves two files:

- `results_<host>.json` – the raw data
- `results_<host>.html` – a table view you can open in a browser

## Example output

```
[+] Open port: 22 - SSH-2.0-OpenSSH_8.2p1
[+] Open port: 80 - Apache/2.4.41 (Ubuntu)
[✔] Results saved to results_127.0.0.1.json
[✔] Results saved to results_127.0.0.1.html
```

## Notes

- This is for learning/testing purposes only.
- It’s not meant for scanning systems you don’t own.
- It’s a basic scanner and won’t bypass firewalls or detect every service.
- Be careful when using this on live systems.

## License

This project uses the MIT License.
