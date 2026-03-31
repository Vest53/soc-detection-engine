import re
import json
from datetime import datetime
from collections import defaultdict

# =========================
# CONFIG
# =========================

FAILED_THRESHOLD = 5
SCAN_THRESHOLD = 10

BLACKLIST = ["10.10.10.10", "123.123.123.123"]

incidents = []
seen_incidents = set()

failed_logins = defaultdict(int)
port_scans = defaultdict(int)

# =========================
# DETECÇÕES
# =========================

def detect_ssh_bruteforce(ip):
    if failed_logins[ip] >= FAILED_THRESHOLD:
        return {
            "type": "SSH Brute Force",
            "severity": "HIGH",
            "mitre": "T1110",
            "description": f"Multiple failed SSH logins from {ip}"
        }

def detect_port_scan(ip):
    if port_scans[ip] >= SCAN_THRESHOLD:
        return {
            "type": "Port Scan (Nmap)",
            "severity": "MEDIUM",
            "mitre": "T1046",
            "description": f"Multiple ports scanned from {ip}"
        }

def detect_blacklist(ip):
    if ip in BLACKLIST:
        return {
            "type": "Blacklisted IP",
            "severity": "HIGH",
            "mitre": "T1071",
            "description": f"Connection from known malicious IP {ip}"
        }

def detect_suspicious_activity(ip):
    if failed_logins[ip] > 2:
        return {
            "type": "Suspicious Login Activity",
            "severity": "LOW",
            "mitre": "T1078",
            "description": f"Multiple login attempts from {ip}"
        }

# =========================
# PROCESSAMENTO DE LOG
# =========================

def process_log_line(line):
    ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
    if not ip_match:
        return

    ip = ip_match.group()

    # SSH failed
    if "Failed password" in line:
        failed_logins[ip] += 1

    # Port scan
    if "scan" in line.lower() or "nmap" in line.lower():
        port_scans[ip] += 1

    # Detect
    checks = [
        detect_ssh_bruteforce(ip),
        detect_port_scan(ip),
        detect_blacklist(ip),
        detect_suspicious_activity(ip)
    ]

    for incident in checks:
        if incident:
            key = (incident["type"], ip)

            if key not in seen_incidents:
                seen_incidents.add(key)

                incident["ip"] = ip
                incident["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                incidents.append(incident)

# =========================
# SALVAR INCIDENTES
# =========================

def save_incidents():
    with open("incidents.json", "w") as f:
        json.dump(incidents, f, indent=4)

# =========================
# RELATÓRIO
# =========================

def generate_report():
    total = len(incidents)

    by_type = defaultdict(int)
    by_severity = defaultdict(int)

    for inc in incidents:
        by_type[inc["type"]] += 1
        by_severity[inc["severity"]] += 1

    with open("report.txt", "w") as f:
        f.write("==== SOC REPORT ====\n\n")
        f.write(f"Total Incidents: {total}\n\n")

        f.write("By Type:\n")
        for k, v in by_type.items():
            f.write(f"- {k}: {v}\n")

        f.write("\nBy Severity:\n")
        for k, v in by_severity.items():
            f.write(f"- {k}: {v}\n")

        f.write("\nTop Attackers:\n")
        for ip, count in sorted(failed_logins.items(), key=lambda x: x[1], reverse=True):
            f.write(f"- {ip}: {count} failed attempts\n")

        f.write("\nRecommendations:\n")
        f.write("- Block malicious IPs\n")
        f.write("- Enable MFA for SSH\n")
        f.write("- Monitor unusual traffic\n")

# =========================
# MAIN
# =========================

def main():
    try:
        with open("logs/access.log", "r") as f:
            for line in f:
                process_log_line(line)

        save_incidents()
        generate_report()

        print("✅ Analysis complete!")
        print("📁 Check incidents.json and report.txt")

    except FileNotFoundError:
        print("❌ Log file not found. Check logs/access.log")

if __name__ == "__main__":
    main()