# Auto-SOC-Triage
# Author: Youssef Elfadili
# Simple log triage tool for SOC investigations

import re
import datetime

# Patterns MITRE ATT&CK simples (exemples)
MITRE_PATTERNS = {
    "T1078": r"Login\sfailed\sfor\suser",
    "T1059": r"(powershell.exe|cmd.exe)",
    "T1021": r"Remote\sdesktop\sconnection",
}

def analyze_log_line(line):
    detections = []
    for technique, pattern in MITRE_PATTERNS.items():
        if re.search(pattern, line, re.IGNORECASE):
            detections.append(technique)
    return detections

def generate_report(findings):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"triage_report_{timestamp}.txt"
    with open(filename, 'w') as report:
        for entry in findings:
            report.write(f"{entry['line'].strip()} => Detected: {', '.join(entry['detections'])}\n")
    print(f"[+] Rapport généré : {filename}")

def main():
    log_file = input("Entrez le chemin du fichier log à analyser : ")
    findings = []
    try:
        with open(log_file, 'r') as logs:
            for line in logs:
                detections = analyze_log_line(line)
                if detections:
                    findings.append({'line': line, 'detections': detections})
    except FileNotFoundError:
        print("[-] Fichier non trouvé.")
        return
    
    if findings:
        print(f"[+] {len(findings)} alertes détectées. Génération du rapport...")
        generate_report(findings)
    else:
        print("[+] Aucune activité suspecte détectée.")

if __name__ == "__main__":
    main()
