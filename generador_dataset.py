import json
import random
import csv

# 1. INVENTARIO (4 Activos con distintas criticidades Ca)
inventario = [
    {"ip": "192.168.1.10", "hostname": "SRV-BD-PROD", "ca": 1.2},
    {"ip": "192.168.1.20", "hostname": "SRV-WEB-DMZ", "ca": 1.0},
    {"ip": "192.168.1.30", "hostname": "WKS-ADMIN", "ca": 0.8},
    {"ip": "192.168.1.50", "hostname": "SRV-TESTING", "ca": 0.5}
]

# 2. VULNERABILIDADES OPENVAS (20 CVEs estructurales)
# Forzamos los casos de prueba específicos mencionados en la tesis
cves = [
    {"ip": "192.168.1.10", "cve": "CVE-2021-44228", "cvss": 10.0, "en_cisa": True},  # Peligro Crítico Real
    {"ip": "192.168.1.50", "cve": "CVE-2020-1472", "cvss": 10.0, "en_cisa": False},  # Falso Positivo (Ruido)
    {"ip": "192.168.1.20", "cve": "CVE-2014-0160", "cvss": 7.5, "en_cisa": True},   # Peligro Activo Medio
]
# Generar 17 vulnerabilidades aleatorias extra para rellenar
for i in range(17):
    cves.append({
        "ip": random.choice(inventario)["ip"],
        "cve": f"CVE-2023-{random.randint(1000, 9999)}",
        "cvss": round(random.uniform(4.0, 9.8), 1),
        "en_cisa": random.choice([True, False])
    })

# 3. ALERTAS WAZUH (50 Eventos operacionales simulados)
alertas_wazuh = [
    {"ip": "192.168.1.10", "regla_nivel": 12, "descripcion": "Ataque RCE detectado"},
    {"ip": "192.168.1.20", "regla_nivel": 10, "descripcion": "Intento de explotación web"},
    {"ip": "192.168.1.50", "regla_nivel": 3, "descripcion": "Escaneo de puertos (Ruido)"}
]
for i in range(47):
    alertas_wazuh.append({
        "ip": random.choice(inventario)["ip"],
        "regla_nivel": random.choice([3, 5, 7, 8]), # Mayormente ruido
        "descripcion": "Evento operacional genérico"
    })

# 4. GROUND TRUTH (Etiquetado SSVC Independiente)
# Track = Ignorar/Monitorear | Attend = Revisar pronto | Act = Actuar Inmediato
ground_truth = []
for cve in cves:
    accion_ssvc = "Track"
    if cve["cvss"] >= 9.0 and cve["en_cisa"]: accion_ssvc = "Attend"
    if cve["ip"] == "192.168.1.10" and cve["cve"] == "CVE-2021-44228": accion_ssvc = "Act"
    if cve["ip"] == "192.168.1.20" and cve["cve"] == "CVE-2014-0160": accion_ssvc = "Act"
    
    ground_truth.append({"ip": cve["ip"], "cve": cve["cve"], "ssvc_decision": accion_ssvc})

# GUARDAR ARCHIVOS
with open('inventario.json', 'w') as f: json.dump(inventario, f, indent=4)
with open('openvas.json', 'w') as f: json.dump(cves, f, indent=4)
with open('alertas_wazuh.json', 'w') as f: json.dump(alertas_wazuh, f, indent=4)
with open('ground_truth_ssvc.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=["ip", "cve", "ssvc_decision"])
    writer.writeheader()
    writer.writerows(ground_truth)

print("¡Dataset sintético generado con éxito!")