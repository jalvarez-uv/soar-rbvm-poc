import json

def calcular_rf(cvss, ca, it, eo):
    # Ecuación de la Tesis
    mdin = (eo * 0.45) + (ca * 0.35) + (it * 0.20)
    rf = (cvss * mdin) / 1.2
    return round(rf, 2)

# Cargar archivos locales (Mocking)
with open('inventario.json', 'r') as f: inventario = json.load(f)
with open('openvas.json', 'r') as f: cves = json.load(f)
with open('alertas_wazuh.json', 'r') as f: alertas = json.load(f)

# Diccionarios de búsqueda rápida
dict_ca = {item['ip']: item['ca'] for item in inventario}
dict_alertas = {} # Guardar solo la alerta más crítica por IP
for alerta in alertas:
    ip = alerta['ip']
    if ip not in dict_alertas or alerta['regla_nivel'] > dict_alertas[ip]:
        dict_alertas[ip] = alerta['regla_nivel']

# Triaje
resultados_triaje = []
for cve in cves:
    ip = cve['ip']
    cvss = cve['cvss']
    
    # 1. Criticidad (Ca)
    ca = dict_ca.get(ip, 1.0)
    
    # 2. Inteligencia (It)
    it = 1.2 if cve['en_cisa'] else 0.5
    
    # 3. Evidencia Operativa (Eo)
    nivel_max = dict_alertas.get(ip, 0)
    if nivel_max >= 10: eo = 1.2
    elif nivel_max >= 5: eo = 0.8
    else: eo = 0.5
        
    # Calcular Riesgo Final
    rf = calcular_rf(cvss, ca, it, eo)
    
    resultados_triaje.append({
        "ip": ip,
        "cve": cve['cve'],
        "cvss_estatico": cvss,
        "riesgo_dinamico_rf": rf
    })

# Ordenar por Riesgo Dinámico (RBVM)
resultados_triaje.sort(key=lambda x: x['riesgo_dinamico_rf'], reverse=True)

print("TOP 5 VULNERABILIDADES PRIORIZADAS (RBVM):")
for r in resultados_triaje[:5]:
    print(f"IP: {r['ip']} | CVE: {r['cve']} | CVSS: {r['cvss_estatico']} -> Rf: {r['riesgo_dinamico_rf']}")