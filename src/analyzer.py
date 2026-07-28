import re
import json
import sys
import os
import requests
import shodan
from dotenv import load_dotenv
from datetime import datetime


if len(sys.argv)!= 2 :
    print("Introducir por parametro como argumentos el ejecutable y el archivo a analizar")
    sys.exit(1)

archivo_log = sys.argv[1]

load_dotenv()
abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
shodan_key = os.getenv("SHODAN_API_KEY")
api_shodan = shodan.Shodan(shodan_key)
url = "https://api.abuseipdb.com/api/v2/check"
headers = {
    "Key": abuseipdb_key,
    "Accept": "application/json"
}
with open(archivo_log, "r") as archivo:

    intentos_por_ip = {}
    intentos_usuarios_ip_fallos = {}
    intentos_usuarios_ip_acceso = {}
    accesos_por_ip = {}
    for linea in archivo:
        linea = linea.strip()
        patron = r"(\d{2}:\d{2}:\d{2}).*(Failed|Accepted).*?(?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)" 
        resultado = re.search(patron, linea)


        if resultado:
            hora = resultado.group(1)
            acceso = resultado.group(2)
            user = resultado.group(3)
            ip = resultado.group(4)

            if acceso == "Failed":
                if ip not in intentos_por_ip:
                    intentos_por_ip[ip] = []
                intentos_por_ip[ip].append(hora)
                if ip not in intentos_usuarios_ip_fallos:
                    intentos_usuarios_ip_fallos[ip] = []
                intentos_usuarios_ip_fallos[ip].append(user)

            if acceso == "Accepted":
                if ip not in accesos_por_ip:
                    accesos_por_ip[ip] = []
                accesos_por_ip[ip].append(hora)
                if ip not in intentos_usuarios_ip_acceso:
                    intentos_usuarios_ip_acceso[ip] = []
                intentos_usuarios_ip_acceso[ip].append(user)
                
    reporte = []

    for ip, lista_horas in intentos_por_ip.items():
        intentos_convertidos = []
        for horas in lista_horas:
            nueva_hora = datetime.strptime(horas, "%H:%M:%S")
            intentos_convertidos.append(nueva_hora)
        segundos_diferencia = intentos_convertidos[-1] - intentos_convertidos[0]
        segundos = segundos_diferencia.total_seconds()
        if (segundos <= 60 and  len(intentos_convertidos) >= 5):    
            try:
                resultado_abuse = requests.get(url, headers=headers, params={"ipAddress": ip, "maxAgeInDays": 90}).json()
                abuse_score = resultado_abuse["data"]["abuseConfidenceScore"]
            except Exception:
               abuse_score = None

            try:
                resultado_shodan = api_shodan.host(ip)
                puertos_shodan = resultado_shodan.get("ports", [])
            except shodan.APIError:
                puertos_shodan = []
                
            if ip in accesos_por_ip:
                entrada = {
                    "ip": ip,
                    "severidad": "Alta",
                    "intentos_fallidos": len(intentos_convertidos),
                    "ventana_segundos": segundos,
                    "usuarios_probados": intentos_usuarios_ip_fallos[ip],
                    "acceso_exitoso": True,
                    "usuario_acceso": intentos_usuarios_ip_acceso[ip],
                    "hora_acceso": accesos_por_ip[ip][0]
                }
                entrada["abuseipdb_score"] = abuse_score
                entrada["shodan_puertos"] = puertos_shodan
                reporte.append(entrada)
            else:
                entrada = {
                    "ip": ip,
                    "severidad": "Moderada",
                    "intentos_fallidos": len(intentos_convertidos),
                    "ventana_segundos": segundos,
                    "usuarios_probados": intentos_usuarios_ip_fallos[ip],
                    "acceso_exitoso": False,
                    "hora_acceso": None
                }
                entrada["abuseipdb_score"] = abuse_score
                entrada["shodan_puertos"] = puertos_shodan
                reporte.append(entrada)
    reporte_final = {
        "fecha_del_reporte": datetime.now().strftime("%Y-%m-%d"),
        "archivo_analizado": archivo_log,
        "total_Ip_sospechosas": len(reporte),
        "alertas": reporte
    }
    
    fecha = datetime.now().strftime("%Y%m%d_%H%M%S")
    nombre_archivo = f"../reports/reporte_{fecha}.json"

    with open(nombre_archivo, "w") as archivo_salida:
        json.dump(reporte_final, archivo_salida, indent=4)