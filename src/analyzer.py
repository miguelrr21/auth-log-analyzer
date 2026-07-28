import re
from datetime import datetime

with open("../samples/auth.log", "r") as archivo:

    intentos_por_ip = {}
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
            print(hora,acceso,user,ip)

            if acceso == "Failed":
                if ip not in intentos_por_ip:
                    intentos_por_ip[ip] = []
                intentos_por_ip[ip].append(hora)

            if acceso == "Accepted":
                if ip not in accesos_por_ip:
                    accesos_por_ip[ip] = []
                accesos_por_ip[ip].append(hora)
        print(linea)

    for ip, horas in intentos_por_ip.items():
        print(f"IP: {ip} - Intentos fallidos: {len(horas)} - Horas: {horas}")
    for ip, horas in accesos_por_ip.items():
        print(f"IP: {ip} - Accesos: {len(horas)} - Horas: {horas}")

    for ip, lista_horas in intentos_por_ip.items():
        intentos_convertidos = []
        for horas in lista_horas:
            nueva_hora = datetime.strptime(horas, "%H:%M:%S")
            intentos_convertidos.append(nueva_hora)
        segundos_diferencia = intentos_convertidos[-1] - intentos_convertidos[0]
        segundos = segundos_diferencia.total_seconds()
        if (segundos <= 60 and  len(intentos_convertidos) >= 5):    
            if ip in accesos_por_ip:
                print(f"ALERTA!!! Tras {len(intentos_convertidos)} la IP {ip} ha logrado acceder correctamente en {segundos} segundos a la hora {accesos_por_ip[ip][0]}")
            else:
                print(f"IP {ip} SOSPECHOSA: {len(intentos_convertidos)} intentos en {segundos} segundos")

