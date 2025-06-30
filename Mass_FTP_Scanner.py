import ftplib
import os
import sys
import concurrent.futures

# Archivos de salida
anonymous_file = 'anonymous.txt'
ftp_file = 'ftp.txt'
admin_file = 'admin.txt'
details_file = 'FTP_Abierto_detalle.txt'

# Credenciales a probar
credentials = [
    ('anonymous', 'anonymous'),
    ('ftp', 'ftp'),
    ('admin', 'admin')
]

def save_ip(file_name, ip):
    with open(file_name, 'a') as f:
        f.write(f'{ip}\n')

def save_details(ip, details):
    with open(details_file, 'a') as f:
        f.write(f'IP: {ip}\n')
        f.write(details)
        f.write('\n\n')

def list_files(ftp, path, details):
    try:
        items = ftp.nlst(path)
        for item in items:
            details.append(item)
            if '.' not in item:
                list_files(ftp, item, details)
    except ftplib.error_perm as e:
        pass

def attempt_login(ip, user, passwd, success_file):
    details = []
    try:
        ftp = ftplib.FTP(ip)
        ftp.login(user, passwd)
        save_ip(success_file, ip)
        list_files(ftp, '/', details)
        save_details(ip, '\n'.join(details))
        ftp.quit()
        return f"Conexión exitosa a {ip} con credenciales {user}:{passwd}"
    except ftplib.all_errors as e:
        return f"Conexión fallida a {ip} con credenciales {user}:{passwd}"

def scan_ip(ip):
    results = []
    for user, passwd in credentials:
        if user == 'anonymous':
            print(f"Escaneando {ip} con credenciales {user}:{passwd}")
            result = attempt_login(ip, user, passwd, anonymous_file)
            results.append(result)
        elif user == 'ftp':
            print(f"Escaneando {ip} con credenciales {user}:{passwd}")
            result = attempt_login(ip, user, passwd, ftp_file)
            results.append(result)
        elif user == 'admin':
            print(f"Escaneando {ip} con credenciales {user}:{passwd}")
            result = attempt_login(ip, user, passwd, admin_file)
            results.append(result)
    return results

def main(ip_list_file):
    # Leer lista de IPs del archivo proporcionado
    with open(ip_list_file, 'r') as file:
        ip_list = file.read().splitlines()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(scan_ip, ip): ip for ip in ip_list}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                data = future.result()
                for result in data:
                    print(result)
            except Exception as exc:
                print(f"Generó una excepción: {exc}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Uso: python ftp_assessment.py <archivo_de_lista_de_ips>")
    else:
        ip_list_file = sys.argv[1]
        main(ip_list_file)
