import ipaddress
import subprocess
from scapy.all import ARP, Ether, srp, sr1, IP, TCP, ICMP
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Configuración del logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Lista actualizada de puertos TCP para escaneo
tcp_ports = [22, 80, 443, 445, 3389, 1433, 3306, 25, 53, 135, 139, 23, 8080, 1723, 21, 81, 110]

def generate_ip_list(ip_range):
    ip_list = [str(ip) for ip in ipaddress.IPv4Network(ip_range)]
    logging.info(f"Generada lista de IPs para el rango {ip_range}")
    return ip_list

def is_alive(ip):
    logging.info(f"Escaneando {ip}")
    
    # Primero, realizamos un ping
    ping_response = subprocess.run(['ping', '-c', '1', '-W', '1', ip], stdout=subprocess.DEVNULL)
    if ping_response.returncode == 0:
        logging.info(f"{ip} está vivo (ping)")
        return True

    # Si el ping falla, realizamos un escaneo ARP
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        logging.info(f"{ip} está vivo (ARP)")
        return True

    # Si el escaneo ARP falla, realizamos un escaneo TCP SYN en múltiples puertos
    for port in tcp_ports:
        syn_packet = IP(dst=ip) / TCP(dport=port, flags='S')
        syn_response = sr1(syn_packet, timeout=1, verbose=False)
        if syn_response and syn_response.haslayer(TCP):
            if syn_response[TCP].flags == 0x12:
                logging.info(f"{ip} está vivo (TCP SYN en el puerto {port})")
                return True
            elif syn_response[TCP].flags == 0x14:
                # Respuesta RST, el puerto está cerrado o tcpwrapped
                logging.info(f"{ip} puerto {port} cerrado (TCP RST recibido)")
            elif syn_response[TCP].flags == 0x02:
                # Respuesta SYN, posiblemente "tcpwrapped" o filtrado
                logging.info(f"{ip} puerto {port} cerrado (TCP SYN recibido)")
            elif syn_response[TCP].flags == 0x13:
                # Respuesta ICMP, indicando probable filtrado
                logging.info(f"{ip} puerto {port} cerrado (TCP ICMP recibido)")
        elif syn_response and syn_response.haslayer(ICMP):
            # Respuesta ICMP recibida, puede indicar filtrado o puerto cerrado
            logging.info(f"{ip} puerto {port} cerrado (ICMP error recibido)")
    
    return False

def scan_ip(ip, network_file, all_file, all_alive_ips):
    if is_alive(ip):
        with open(network_file, 'a') as net_file:
            net_file.write(ip + "\n")
        with open(all_file, 'a') as all_file:
            all_file.write(ip + "\n")
        all_alive_ips[ip] = None
        return ip
    return None

def sort_and_deduplicate_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    unique_lines = sorted(set(lines))
    with open(file_path, 'w') as file:
        file.writelines(unique_lines)

def count_lines(file_path):
    with open(file_path, 'r') as file:
        line_count = sum(1 for line in file)
    return line_count

def scan_networks(file_path, max_threads=100):
    all_alive_ips = defaultdict(lambda: None)
    with open(file_path, 'r') as file:
        networks = file.readlines()
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        for network in networks:
            network = network.strip()
            if not network:
                continue
            
            logging.info(f"Escaneando el rango de red {network}")
            ip_list = generate_ip_list(network)
            network_file = f"{network.replace('/', '-')}.txt"
            
            for ip in ip_list:
                futures.append(executor.submit(scan_ip, ip, network_file, "all_alive_ips.txt", all_alive_ips))
        
        for future in as_completed(futures):
            future.result()
    
    for network in networks:
        network = network.strip()
        if not network:
            continue
        network_file = f"{network.replace('/', '-')}.txt"
        sort_and_deduplicate_file(network_file)
    
    sort_and_deduplicate_file("all_alive_ips.txt")
    
    # Obtener y mostrar el resumen
    summary_lines = []

    for network in networks:
        network = network.strip()
        if not network:
            continue
        network_file = f"{network.replace('/', '-')}.txt"
        num_alive_hosts = count_lines(network_file)
        summary_lines.append(f"Rango {network} - {num_alive_hosts} hosts vivos")
    
    total_alive_hosts = sum(count_lines(f"{network.replace('/', '-')}.txt") for network in networks)
    total_hosts = count_lines("all_alive_ips.txt")
    summary_lines.append(f"Total de {total_alive_hosts} IPs vivas encontradas en todos los rangos")
    summary_lines.append(f"Total de {total_hosts} IPs vivas en total")

    # Escribir el resumen a un archivo
    with open("resumen_alive.txt", 'w') as summary_file:
        for line in summary_lines:
            summary_file.write(line + "\n")
    
    # Mostrar el resumen por consola
    for line in summary_lines:
        logging.info(line)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    scan_networks(file_path)
