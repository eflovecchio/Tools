import sys
import nmap
import concurrent.futures
from collections import defaultdict

def scan_ip_port(ip, port):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, str(port))
        if ip in nm.all_hosts() and port in nm[ip]['tcp'] and nm[ip]['tcp'][port]['state'] == 'open':
            return (ip, port, nm[ip]['tcp'][port]['product'] + " " + nm[ip]['tcp'][port]['version'])
    except nmap.NmapHostDiscoveryError as e:
        print(f'Error de descubrimiento al escanear {ip}: {e}')
    except nmap.PortScannerError as e:
        print(f'Error del escáner de puertos al escanear {ip}: {e}')
    except Exception as e:
        print(f'Error al escanear {ip} en el puerto {port}: {e}')
    return None

def write_to_file(filename, data):
    with open(filename, 'a') as file:
        file.write(data + '\n')

def main(targets_file, ports_input):
    try:
        # Leer objetivos desde el archivo
        with open(targets_file, 'r') as file:
            targets = [line.strip() for line in file.readlines()]

        # Determinar la lista de puertos
        if ports_input.endswith('.txt'):
            with open(ports_input, 'r') as file:
                ports = [int(line.strip()) for line in file.readlines()]
        else:
            ports = [int(port) for port in ports_input.split(',')]

        print(f'Escaneando IPs desde el archivo: {targets_file}')
        print(f'Escaneando puertos: {ports}')

        # Escanear IPs y puertos concurrentemente con un número alto de hilos
        open_ports = defaultdict(list)
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:  # Ajustar el número de hilos según tus necesidades
            futures = []
            for ip in targets:
                for port in ports:
                    futures.append(executor.submit(scan_ip_port, ip, port))
            
            print(f'Iniciando escaneo de {len(futures)} combinaciones de IP y puerto...')

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        ip, port, service = result
                        open_ports[port].append((ip, service))
                        write_to_file(f'{port}_abierto.txt', ip)
                        write_to_file(f'{port}_abierto_detalle_servicio.txt', f'{ip} - {service}')
                        print(f'Encontrado servicio abierto en {ip}:{port} - {service}')
                except Exception as e:
                    print(f'Error al obtener el resultado de un escaneo: {e}')

        # Obtener más detalles sobre los servicios encontrados
        with open('resultado.txt', 'w') as result_file:
            result_file.write('Detalles de los servicios encontrados:\n')
            result_file.write('**********************************\n')
            
            for port in open_ports:
                ip_abierto_file = f'{port}_abierto.txt'
                with open(ip_abierto_file, 'r') as file:
                    lines_count = sum(1 for line in file)
                
                result_file.write(f'Puerto {port}: {lines_count} IPs encontradas\n')
                
                services_count = defaultdict(int)
                for ip, service in open_ports[port]:
                    services_count[service] += 1
                
                sorted_services = sorted(services_count.items(), key=lambda item: item[1], reverse=True)
                
                result_file.write(f'Servicios en el puerto {port}:\n')
                for service, count in sorted_services:
                    result_file.write(f'{count} - {service}\n')

                result_file.write('**********************************\n')

        # Mostrar contenido de resultado.txt al finalizar
        with open('resultado.txt', 'r') as result_file:
            print('\n' + result_file.read())

    except Exception as e:
        print(f'Ocurrió un error: {e}')

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Uso: python script.py <archivo_objetivos> <entrada_puertos>')
        sys.exit(1)
    
    targets_file = sys.argv[1]
    ports_input = sys.argv[2]
    
    main(targets_file, ports_input)
