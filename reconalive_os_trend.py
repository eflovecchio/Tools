#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scanner de Red Completo - Versión Corregida
Mapea equipos vivos usando NetExec con parseo definitivo de OS
Acepta: rangos CIDR, IPs individuales, nombres DNS, desde archivo
"""

import subprocess
import threading
import time
import csv
import re
import sys
import os
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import socket
import argparse
import signal
import atexit

class NetworkScanner:
    def __init__(self, targets, threads=100, debug=False, output_file="scan_results.csv"):
        self.targets = targets  # Lista de targets a escanear
        self.threads = threads
        self.debug = debug
        self.output_file = output_file
        self.executive_file = output_file.replace('.csv', '_ejecutivo.txt')

        # Determinar qué comando usar (netexec o crackmapexec)
        self.netexec_cmd = self.detect_netexec_command()

        # Estadísticas
        self.total_hosts = 0
        self.scanned_hosts = 0
        self.live_hosts = 0
        self.results = []
        self.start_time = None
        self.lock = threading.Lock()

        # Lista final de IPs a escanear
        self.ip_list = []

        # Estadísticas del reporte
        self.os_stats = defaultdict(int)
        self.trend_stats = {"Si": 0, "No": 0, "Desconocido": 0}

        # Configurar CSV - SIN PUERTOS
        self.csv_headers = ['IP', 'Hostname', 'OS Version', 'Trend Micro']

        # Configurar debug file y buffer por host
        self.debug_file = None
        self.debug_buffer = {}  # Buffer por IP para escribir ordenadamente
        self.debug_lock = threading.Lock()  # Lock específico para debug

        # Control de procesos activos
        self.active_processes = []
        self.process_lock = threading.Lock()
        self.shutdown_requested = False

        # Registrar limpieza al salir
        atexit.register(self.cleanup_resources)
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        if self.debug:
            debug_filename = self.output_file.replace('.csv', '_debug.log')
            try:
                self.debug_file = open(debug_filename, 'w', encoding='utf-8')
                self.debug_file.write(f"=== DEBUG LOG - {datetime.now().strftime('%d/%m/%Y %H:%M:%S')} ===\n\n")
            except Exception as e:
                print(f"⚠️ No se pudo crear archivo debug: {e}")
                self.debug = False

    def detect_netexec_command(self):
        """Detectar si usar netexec o crackmapexec"""
        try:
            # Probar netexec con diferentes opciones
            result = subprocess.run(['netexec', '--help'], capture_output=True, timeout=3)
            if result.returncode == 0:
                return 'netexec'
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        try:
            # Probar crackmapexec
            result = subprocess.run(['crackmapexec', '--help'], capture_output=True, timeout=3)
            if result.returncode == 0:
                return 'crackmapexec'
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Default fallback
        return 'netexec'

    def signal_handler(self, signum, frame):
        """Manejar señales de interrupción"""
        print(f"\n⚠️ Señal {signum} recibida, iniciando limpieza...")
        self.shutdown_requested = True
        self.cleanup_resources()
        sys.exit(1)

    def cleanup_resources(self):
        """Limpiar todos los recursos antes de salir"""
        print("🔧 Iniciando limpieza de recursos...")

        # Terminar procesos activos
        with self.process_lock:
            for proc in self.active_processes[:]:
                try:
                    if proc.poll() is None:
                        proc.terminate()
                        proc.wait(timeout=2)
                    self.active_processes.remove(proc)
                except:
                    pass

        # Cerrar archivo debug
        self.close_debug_file()

        print("✅ Recursos liberados")

    def print_status(self, message, ip=None):
        """Imprimir estado con timestamp - SOLO al archivo debug, NO a consola durante escaneo"""
        if self.debug and self.debug_file and not self.debug_file.closed:
            timestamp = datetime.now().strftime("%H:%M:%S")
            debug_message = f"[{timestamp}] {message}"

            # Si tiene IP, agregar al buffer de ese host
            if ip:
                with self.debug_lock:
                    if ip not in self.debug_buffer:
                        self.debug_buffer[ip] = []
                    self.debug_buffer[ip].append(debug_message)
            else:
                # Sin IP, escribir directo al archivo
                try:
                    self.debug_file.write(debug_message + "\n")
                    self.debug_file.flush()
                except:
                    pass

    def print_console(self, message):
        """Imprimir solo en consola - para resultados ordenados"""
        print(message)

    def flush_debug_buffer(self, ip):
        """Escribir todo el buffer de debug de un IP al archivo ordenadamente"""
        if self.debug and self.debug_file and not self.debug_file.closed and ip in self.debug_buffer:
            with self.debug_lock:
                try:
                    self.debug_file.write(f"\n{'='*80}\n")
                    self.debug_file.write(f"DEBUG COMPLETO PARA {ip}\n")
                    self.debug_file.write(f"{'='*80}\n")

                    for line in self.debug_buffer[ip]:
                        self.debug_file.write(line + "\n")

                    self.debug_file.write(f"{'='*80}\n")
                    self.debug_file.write(f"FIN DEBUG {ip}\n")
                    self.debug_file.write(f"{'='*80}\n\n")
                    self.debug_file.flush()

                    # Limpiar buffer
                    del self.debug_buffer[ip]
                except:
                    pass

    def resolve_hostname(self, hostname):
        """Resolver nombre de host a IP"""
        try:
            ip = socket.gethostbyname(hostname)
            self.print_status(f"Resuelto {hostname} -> {ip}")
            return ip
        except socket.gaierror as e:
            self.print_status(f"Error resolviendo {hostname}: {e}")
            return None

    def parse_ip_range(self, ip_range):
        """Parsear rango IP (ej: 192.168.1.1-192.168.1.50)"""
        try:
            if '-' in ip_range:
                start_ip, end_ip = ip_range.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())

                if start.version != end.version:
                    raise ValueError("Versiones de IP diferentes")

                ips = []
                current = start
                while current <= end:
                    ips.append(str(current))
                    current += 1

                return ips
            else:
                return [ip_range]

        except Exception as e:
            self.print_status(f"Error parseando rango {ip_range}: {e}")
            return []

    def process_target(self, target):
        """Procesar un target individual (IP, CIDR, hostname, rango)"""
        target = target.strip()
        if not target or target.startswith('#'):
            return []

        ips = []

        try:
            # Intentar como red CIDR
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                ips = [str(ip) for ip in network.hosts()]
                self.print_status(f"CIDR {target} -> {len(ips)} IPs")

            # Intentar como rango IP (192.168.1.1-192.168.1.50)
            elif '-' in target and not target.replace('-', '').replace('.', '').replace(':', '').isalnum():
                ips = self.parse_ip_range(target)
                self.print_status(f"Rango {target} -> {len(ips)} IPs")

            # Intentar como IP individual
            elif target.replace('.', '').replace(':', '').isdigit() or ':' in target:
                try:
                    ipaddress.ip_address(target)
                    ips = [target]
                    self.print_status(f"IP {target}")
                except:
                    # Podría ser hostname
                    resolved_ip = self.resolve_hostname(target)
                    if resolved_ip:
                        ips = [resolved_ip]

            # Intentar como hostname
            else:
                resolved_ip = self.resolve_hostname(target)
                if resolved_ip:
                    ips = [resolved_ip]
                else:
                    print(f"⚠️  No se pudo resolver o procesar: {target}")

        except Exception as e:
            print(f"⚠️  Error procesando {target}: {e}")

        return ips

    def load_targets_from_file(self, filename):
        """Cargar targets desde archivo"""
        targets = []
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)

            print(f"📁 Cargadas {len(targets)} entradas desde {filename}")
            return targets

        except FileNotFoundError:
            print(f"❌ Error: Archivo {filename} no encontrado")
            return []
        except Exception as e:
            print(f"❌ Error leyendo archivo {filename}: {e}")
            return []

    def build_ip_list(self):
        """Construir lista final de IPs desde todos los targets"""
        print("🔍 Procesando targets...")

        all_ips = set()  # Usar set para evitar duplicados

        for target in self.targets:
            ips = self.process_target(target)
            all_ips.update(ips)

        self.ip_list = sorted(all_ips, key=lambda x: ipaddress.ip_address(x))
        self.total_hosts = len(self.ip_list)

        print(f"✅ Total de IPs únicas a escanear: {self.total_hosts:,}")

        if self.debug and self.total_hosts <= 50:
            print("IPs a escanear:", ', '.join(self.ip_list))

    def update_progress(self):
        """Actualizar barra de progreso - LÍNEA ÚNICA"""
        if self.total_hosts == 0:
            return

        progress = (self.scanned_hosts / self.total_hosts) * 100
        elapsed = time.time() - self.start_time

        if self.scanned_hosts > 0:
            estimated_total = (elapsed / self.scanned_hosts) * self.total_hosts
            remaining = max(0, estimated_total - elapsed)
            remaining_str = f"{int(remaining//60):02d}:{int(remaining%60):02d}"
        else:
            remaining_str = "00:00"

        elapsed_str = f"{int(elapsed//60):02d}:{int(elapsed%60):02d}"

        # LÍNEA ÚNICA CON LONGITUD FIJA para evitar pisadas
        progress_line = f"[SCAN] {progress:5.1f}% | Vivos: {self.live_hosts:3d}/{self.scanned_hosts:3d} | Tiempo: {elapsed_str} | Restante: {remaining_str}"

        # Limpiar línea completa y escribir nueva
        print(f"\r{progress_line:<80}", end='', flush=True)

    def fast_port_scan(self, ip, ports, timeout=1):
        """Escaneo rápido de puertos específicos"""
        open_ports = []

        for port in ports:
            if self.shutdown_requested:
                break

            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)

                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                    self.print_status(f"⚡ Puerto abierto {ip}:{port}", ip)

            except Exception as e:
                self.print_status(f"Error port scan {ip}:{port} - {e}", ip)
            finally:
                if sock:
                    try:
                        sock.close()
                    except:
                        pass

        return open_ports

    def run_netexec_comprehensive(self, ip, open_ports):
        """Ejecutar NetExec sin timeouts pero con detección de procesos colgados"""
        if self.shutdown_requested:
            return {}

        netexec_results = {}

        # Mapeo de puertos a protocolos NetExec
        port_to_protocol = {
            445: 'smb',
            22: 'ssh',
            5985: 'winrm',
            3389: 'rdp',
            389: 'ldap',
            636: 'ldaps',
            21: 'ftp',
            1433: 'mssql',
            3306: 'mysql',
            5432: 'postgresql',
            5900: 'vnc'  # VNC problemático
        }

        # Timeouts específicos para protocolos problemáticos
        protocol_timeouts = {
            'vnc': 45,      # VNC tiende a colgarse
            'ftp': 30,      # FTP puede ser lento
            'rdp': 45,      # RDP puede tardar
            'mssql': 60,    # MSSQL puede ser lento
            'smb': None,    # SMB sin timeout (más importante)
            'ssh': None,    # SSH sin timeout (importante)
        }

        # Determinar protocolos basado en puertos abiertos, con PRIORIDADES
        protocols_to_test = []

        # PRIORIDAD 1: SMB si está disponible (mejor info para Windows)
        if 445 in open_ports:
            protocols_to_test.append(('smb', 445))

        # PRIORIDAD 2: SSH si está disponible (mejor info para Linux)
        if 22 in open_ports:
            protocols_to_test.append(('ssh', 22))

        # PRIORIDAD 3: Otros servicios por importancia
        priority_ports = [5985, 3389, 389, 1433, 21, 5900]
        for port in priority_ports:
            if port in open_ports and port in port_to_protocol:
                protocol = port_to_protocol[port]
                protocols_to_test.append((protocol, port))

        # Si no hay puertos conocidos, probar SMB por defecto (común en Windows)
        if not protocols_to_test:
            protocols_to_test.append(('smb', 445))
            self.print_status(f"No hay puertos detectados, probando SMB por defecto", ip)

        # Ejecutar NetExec - con timeouts selectivos para protocolos problemáticos
        for protocol, port in protocols_to_test:
            if self.shutdown_requested:
                break

            try:
                timeout_value = protocol_timeouts.get(protocol)
                timeout_msg = f"timeout: {timeout_value}s" if timeout_value else "sin timeout"
                self.print_status(f"Ejecutando NetExec {protocol.upper()} en {ip}:{port} ({timeout_msg})", ip)

                cmd = [self.netexec_cmd, protocol, ip]

                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                # Registrar proceso activo
                with self.process_lock:
                    self.active_processes.append(proc)

                try:
                    if timeout_value:
                        # Protocolos problemáticos con timeout
                        stdout, stderr = proc.communicate(timeout=timeout_value)
                    else:
                        # Protocolos importantes sin timeout (SMB, SSH)
                        stdout, stderr = proc.communicate()

                    # Remover de lista activa
                    with self.process_lock:
                        if proc in self.active_processes:
                            self.active_processes.remove(proc)

                    if proc.returncode == 0 and stdout.strip():
                        output = stdout.strip()
                        netexec_results[protocol] = output
                        self.print_status(f"✅ {protocol.upper()} RESPUESTA COMPLETA ({len(output)} chars)", ip)

                        # Si SMB fue exitoso, tenemos la mejor info posible
                        if protocol == 'smb' and '[*]' in output:
                            self.print_status(f"✅ SMB con info completa obtenida, análisis exitoso", ip)

                    elif stderr:
                        error_msg = stderr.strip()
                        # Filtrar errores comunes que no son críticos
                        if not any(err in error_msg.lower() for err in ["connection refused", "errno", "network unreachable"]):
                            self.print_status(f"⚠️ {protocol.upper()} stderr: {error_msg[:100]}", ip)
                    else:
                        self.print_status(f"⚠️ {protocol.upper()} sin output útil (rc: {proc.returncode})", ip)

                except subprocess.TimeoutExpired:
                    self.print_status(f"⚠️ NetExec {protocol.upper()} TIMEOUT después de {timeout_value}s - terminando proceso", ip)
                    proc.kill()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.print_status(f"❌ Proceso {protocol.upper()} no responde a kill", ip)

                    with self.process_lock:
                        if proc in self.active_processes:
                            self.active_processes.remove(proc)

                except Exception as comm_error:
                    self.print_status(f"❌ Error comunicando con NetExec {protocol.upper()}: {str(comm_error)[:50]}", ip)
                    with self.process_lock:
                        if proc in self.active_processes:
                            self.active_processes.remove(proc)

            except FileNotFoundError:
                self.print_status(f"❌ NetExec no encontrado", ip)
                break
            except Exception as e:
                self.print_status(f"❌ Error NetExec {protocol} en {ip}: {str(e)[:50]}", ip)
                # Limpiar proceso si quedó registrado
                with self.process_lock:
                    if 'proc' in locals() and proc in self.active_processes:
                        self.active_processes.remove(proc)

        return netexec_results

    def intelligent_os_parsing(self, netexec_results, ip):
        """Parseo súper inteligente de sistemas operativos con patrón definitivo"""
        hostname = "Desconocido"
        os_version = "Desconocido"
        os_type = "Desconocido"
        raw_data = []

        self.print_status(f"🧠 INICIANDO PARSEO INTELIGENTE PARA {ip}", ip)

        # FASE 1: ANÁLISIS SMB (MÁXIMA PRIORIDAD)
        if 'smb' in netexec_results:
            smb_output = netexec_results['smb']
            self.print_status(f"📋 SMB OUTPUT COMPLETO: {smb_output}", ip)

            # Extraer hostname del SMB - MÚLTIPLES PATRONES ROBUSTOS
            hostname_patterns = [
                r'SMB\s+[\d\.]+\s+445\s+([^\s]+)',      # SMB IP 445 HOSTNAME
                r'\s+445\s+([^\s]+)\s+\[\*\]',          # 445 HOSTNAME [*]
                r'\(name:([^)]+)\)',                     # (name:HOSTNAME)
                r'445\s+([A-Za-z0-9\-_]+)\s+\[\*\]'     # Más permisivo
            ]

            for i, pattern in enumerate(hostname_patterns, 1):
                match = re.search(pattern, smb_output)
                if match:
                    extracted_hostname = match.group(1).strip()
                    if extracted_hostname and extracted_hostname != ip:
                        hostname = extracted_hostname
                        self.print_status(f"🏷️ Hostname extraído (patrón {i}): '{hostname}'", ip)
                        break

            if hostname == "Desconocido":
                self.print_status(f"⚠️ TODOS los patrones hostname fallaron", ip)

            # Análisis de OS - ROBUSTO CON MÚLTIPLES PATRONES
            if '[*] Unix' in smb_output:
                os_version = "Linux"
                os_type = "Linux"
                self.print_status(f"🐧 Unix detectado → Linux", ip)

            elif '[*]' in smb_output:
                self.print_status(f"🔍 Intentando múltiples patrones de Windows...", ip)

                # PATRÓN 1: Hasta x32/x64 (más común)
                pattern1 = r'\[\*\]\s+(.+?x(?:32|64))'
                match1 = re.search(pattern1, smb_output)

                if match1:
                    os_version = match1.group(1)
                    os_type = "Windows"
                    self.print_status(f"🪟 OS extraído (patrón x32/x64): '{os_version}'", ip)
                    raw_data.append(f"SMB-Pattern1: {os_version}")
                else:
                    # PATRÓN 2: Desde [*] hasta primer paréntesis (MEJORADO)
                    self.print_status(f"🔍 Patrón x32/x64 falló, probando hasta paréntesis...", ip)
                    pattern2 = r'\[\*\]\s+([^(]+)'
                    match2 = re.search(pattern2, smb_output)

                    if match2:
                        os_version = match2.group(1).strip()
                        os_type = "Windows"
                        self.print_status(f"🪟 OS extraído (patrón paréntesis): '{os_version}'", ip)
                        raw_data.append(f"SMB-Pattern2: {os_version}")
                    else:
                        self.print_status(f"❌ TODOS los patrones OS fallaron", ip)
            else:
                self.print_status(f"⚠️ No hay [*] en output SMB: {smb_output}", ip)

            # Extraer información adicional del SMB
            domain_match = re.search(r'\(domain:([^)]+)\)', smb_output)
            if domain_match:
                domain = domain_match.group(1).strip()
                raw_data.append(f"Domain: {domain}")
                self.print_status(f"🌐 Dominio extraído: '{domain}'", ip)

            signing_match = re.search(r'\(signing:([^)]+)\)', smb_output)
            if signing_match:
                signing = signing_match.group(1).strip()
                raw_data.append(f"SMB Signing: {signing}")
                self.print_status(f"🔐 SMB Signing: {signing}", ip)

            smb1_match = re.search(r'\(SMBv1:([^)]+)\)', smb_output)
            if smb1_match:
                smb1 = smb1_match.group(1).strip()
                raw_data.append(f"SMBv1: {smb1}")
                self.print_status(f"📡 SMBv1: {smb1}", ip)

        # FASE 2: ANÁLISIS SSH (PARA LINUX)
        if 'ssh' in netexec_results and (os_version == "Desconocido" or os_type != "Windows"):
            ssh_output = netexec_results['ssh']
            self.print_status(f"🐧 SSH RAW COMPLETO: {ssh_output}", ip)

            # Extraer banner SSH completo con múltiples patrones
            ssh_patterns = [
                r'\[\*\]\s+(SSH-[\d\.]+-[^\r\n]+)',
                r'SSH-[\d\.]+-([^\r\n]+)',
                r'\[\*\]\s+(.+SSH.+)'
            ]

            for pattern in ssh_patterns:
                match = re.search(pattern, ssh_output, re.IGNORECASE)
                if match:
                    ssh_banner = match.group(1).strip()
                    self.print_status(f"📡 SSH Banner extraído: '{ssh_banner}'", ip)
                    raw_data.append(f"SSH: {ssh_banner}")

                    # Análisis detallado del banner SSH - SIMPLIFICADO
                    if ssh_banner:
                        os_version = "Linux"
                        os_type = "Linux"
                        self.print_status(f"🐧 OS detectado por SSH: Linux", ip)
                        raw_data.append(f"SSH: Linux")
                        break

            # Intentar extraer hostname del SSH
            if hostname == "Desconocido":
                ssh_hostname_patterns = [
                    r'22\s+([A-Za-z0-9\-\.]+)\s+\[\*\]',
                    r'SSH\s+[\d\.]+\s+22\s+([A-Za-z0-9\-\.]+)'
                ]

                for pattern in ssh_hostname_patterns:
                    match = re.search(pattern, ssh_output)
                    if match:
                        potential_hostname = match.group(1)
                        if not potential_hostname.replace('.', '').isdigit():
                            hostname = potential_hostname
                            self.print_status(f"🏷️ Hostname SSH extraído: '{hostname}'", ip)
                            break

        # FASE 3: ANÁLISIS DE OTROS SERVICIOS - SOLO SI SMB NO DETECTÓ NADA
        if os_version == "Desconocido":
            self.print_status(f"🔧 SMB no detectó OS, analizando otros servicios...", ip)
            for service in ['winrm', 'rdp', 'ldap', 'ftp', 'mssql']:
                if service in netexec_results:
                    service_output = netexec_results[service]
                    self.print_status(f"🔧 {service.upper()} RAW: {service_output}", ip)
                    raw_data.append(f"{service.upper()}: detected")

                    if os_version == "Desconocido":
                        if service in ['winrm', 'rdp', 'ldap', 'mssql']:
                            os_version = "Windows Server"
                            os_type = "Windows"
                            self.print_status(f"🪟 OS fallback detectado por {service.upper()}: '{os_version}'", ip)
                            break
                        elif service == 'ftp':
                            if 'Microsoft' in service_output:
                                os_version = "Windows Server"
                                os_type = "Windows"
                                break
                            elif 'vsftpd' in service_output:
                                os_version = "Linux"
                                os_type = "Linux"
                                break
        else:
            self.print_status(f"✅ SMB ya detectó OS, saltando análisis de otros servicios", ip)

        # FASE 4: LOGGING COMPLETO Y FINAL
        self.print_status(f"🎯 RESULTADO FINAL DEL PARSING:", ip)
        self.print_status(f"   📍 IP: {ip}", ip)
        self.print_status(f"   🏷️ Hostname: '{hostname}'", ip)
        self.print_status(f"   💻 OS Version: '{os_version}'", ip)
        self.print_status(f"   📊 OS Type: '{os_type}'", ip)
        self.print_status(f"   📋 Raw Data Collected: {raw_data}", ip)

        return hostname, os_version, os_type

    def resolve_hostname_dns(self, ip):
        """Resolver hostname usando ping -a y nslookup"""
        try:
            # Método 1: ping -a
            if os.name == 'nt':  # Windows
                cmd = ['ping', '-a', '-n', '1', ip]
            else:  # Linux/Unix
                cmd = ['ping', '-a', '-c', '1', '-W', '2', ip]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                output = result.stdout
                # Buscar hostname en la salida
                hostname_match = re.search(r'PING\s+([^\s\(]+)', output, re.IGNORECASE)
                if hostname_match:
                    potential_hostname = hostname_match.group(1)
                    if potential_hostname != ip and not potential_hostname.replace('.', '').isdigit():
                        self.print_status(f"🔍 Hostname DNS (ping): '{potential_hostname}'", ip)
                        return potential_hostname

            # Método 2: nslookup
            cmd = ['nslookup', ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                output = result.stdout
                name_match = re.search(r'name\s*=\s*([^\s\r\n]+)', output, re.IGNORECASE)
                if name_match:
                    hostname = name_match.group(1).rstrip('.')
                    if hostname != ip:
                        self.print_status(f"🔍 Hostname DNS (nslookup): '{hostname}'", ip)
                        return hostname

            return None

        except Exception as e:
            self.print_status(f"Error resolviendo DNS para {ip}: {e}", ip)
            return None

    def banner_grabbing(self, ip, port, timeout=3):
        """Realizar banner grabbing en un puerto específico"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            if sock.connect_ex((ip, port)) == 0:
                if port in [80, 8080, 8000, 8443]:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 443:
                    try:
                        import ssl
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        sock = context.wrap_socket(sock, server_hostname=ip)
                        sock.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    except:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port in [22, 21, 23, 25]:
                    pass  # Estos servicios envían banner automáticamente
                else:
                    sock.send(b"\r\n")

                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner.strip()

        except Exception as e:
            self.print_status(f"Error banner grabbing {ip}:{port} - {e}", ip)
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass

        return None

    def detect_os_by_ttl(self, ip):
        """Detectar OS basado en TTL del ping"""
        try:
            if os.name == 'nt':  # Windows
                cmd = ['ping', '-n', '1', ip]
            else:  # Linux/Unix
                cmd = ['ping', '-c', '1', ip]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                output = result.stdout

                ttl_match = re.search(r'ttl=(\d+)', output, re.IGNORECASE)
                if not ttl_match:
                    ttl_match = re.search(r'TTL=(\d+)', output)

                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    self.print_status(f"🕐 TTL detectado para {ip}: {ttl}", ip)

                    if ttl <= 64:
                        return "Linux"
                    elif ttl <= 128:
                        return f"Windows TTL {ttl}"
                    elif ttl <= 255:
                        return f"Router TTL {ttl}"
                    else:
                        return f"Desconocido TTL {ttl}"

            return "TTL no detectado"

        except Exception as e:
            self.print_status(f"Error detectando TTL para {ip}: {e}", ip)
            return "Error TTL"

    def advanced_port_scan_trend(self, ip):
        """Escaneo avanzado de puertos de Trend Micro - SIN 8080 Y 8443"""
        # PUERTOS REMOVIDOS: 8080 y 8443 como solicitaste
        trend_ports = {
            21112: "Trend Micro Control Manager",
            43190: "Trend Micro Security Agent",
            4343: "Trend Micro Management Console",
            4118: "Trend Micro OfficeScan",
            4122: "Trend Micro ServerProtect"
        }

        detected_services = []
        open_trend_ports = []

        for port, service_name in trend_ports.items():
            if self.shutdown_requested:
                break

            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)

                if sock.connect_ex((ip, port)) == 0:
                    open_trend_ports.append(port)
                    detected_services.append(service_name)
                    self.print_status(f"🛡️ Puerto Trend {ip}:{port} ({service_name}) ABIERTO", ip)

                    # Banner grabbing específico para Trend - SIMPLIFICADO
                    try:
                        sock.settimeout(2)
                        banner = sock.recv(256).decode('utf-8', errors='ignore')
                        if banner.strip():
                            self.print_status(f"📋 Banner {ip}:{port}: {banner.strip()[:50]}", ip)
                    except:
                        pass

            except Exception as e:
                self.print_status(f"Error escaneando puerto Trend {ip}:{port}: {e}", ip)
            finally:
                if sock:
                    try:
                        sock.close()
                    except:
                        pass

        if open_trend_ports:
            self.print_status(f"✅ Trend Micro detectado en {ip}: puertos {open_trend_ports}", ip)
            return "Si"
        else:
            return "No"

    def scan_host(self, ip):
        """Escanear un host individual con análisis súper completo"""
        if self.shutdown_requested:
            return

        try:
            self.print_status(f"\n{'='*80}", ip)
            self.print_status(f"🎯 INICIANDO ANÁLISIS DE {ip}", ip)
            self.print_status(f"{'='*80}", ip)

            # PASO 0: Resolución DNS inicial
            self.print_status(f"[0/4] 🔍 Resolviendo hostname DNS para {ip}", ip)
            dns_hostname = self.resolve_hostname_dns(ip)

            # PASO 1: Port scan rápido
            self.print_status(f"[1/4] ⚡ Port scan rápido en {ip}", ip)
            target_ports = [445, 22, 5985, 3389, 389, 636, 21, 1433, 3306, 5432, 5900]
            open_ports = self.fast_port_scan(ip, target_ports, timeout=1)

            if open_ports:
                self.print_status(f"✅ Puertos abiertos detectados: {','.join(map(str, open_ports))}", ip)
            else:
                self.print_status(f"⚠️ No hay servicios conocidos detectados en puertos objetivo", ip)

            # PASO 2: NetExec comprehensive
            self.print_status(f"[2/4] 🔍 NetExec comprehensive en {ip}", ip)
            netexec_results = self.run_netexec_comprehensive(ip, open_ports)

            hostname = "Desconocido"
            os_version = "Desconocido"

            if netexec_results:
                hostname, os_version, os_type = self.intelligent_os_parsing(netexec_results, ip)
                self.print_status(f"✅ NetExec parsing completado", ip)
                self.print_status(f"   🔍 Hostname obtenido: '{hostname}'", ip)
                self.print_status(f"   🔍 OS obtenido: '{os_version}'", ip)
            else:
                self.print_status(f"⚠️ NetExec no obtuvo resultados útiles", ip)

            # PASO 2.5: Usar hostname DNS si NetExec no obtuvo uno
            if hostname == "Desconocido" and dns_hostname:
                hostname = dns_hostname
                self.print_status(f"✅ Usando hostname DNS como fallback: '{hostname}'", ip)

            # PASO 3: Análisis fallback SOLO si NetExec completamente falló
            if os_version == "Desconocido":
                self.print_status(f"[3/4] 🔧 Análisis fallback por puertos en {ip}", ip)

                if 445 in open_ports:
                    os_version = "Windows Server"
                    self.print_status(f"🪟 OS fallback por puerto SMB (445): Windows Server", ip)
                elif 3389 in open_ports and 5985 in open_ports:
                    os_version = "Windows Server"
                    self.print_status(f"🪟 OS fallback por RDP+WinRM: Windows Server", ip)
                elif 3389 in open_ports:
                    os_version = "Windows"
                    self.print_status(f"🪟 OS fallback por puerto RDP (3389): Windows", ip)
                elif 22 in open_ports:
                    os_version = "Linux"
                    self.print_status(f"🐧 OS fallback por puerto SSH (22): Linux", ip)
                elif 1433 in open_ports:
                    os_version = "Windows Server"
                    self.print_status(f"🪟 OS fallback por puerto MSSQL (1433): Windows Server", ip)
                else:
                    # TTL como último recurso
                    ttl_result = self.detect_os_by_ttl(ip)
                    if ttl_result not in ["TTL no detectado", "Error TTL"]:
                        os_version = ttl_result
                        self.print_status(f"🕐 OS fallback por TTL: {os_version}", ip)
            else:
                self.print_status(f"[3/4] ✅ Saltando análisis fallback (NetExec exitoso con: '{os_version}')", ip)

            # PASO 4: Análisis Trend Micro
            self.print_status(f"[4/4] 🛡️ Verificación Trend Micro en {ip}", ip)
            trend_status = self.advanced_port_scan_trend(ip)

            # Validación final de datos
            if not hostname or hostname.strip() == "":
                hostname = "Desconocido"
            if not os_version or os_version.strip() == "":
                os_version = "Desconocido"
            if not trend_status or trend_status.strip() == "":
                trend_status = "Desconocido"

            # Guardar resultado
            result = {
                'ip': str(ip),
                'hostname': str(hostname).strip(),
                'os_version': str(os_version).strip(),
                'trend_micro': str(trend_status).strip()
            }

            with self.lock:
                self.results.append(result)
                self.live_hosts += 1

                # Actualizar estadísticas
                self.os_stats[str(os_version)] += 1
                self.trend_stats[str(trend_status)] += 1

            self.print_status(f"🎯 RESULTADO FINAL CONSOLIDADO:", ip)
            self.print_status(f"   📍 IP: {ip}", ip)
            self.print_status(f"   🏷️ Hostname: '{hostname}'", ip)
            self.print_status(f"   💻 OS Version: '{os_version}'", ip)
            self.print_status(f"   🛡️ Trend Micro: '{trend_status}'", ip)

            self.print_status(f"{'='*80}", ip)
            self.print_status(f"🏁 FIN ANÁLISIS DE {ip}", ip)
            self.print_status(f"{'='*80}\n", ip)

            # Limpiar buffer debug para este IP
            self.flush_debug_buffer(ip)

        except Exception as e:
            self.print_status(f"❌ Error crítico escaneando {ip}: {e}", ip)

            try:
                with self.lock:
                    error_result = {
                        'ip': str(ip),
                        'hostname': "Error",
                        'os_version': f"Error: {str(e)[:50]}",
                        'trend_micro': "Desconocido"
                    }
                    self.results.append(error_result)
                    self.live_hosts += 1
                    self.os_stats["Error"] += 1
                    self.trend_stats["Desconocido"] += 1
            except:
                pass

        finally:
            with self.lock:
                self.scanned_hosts += 1
                self.update_progress()

    def ping_sweep(self, ip):
        """Verificar si el host está vivo con ping"""
        if self.shutdown_requested:
            return None

        try:
            cmd = ['ping', '-c', '1', '-W', '1', ip] if os.name != 'nt' else ['ping', '-n', '1', '-w', '1000', ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)

            if result.returncode == 0:
                return ip
            return None

        except Exception:
            return None

    def wait_for_threads_completion(self, executor, futures, timeout=None, show_progress=False):
        """Esperar a que todos los threads terminen - SIN TIMEOUT para escaneos masivos"""
        completed = 0
        total = len(futures)
        start_time = time.time()

        try:
            # SIN TIMEOUT - para escaneos de millones de IPs
            for future in as_completed(futures):
                try:
                    future.result(timeout=1)
                    completed += 1
                except Exception as e:
                    if self.debug:
                        self.print_status(f"Error en thread: {e}")
                    completed += 1

                # SOLO mostrar progreso si se solicita Y no hay otro progreso activo
                if show_progress and completed % 1000 == 0:
                    elapsed = time.time() - start_time
                    remaining = total - completed
                    print(f"\r[THREADS] {completed:,}/{total:,} completados ({elapsed:.0f}s restantes: {remaining:,})", end='', flush=True)

        except Exception as error:
            elapsed = time.time() - start_time
            print(f"\n⚠️ Error en threads después de {elapsed:.1f}s - Completados: {completed:,}/{total:,}")

            # Intentar obtener resultados de futures pendientes
            for future in futures:
                if not future.done():
                    try:
                        future.result(timeout=0.1)
                        completed += 1
                    except:
                        pass

        if show_progress:
            print(f"\n✅ Threads finalizados: {completed:,}/{total:,}")

        return completed

    def scan_network(self):
        """Escanear toda la lista de IPs con manejo mejorado de threads"""
        print(f"🎯 Escaneando {self.total_hosts:,} hosts...")
        print(f"⚡ Configuración: {self.threads} threads | Debug: {'ON' if self.debug else 'OFF'}")
        print(f"🕐 Iniciado: {datetime.now().strftime('%H:%M:%S')}")
        print("-" * 60)

        self.start_time = time.time()

        try:
            # Primer paso: ping sweep
            live_ips = []
            print("🔍 Buscando hosts vivos...")

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                ping_futures = [executor.submit(self.ping_sweep, ip) for ip in self.ip_list]

                try:
                    print(f"⏱️ SIN TIMEOUT - Procesando {self.total_hosts:,} hosts sin límite de tiempo")

                    # SIN TIMEOUT - para escaneos masivos
                    self.wait_for_threads_completion(executor, ping_futures, timeout=None, show_progress=False)

                    for future in ping_futures:
                        try:
                            result = future.result(timeout=1)
                            if result:
                                live_ips.append(result)
                        except:
                            pass

                        with self.lock:
                            self.scanned_hosts += 1
                            if self.scanned_hosts % 10000 == 0:  # Progreso cada 10K para rangos masivos
                                print(f"\rPing sweep: {self.scanned_hosts:,}/{self.total_hosts:,} - Vivos encontrados: {len(live_ips):,}", end='', flush=True)

                except Exception as e:
                    print(f"\n⚠️ Error en ping sweep: {e}")
                    # Continuar con los IPs encontrados hasta ahora

            print(f"\n✅ Encontrados {len(live_ips)} hosts vivos")

            if not live_ips:
                print("❌ No se encontraron hosts vivos")
                return

            print("🔬 Recolectando información detallada...")

            # Reset para la segunda fase
            self.scanned_hosts = 0
            self.total_hosts = len(live_ips)

            # Segundo paso: análisis detallado - SIN timeouts para escaneos masivos
            max_detailed_threads = min(self.threads // 2, 25)
            print(f"\n⚡ Usando {max_detailed_threads} threads para análisis detallado")
            print("⏱️ NetExec y análisis detallado SIN TIMEOUTS - procesamiento completo garantizado\n")

            with ThreadPoolExecutor(max_workers=max_detailed_threads) as executor:
                scan_futures = [executor.submit(self.scan_host, ip) for ip in live_ips]

                try:
                    # SIN TIMEOUT - procesamiento completo sin interrupciones
                    completed_threads = self.wait_for_threads_completion(executor, scan_futures, timeout=None, show_progress=False)

                    # FORZAR finalización de threads pendientes si los hay
                    pending_threads = len(scan_futures) - completed_threads
                    if pending_threads > 0:
                        print(f"⚠️ Finalizando {pending_threads} threads pendientes...")

                        # Intentar obtener resultados rápidamente
                        for future in scan_futures:
                            if not future.done():
                                try:
                                    future.result(timeout=0.5)
                                except:
                                    pass

                        # Forzar shutdown del executor
                        executor.shutdown(wait=False)
                        print("🔧 Executor forzado a cerrar")

                except Exception as e:
                    print(f"\n⚠️ Error en análisis detallado: {e}")
                    print("📊 Continuando con resultados obtenidos hasta ahora...")
                    # Forzar shutdown en caso de error
                    executor.shutdown(wait=False)

                finally:
                    # Forzar finalización de línea de progreso
                    print(f"\n✅ Análisis completado - procesando resultados...")

        except KeyboardInterrupt:
            print(f"\n⚠️ Escaneo interrumpido por el usuario")
            self.shutdown_requested = True
        except Exception as e:
            print(f"\n❌ Error durante el escaneo: {e}")

        # LIMPIEZA AGRESIVA - No esperar threads colgados
        print("🔧 Iniciando limpieza agresiva de recursos...")

        # 1. Terminar TODOS los procesos NetExec inmediatamente
        with self.process_lock:
            active_count = len(self.active_processes)
            if active_count > 0:
                print(f"⏳ Terminando {active_count} procesos NetExec...")
                for proc in self.active_processes[:]:
                    try:
                        if proc.poll() is None:
                            proc.kill()  # KILL directo, no terminate
                            try:
                                proc.wait(timeout=2)
                            except subprocess.TimeoutExpired:
                                pass  # Ignorar si no responde
                        self.active_processes.remove(proc)
                    except:
                        pass

        # 2. Cerrar archivos debug inmediatamente
        if self.debug_file and not self.debug_file.closed:
            try:
                self.debug_file.close()
            except:
                pass

        print(f"📊 Escaneo finalizado - {self.live_hosts} hosts procesados")
        print("⚡ Procediendo inmediatamente al guardado de archivos...")

        # NO esperar más - proceder directamente al guardado

    def save_results(self):
        """Guardar resultados en CSV de forma segura"""
        print("💾 Guardando resultados en CSV...")

        try:
            # Asegurar que tenemos resultados
            if not self.results:
                print("⚠️ No hay resultados para guardar")
                return

            # Crear directorio si no existe
            output_dir = os.path.dirname(self.output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)

            with open(self.output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(self.csv_headers)

                # Ordenar por IP
                sorted_results = sorted(self.results, key=lambda x: ipaddress.ip_address(x['ip']))

                for result in sorted_results:
                    row = [
                        result.get('ip', 'Error'),
                        result.get('hostname', 'Desconocido'),
                        result.get('os_version', 'Desconocido'),
                        result.get('trend_micro', 'Desconocido')
                    ]

                    # Limpiar valores None o vacíos
                    row = [str(item).strip() if item and str(item).strip() else 'Desconocido' for item in row]
                    writer.writerow(row)

            print(f"✅ CSV guardado exitosamente: {self.output_file}")
            print(f"📊 Total de registros: {len(self.results)}")

        except Exception as e:
            print(f"❌ Error guardando CSV: {e}")

            # Intentar backup
            try:
                backup_file = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                with open(backup_file, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(self.csv_headers)
                    for result in self.results:
                        writer.writerow([
                            str(result.get('ip', 'Error')),
                            str(result.get('hostname', 'Backup')),
                            str(result.get('os_version', 'Error en procesamiento')),
                            str(result.get('trend_micro', 'Desconocido'))
                        ])
                print(f"💾 Backup guardado en: {backup_file}")
            except Exception as backup_error:
                print(f"❌ Error en backup: {backup_error}")

    def generate_executive_report(self):
        """Generar reporte ejecutivo con estadísticas separadas por OS"""
        print("📋 Generando reporte ejecutivo...")

        try:
            if not self.results:
                print("⚠️ No hay resultados para el reporte")
                return

            # Crear directorio si no existe
            output_dir = os.path.dirname(self.executive_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)

            with open(self.executive_file, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("REPORTE EJECUTIVO - ESCANEO DE RED\n")
                f.write("=" * 60 + "\n\n")

                f.write(f"📅 Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
                f.write(f"🎯 Targets procesados: {len(self.targets)}\n")
                f.write(f"📍 IPs totales analizadas: {len(self.ip_list)}\n")
                f.write(f"💻 Hosts vivos encontrados: {self.live_hosts}\n")
                f.write(f"⚡ Configuración: {self.threads} threads\n\n")

                # Estadísticas de OS
                f.write("SISTEMAS OPERATIVOS ENCONTRADOS\n")
                f.write("-" * 35 + "\n")

                for os_name, count in sorted(self.os_stats.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / self.live_hosts * 100) if self.live_hosts > 0 else 0
                    f.write(f"{str(os_name)[:30]:<30}: {count:>3} ({percentage:.1f}%)\n")

                # NUEVA SECCIÓN: Estadísticas TREND MICRO POR OS
                f.write(f"\nTREND MICRO ANTIVIRUS - DISTRIBUCIÓN POR OS\n")
                f.write("-" * 45 + "\n")

                # Separar resultados por tipo de OS
                windows_results = []
                linux_results = []
                other_results = []

                for result in self.results:
                    os_version = str(result.get('os_version', 'Desconocido')).lower()
                    trend_status = result.get('trend_micro', 'Desconocido')

                    if 'windows' in os_version or 'microsoft' in os_version:
                        windows_results.append(trend_status)
                    elif 'linux' in os_version or 'unix' in os_version or 'ubuntu' in os_version or 'centos' in os_version:
                        linux_results.append(trend_status)
                    else:
                        other_results.append(trend_status)

                # Estadísticas Windows
                if windows_results:
                    f.write(f"\n🪟 WINDOWS ({len(windows_results)} hosts):\n")
                    windows_trend_stats = defaultdict(int)
                    for status in windows_results:
                        windows_trend_stats[status] += 1

                    for status, count in windows_trend_stats.items():
                        percentage = (count / len(windows_results) * 100)
                        f.write(f"  {status[:15]:<15}: {count:>3} ({percentage:.1f}%)\n")

                # Estadísticas Linux
                if linux_results:
                    f.write(f"\n🐧 LINUX ({len(linux_results)} hosts):\n")
                    linux_trend_stats = defaultdict(int)
                    for status in linux_results:
                        linux_trend_stats[status] += 1

                    for status, count in linux_trend_stats.items():
                        percentage = (count / len(linux_results) * 100)
                        f.write(f"  {status[:15]:<15}: {count:>3} ({percentage:.1f}%)\n")

                # Otros sistemas
                if other_results:
                    f.write(f"\n❓ OTROS SISTEMAS ({len(other_results)} hosts):\n")
                    other_trend_stats = defaultdict(int)
                    for status in other_results:
                        other_trend_stats[status] += 1

                    for status, count in other_trend_stats.items():
                        percentage = (count / len(other_results) * 100)
                        f.write(f"  {status[:15]:<15}: {count:>3} ({percentage:.1f}%)\n")

                # Estadísticas generales de Trend Micro
                f.write(f"\nTREND MICRO ANTIVIRUS - TOTAL GENERAL\n")
                f.write("-" * 40 + "\n")

                for status, count in self.trend_stats.items():
                    percentage = (count / self.live_hosts * 100) if self.live_hosts > 0 else 0
                    f.write(f"{status[:15]:<15}: {count:>3} ({percentage:.1f}%)\n")

                # Resumen de hosts
                f.write(f"\nRESUMEN DE HOSTS\n")
                f.write("-" * 120 + "\n")
                f.write(f"{'IP':<15} {'Hostname':<30} {'OS':<60} {'Trend'}\n")
                f.write("-" * 120 + "\n")

                try:
                    sorted_results = sorted(self.results, key=lambda x: ipaddress.ip_address(str(x.get('ip', '0.0.0.0'))))
                    for result in sorted_results:
                        ip = str(result.get('ip', 'Error'))[:14]
                        hostname = str(result.get('hostname', 'Desconocido'))[:29]
                        os_version = str(result.get('os_version', 'Desconocido'))[:59]
                        trend = str(result.get('trend_micro', 'Desconocido'))

                        f.write(f"{ip:<15} {hostname:<30} {os_version:<60} {trend}\n")

                except Exception as sort_error:
                    f.write(f"Error ordenando resultados: {sort_error}\n")
                    # Escribir sin ordenar
                    for result in self.results:
                        ip = str(result.get('ip', 'Error'))[:14]
                        hostname = str(result.get('hostname', 'Desconocido'))[:29]
                        os_version = str(result.get('os_version', 'Desconocido'))[:59]
                        trend = str(result.get('trend_micro', 'Desconocido'))
                        f.write(f"{ip:<15} {hostname:<30} {os_version:<60} {trend}\n")

            print(f"✅ Reporte ejecutivo guardado: {self.executive_file}")

        except Exception as e:
            print(f"❌ Error generando reporte ejecutivo: {e}")

    def close_debug_file(self):
        """Cerrar archivo de debug de forma segura"""
        try:
            if self.debug_file and not self.debug_file.closed:
                print("📝 Cerrando archivo debug...")

                # Escribir cualquier buffer pendiente
                with self.debug_lock:
                    for ip, messages in self.debug_buffer.items():
                        self.debug_file.write(f"\n{'='*80}\n")
                        self.debug_file.write(f"DEBUG PENDIENTE PARA {ip}\n")
                        self.debug_file.write(f"{'='*80}\n")
                        for message in messages:
                            self.debug_file.write(message + "\n")
                    self.debug_buffer.clear()

                self.debug_file.write(f"\n=== FIN DEL LOG - {datetime.now().strftime('%H:%M:%S')} ===\n")
                self.debug_file.flush()
                self.debug_file.close()
                print("✅ Debug log cerrado correctamente")

        except Exception as e:
            print(f"⚠️ Error cerrando debug file: {e}")
            if self.debug_file:
                try:
                    self.debug_file.close()
                except:
                    pass

def main():
    parser = argparse.ArgumentParser(
        description='Scanner de Red con NetExec - Parseo Definitivo de OS',
        epilog='''
Ejemplos de uso:
  %(prog)s 192.168.1.0/24
  %(prog)s 10.0.0.1 10.0.0.5 google.com
  %(prog)s -f targets.txt
  %(prog)s -f hosts.txt 8.8.8.8 --debug
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('targets', nargs='*',
                       help='IPs, rangos CIDR, hostnames o rangos')
    parser.add_argument('-f', '--file',
                       help='Archivo con lista de targets')
    parser.add_argument('-t', '--threads', type=int, default=100,
                       help='Número de threads (default: 100)')
    parser.add_argument('-o', '--output', default='scan_results.csv',
                       help='Archivo de salida (default: scan_results.csv)')
    parser.add_argument('-d', '--debug', action='store_true',
                       help='Activar modo debug con archivo log')

    args = parser.parse_args()

    # Validar entrada
    all_targets = []

    if args.targets:
        all_targets.extend(args.targets)

    if args.file:
        scanner_temp = NetworkScanner([], debug=args.debug)
        file_targets = scanner_temp.load_targets_from_file(args.file)
        all_targets.extend(file_targets)
        scanner_temp.cleanup_resources()

    if not all_targets:
        print("❌ Error: Especificá al menos un target o un archivo con targets")
        sys.exit(1)

    # Verificar NetExec/CrackMapExec
    try:
        # Probar netexec
        result = subprocess.run(['netexec', '--help'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"✅ NetExec encontrado y funcionando")
        else:
            raise FileNotFoundError()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        try:
            # Probar crackmapexec como alternativa
            result = subprocess.run(['crackmapexec', '--help'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"✅ CrackMapExec encontrado y funcionando")
            else:
                print("❌ Error: ni netexec ni crackmapexec están instalados o no están en el PATH")
                sys.exit(1)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("❌ Error: ni netexec ni crackmapexec están instalados o no están en el PATH")
            sys.exit(1)
    except Exception as e:
        print(f"⚠️ Advertencia verificando netexec/crackmapexec: {e}")
        print("⚡ Continuando con la ejecución...")

    print(f"🎯 Configuración: {len(all_targets)} targets especificados")
    if args.debug:
        print("📋 Targets:", ', '.join(all_targets[:10]) + ('...' if len(all_targets) > 10 else ''))

    # Crear scanner
    scanner = NetworkScanner(
        targets=all_targets,
        threads=args.threads,
        debug=args.debug,
        output_file=args.output
    )

    try:
        # Construir lista de IPs
        scanner.build_ip_list()

        if scanner.total_hosts == 0:
            print("❌ No se pudieron procesar targets válidos")
            sys.exit(1)

        # Ejecutar escaneo
        scanner.scan_network()

        print("\n" + "="*60)
        print("📊 FINALIZANDO Y GUARDANDO RESULTADOS")
        print("="*60)

        # GARANTIZAR que los archivos se generen
        try:
            scanner.save_results()
            print("✅ CSV guardado exitosamente")
        except Exception as e:
            print(f"❌ Error guardando CSV: {e}")
            print("🔄 Intentando guardado de emergencia...")
            try:
                # Guardado de emergencia simple
                emergency_file = f"emergency_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                with open(emergency_file, 'w', newline='', encoding='utf-8') as f:
                    f.write("IP,Hostname,OS Version,Trend Micro\n")
                    for result in scanner.results:
                        f.write(f"{result.get('ip','Error')},{result.get('hostname','Desconocido')},{result.get('os_version','Desconocido')},{result.get('trend_micro','Desconocido')}\n")
                print(f"💾 Guardado de emergencia: {emergency_file}")
            except Exception as emergency_error:
                print(f"❌ Fallo guardado de emergencia: {emergency_error}")

        try:
            scanner.generate_executive_report()
            print("✅ Reporte ejecutivo guardado exitosamente")
        except Exception as e:
            print(f"❌ Error generando reporte ejecutivo: {e}")

        print(f"\n🎉 Proceso completado - {len(scanner.results)} resultados procesados!")

        if scanner.debug:
            debug_file = scanner.output_file.replace('.csv', '_debug.log')
            print(f"📝 Log de debug: {debug_file}")

    except KeyboardInterrupt:
        print("\n⚠️ Escaneo interrumpido por el usuario")
        print("📊 Guardando resultados parciales...")
        try:
            scanner.save_results()
            scanner.generate_executive_report()
            print("✅ Resultados parciales guardados")
        except Exception as save_error:
            print(f"❌ Error guardando resultados parciales: {save_error}")

    except Exception as e:
        print(f"\n❌ Error durante el proceso: {e}")
        print("📊 Intentando guardar resultados parciales...")
        try:
            scanner.save_results()
            scanner.generate_executive_report()
            print("✅ Resultados parciales guardados")
        except Exception as save_error:
            print(f"❌ Error guardando resultados parciales: {save_error}")

    finally:
        # Limpieza final y terminación forzada
        print("🔧 Limpieza final...")
        scanner.cleanup_resources()

        # Forzar terminación del programa - no esperar más
        print("✅ Proceso finalizado - terminando programa...")

        # Dar 1 segundo para que se complete cualquier I/O pendiente
        time.sleep(1)

        # Terminación forzada del programa
        import os
        os._exit(0)  # Terminación inmediata sin cleanup adicional de Python

if __name__ == "__main__":
    main()
