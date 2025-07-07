#!/usr/bin/env python3
# smb_scanner.py
# Escanea múltiples IPs en puerto 445 buscando shares SMB,
# genera cuatro archivos de salida y muestra un panel de estado dinámico.

import argparse
import os
import time
import logging
import subprocess
import shlex
import threading
import curses
from concurrent.futures import ThreadPoolExecutor
from smb.SMBConnection import SMBConnection
from smb.smb_structs import OperationFailure

# ----------------------------
# Argument parsing
# ----------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Escanea múltiples IPs en puerto 445 buscando shares SMB y genera reportes.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("ip_file", help="Archivo con lista de IPs, una por línea.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-A", "--anonymous", action="store_true", help="Login anónimo")
    group.add_argument("-u", "--user", metavar="USER", help="Usuario")
    parser.add_argument("-p", "--password", metavar="PASSWORD", help="Contraseña")
    parser.add_argument("-P", "--processes", type=int, default=10, help="Threads simultáneos")
    parser.add_argument("-D", "--download", metavar="MAX_MB", type=int, nargs='?', const=0,
                        help="Descargar archivos <=MAX_MB MB (0=sin límite)")
    parser.add_argument("--include-ext", nargs="+", metavar="EXT", help="Incluir extensiones (requiere -D)")
    parser.add_argument("--exclude-ext", nargs="+", metavar="EXT", help="Excluir extensiones (requiere -D)")
    return parser.parse_args()

# ----------------------------
# Logging
# ----------------------------

def init_logging():
    logging.basicConfig(
        filename="debug.log",
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
        filemode='w'
    )

# ----------------------------
# Escritura ordenada de shares con prevención de duplicados
# ----------------------------

writer_lock = threading.Lock()

def write_share_output(ip, share, entries, creds, state):
    key = (ip, share)
    with writer_lock:
        if key in state.written_shares:
            return
        state.written_shares.add(key)
        count = len(entries)
        size_total = sum(sz for _, sz, _ in entries)
        mb_total = size_total / 1024**2
        with open("Shares_Abiertos.txt", "a", encoding="utf-8") as f:
            f.write(f"{ip} - Archivos: {count} - {mb_total:.2f} MB\n")
            for path, size, mtime in entries:
                mb = size / 1024**2
                f.write(f"   {share}{path} - {mb:.2f} MB - {mtime}\n")
        if ip not in state.written_ips:
            state.written_ips.add(ip)
            with open("ip_shares_abiertos.txt", "a") as f:
                f.write(f"{ip}\n")
        u, p = creds
        entry = (ip, u or 'anonymous', p or '')
        if entry not in state.written_creds:
            state.written_creds.add(entry)
            with open("ip_shares_abiertos_creds.txt", "a") as f:
                f.write(f"{entry[0]}:{entry[1]}:{entry[2]}\n")
    with state.lock:
        state.shares_accedidos.add(key)
        state.ip_file_count[ip] = state.ip_file_count.get(ip, 0) + count
        state.ip_size_total[ip] = state.ip_size_total.get(ip, 0) + size_total
        state.total_files += count
        state.total_size += size_total

# ----------------------------
# Enumeración de un share con pysmb
# ----------------------------

def enum_share(conn, ip, share, creds, opts, state):
    entries = []
    def recurse(path):
        try:
            files = conn.listPath(share, path)
        except OperationFailure:
            return
        for f in files:
            if f.filename in ('.','..'): continue
            full = os.path.join(path, f.filename).replace('\\','/')
            size = f.file_size
            mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(f.last_write_time))
            entries.append((full, size, mtime))
            # descarga opcional (solo >0 bytes)
            if opts['download'] is not None and size > 0:
                ext = os.path.splitext(f.filename)[1].lower()
                if size <= opts['download']*1024*1024 and (not opts['include'] or ext in opts['include']) and (not opts['exclude'] or ext not in opts['exclude']):
                    if _dl_pysmb(conn, share, full, ip, size, state, creds):
                        continue
            if f.isDirectory:
                recurse(full)
    recurse("")
    write_share_output(ip, share, entries, creds, state)

# ----------------------------
# Escaneo SMB1
# ----------------------------

def scan_smb1(ip, creds, opts, state):
    u, p = creds
    try:
        conn = SMBConnection(u, p, "local", ip, use_ntlm_v2=True)
        if not conn.connect(ip, 445): raise
    except:
        fallback_smbclient(ip, creds, opts, state)
        return
    try:
        shares = conn.listShares()
    except:
        conn.close(); return
    for s in shares:
        if s.isSpecial or s.name.upper()=='IPC$': continue
        enum_share(conn, ip, s.name, creds, opts, state)
    conn.close()

# ----------------------------
# Descarga pysmb helper con estadísticas
# ----------------------------

def _dl_pysmb(conn, share, remote, ip, size, state, creds):
    odir = os.path.join("SMB_Abiertos", ip, share)
    os.makedirs(odir, exist_ok=True)
    local = os.path.join(odir, remote.lstrip('/'))
    os.makedirs(os.path.dirname(local), exist_ok=True)
    try:
        with open(local, 'wb') as fp:
            conn.retrieveFile(share, remote, fp)
    except:
        return False
    # actualizar stats descarga
    with state.lock:
        state.download_count += 1
        state.download_size += size
    return True

# ----------------------------
# fallback smbclient (simplificado)
# ----------------------------

def fallback_smbclient(ip, creds, opts, state):
    u, p = creds
    auth = f"-U {u}%{p}" if u else "-N"
    try:
        out = subprocess.check_output(shlex.split(f"smbclient -L //{ip} {auth}"), stderr=subprocess.DEVNULL).splitlines()
    except:
        return
    for line in out:
        if b'Disk' not in line: continue
        share = line.decode().split()[0]
        write_share_output(ip, share, [], creds, state)

# ----------------------------
# Panel curses
# ----------------------------

def curses_panel(stdscr, total_ips, state):
    curses.curs_set(0)
    while not state.done:
        stdscr.erase()
        stdscr.addstr(0, 0, f"Escaneo iniciado: {state.start_time}")
        stdscr.addstr(1, 0, f"Shares: {total_ips}")
        stdscr.addstr(2, 0, f"Shares accedidos: {len(state.shares_accedidos)}")
        stdscr.addstr(3, 0, f"Archivos enumerados: {state.total_files}")
        mb = state.total_size/1024/1024
        stdscr.addstr(4, 0, f"Peso total archivos enumerados: {mb:.2f} MB")
        stdscr.refresh()
        time.sleep(3)

# ----------------------------
# Main
# ----------------------------

if __name__=='__main__':
    args = parse_args(); init_logging()
    # truncar salidas
    for fname in ["Shares_Abiertos.txt","ip_shares_abiertos.txt","ip_shares_abiertos_creds.txt","reporte_final.txt"]:
        open(fname, "w").close()
    # credenciales
    creds = [( '', '' ),( 'anonymous','anonymous')] if args.anonymous else [(args.user, args.password)]
    opts = {
        'download':args.download,
        'include': set(e.lower() for e in (args.include_ext or [])),
        'exclude': set(e.lower() for e in (args.exclude_ext or []))
    }
    class State: pass
    state = State()
    state.written_ips=set(); state.written_creds=set(); state.written_shares=set()
    state.shares_accedidos=set(); state.ip_file_count={}; state.ip_size_total={}
    state.total_files=0; state.total_size=0; state.lock=threading.Lock()
    state.download_count=0; state.download_size=0
    state.done=False; state.start_time=time.strftime("%Y-%m-%d %H:%M:%S")
    with open(args.ip_file) as f: ips=[l.strip() for l in f if l.strip()]
    total_ips = len(ips)
    def _scan_all():
        with ThreadPoolExecutor(max_workers=args.processes) as ex:
            for ip in ips:
                for cred in creds:
                    ex.submit(scan_smb1, ip, cred, opts, state)
        state.done = True
        # generar reporte_final.txt
        with open("reporte_final.txt","a") as rf:
            rf.write(f"Escaneo final: Shares: {total_ips}, Accedidos: {len(state.shares_accedidos)}, "
                      +f"Archivos: {state.total_files}, Peso: {state.total_size/1024/1024:.2f} MB\n")
            for ip in sorted(state.ip_file_count):
                cnt = state.ip_file_count[ip]
                sz = state.ip_size_total[ip]/1024/1024
                rf.write(f"{ip} - Archivos totales: {cnt} - Peso total share: {sz:.2f} MB\n")
            # estadísticas de descarga
            rf.write(f"\nArchivos descargados: {state.download_count}\n")
            rf.write(f"Peso total descargado: {state.download_size/1024/1024:.2f} MB\n")
    scan_thread = threading.Thread(target=_scan_all)
    scan_thread.start()
    curses.wrapper(lambda scr: curses_panel(scr, total_ips, state))
    scan_thread.join()