import os
import argparse
import multiprocessing
import threading
import time
import datetime
import string
import stat
from concurrent.futures import ProcessPoolExecutor

# Constantes
PRINTABLE_CHARS = set(string.printable)
MIN_PRINTABLE_RATIO = 0.8

# Funciones de parsing

def parse_args():
    parser = argparse.ArgumentParser(
        description="Escanea archivos en paralelo buscando palabras clave (case-insensitive) y muestra progreso en tiempo real.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Ejemplo de uso:
  python3 buscador_sensibles.py -f keywords.txt
  python3 buscador_sensibles.py -f keywords.txt --include .txt .py --exclude .log .bak --processes 8
"""
    )
    parser.add_argument('-f', '--file', required=True,
                        help='Archivo con palabras clave, una por línea')
    parser.add_argument('--include', nargs='*', default=[],
                        help='Extensiones a incluir (ej: .txt .py)')
    parser.add_argument('--exclude', nargs='*', default=[],
                        help='Extensiones a excluir (ej: .exe .bak)')
    parser.add_argument('-p', '--processes', type=int, default=multiprocessing.cpu_count(),
                        help='Cantidad de procesos en paralelo')
    return parser.parse_args()


def load_keywords(path):
    kws = []
    with open(path, encoding='utf-8', errors='ignore') as f:
        for line in f:
            w = line.strip()
            if w:
                kws.append(w.lower())
    return kws

# Verifica si línea tiene suficiente texto legible
def is_readable(line):
    if not line:
        return False
    printable = sum(1 for c in line if c in PRINTABLE_CHARS)
    return printable / len(line) >= MIN_PRINTABLE_RATIO

# Worker de proceso: escanea un solo archivo
def process_file(args):
    (file_path, keywords, scanned_files, scanned_lines,
     success_files, current_status, result_queue) = args
    try:
        data = open(file_path, 'rb').read()
        size = len(data)
        text = data.decode('utf-8', errors='ignore')
    except Exception:
        # Marcar archivo procesado incluso si falla
        scanned_files.value += 1
        current_status.pop(file_path, None)
        return
    lines = text.splitlines()
    total = len(lines)
    matches = []
    for idx, raw in enumerate(lines, 1):
        scanned_lines.value += 1
        # Registrar estado de este proceso
        current_status[file_path] = (idx, total, size)
        if not is_readable(raw):
            continue
        line = raw.rstrip('\n')
        lower = line.lower()
        for kw in keywords:
            if kw in lower:
                matches.append((file_path, kw, line))
    # Terminó de procesar
    scanned_files.value += 1
    if matches:
        success_files.append(file_path)
        for m in matches:
            result_queue.put(m)
    # Limpiar estado
    current_status.pop(file_path, None)

# Hilo escritor: vacía la cola de resultados a archivo
def writer_thread_fn(output_file, result_queue):
    with open(output_file, 'a', encoding='utf-8') as out:
        while True:
            item = result_queue.get()
            if item is None:
                break
            path, kw, line = item
            out.write(f"Path: {os.path.abspath(path)}\n")
            out.write(f"Palabra encontrada: {kw}\n")
            out.write(f"Resultado: {line}\n\n")

def print_progress(start_time, total_files, scanned_files, scanned_lines,
                   success_files, keywords, exts, current_status, proc_count):
    while True:
        os.system('clear')
        print(f"Inicio: {start_time}")
        print(f"Procesos paralelos: {proc_count}")
        print(f"Palabras: {', '.join(keywords)}")
        print(f"Extensiones: {', '.join(exts)}")
        print(f"Archivos totales: {total_files}")
        print(f"Archivos procesados: {scanned_files.value}")
        print(f"Líneas leídas: {scanned_lines.value}")
        print(f"Archivos con resultados: {len(success_files)}")
        # Mostrar status de procesos activos
        for fp, (idx, total, size) in current_status.items():
            mb = size/(1024*1024)
            print(f"Procesando: {fp} - {mb:.2f} MB - línea {idx}/{total}")
        if scanned_files.value >= total_files:
            break
        time.sleep(0.5)

if __name__ == '__main__':
    args = parse_args()
    keywords = load_keywords(args.file)

    # Recolectar y filtrar archivos
    all_files = []
    for d, _, files in os.walk('.'):
        for name in files:
            path = os.path.join(d, name)
            ext = os.path.splitext(path)[1].lower()
            if args.include and ext not in args.include:
                continue
            if ext in args.exclude:
                continue
            all_files.append(path)
    total_files = len(all_files)
    if total_files == 0:
        print('No hay archivos para escanear.'); exit(0)
    # Extensiones únicas
    exts = sorted(set(os.path.splitext(f)[1].lower() or '[sin_ext]' for f in all_files))

    # Preparar estados y colas
    manager = multiprocessing.Manager()
    scanned_files = manager.Value('i', 0)
    scanned_lines = manager.Value('i', 0)
    success_files = manager.list()
    current_status = manager.dict()
    result_queue = manager.Queue()

    # Nombre de archivo de resultados
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f"Busqueda_carpetas_{ts}.txt"
    # Escribir encabezado inicial
    with open(output_file, 'w', encoding='utf-8') as out:
        out.write(f"Inicio de ejecución: {datetime.datetime.now()}\n")
        out.write(f"Palabras: {', '.join(keywords)}\n")
        out.write(f"Extensiones: {', '.join(exts)}\n\n")

    # Iniciar hilo escritor
    writer = threading.Thread(target=writer_thread_fn, args=(output_file, result_queue), daemon=True)
    writer.start()

    # Iniciar hilo de progreso
    start_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    prog = threading.Thread(
        target=print_progress,
        args=(start_time, total_files, scanned_files, scanned_lines,
              success_files, keywords, exts, current_status, args.processes),
        daemon=True
    )
    prog.start()

    # Pool de procesos
    with ProcessPoolExecutor(max_workers=args.processes) as pool:
        pool.map(
            process_file,
            [(f, keywords, scanned_files, scanned_lines,
              success_files, current_status, result_queue) for f in all_files]
        )

    # Señalizar fin al escritor y esperar
    result_queue.put(None)
    writer.join()
    prog.join()
    print(f"Búsqueda completada. Resultados en {output_file}")
