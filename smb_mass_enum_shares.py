import argparse
import concurrent.futures
from smb.SMBConnection import SMBConnection
from smb.base import NotReadyError, OperationFailure

def list_files(conn, share_name, path, detail_file):
    try:
        shared_files = conn.listPath(share_name, path)
        for shared_file in shared_files:
            if shared_file.filename not in ['.', '..']:
                detail_file.write(f"    {path}/{shared_file.filename} - {'Directorio' if shared_file.isDirectory else 'Archivo'}\n")
                print(f"    {path}/{shared_file.filename} - {'Directorio' if shared_file.isDirectory else 'Archivo'}")
                if shared_file.isDirectory:
                    list_files(conn, share_name, f"{path}/{shared_file.filename}", detail_file)
    except OperationFailure as e:
        print(f"    No se pudo acceder al directorio {path}: {e}")

def list_shares(ip, username, password, login_type):
    try:
        conn = SMBConnection(username, password, 'scanner', ip, use_ntlm_v2=True)
        connected = conn.connect(ip, 139)
        
        if connected:
            shares = conn.listShares()
            if shares:
                with open("shares_abiertos.txt", "a") as f:
                    f.write(f"{ip}\n")
            
            with open("detalle_shares_abiertos.txt", "a") as detail_file:
                for share in shares:
                    share_name = share.name
                    try:
                        if login_type == "null":
                            with open("null_share_login.txt", "a") as f:
                                f.write(f"{ip}\n")
                        elif login_type == "anonymous":
                            with open("anonymous_login_shares.txt", "a") as f:
                                f.write(f"{ip}\n")

                        print(f"{ip} - login exitoso con usuario {username}")
                        detail_file.write(f"{ip} - Share: {share_name}\n")
                        list_files(conn, share_name, '', detail_file)
                    except OperationFailure as e:
                        print(f"{ip} - No se pudo acceder al share {share_name}: {e}")
            conn.close()
        else:
            print(f"{ip} - ERROR: No se pudo conectar")
    except NotReadyError as e:
        print(f"{ip} - ERROR: {e}")
    except Exception as e:
        print(f"{ip} - ERROR: {e}")

def scan_ip_null(ip):
    list_shares(ip, "", "", "null")

def scan_ip_anonymous(ip):
    list_shares(ip, "anonymous", "anonymous", "anonymous")

def remove_duplicates_and_sort(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    unique_lines = sorted(set(line.strip() for line in lines))
    
    with open(file_path, 'w') as file:
        for line in unique_lines:
            file.write(line + '\n')

def main():
    parser = argparse.ArgumentParser(description='SMB Share Scanner')
    parser.add_argument('file', metavar='FILE', type=str, help='File containing list of IP addresses to scan')
    parser.add_argument('--threads', metavar='N', type=int, default=10, help='Number of threads to use')
    args = parser.parse_args()

    with open(args.file, 'r') as file:
        ips = [line.strip() for line in file]

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        executor.map(scan_ip_null, ips)
        executor.map(scan_ip_anonymous, ips)

    # Remove duplicates and sort files
    remove_duplicates_and_sort("null_share_login.txt")
    remove_duplicates_and_sort("anonymous_login_shares.txt")
    remove_duplicates_and_sort("shares_abiertos.txt")
    remove_duplicates_and_sort("detalle_shares_abiertos.txt")

    # Summary
    total_ips = len(ips)
    with open("null_share_login.txt", "r") as f:
        null_shares = len(f.readlines())
    with open("anonymous_login_shares.txt", "r") as f:
        anonymous_shares = len(f.readlines())
    with open("shares_abiertos.txt", "r") as f:
        open_shares = len(f.readlines())
    
    summary = (
        f"\nResumen:\n"
        f"Total IPs escaneadas: {total_ips}\n"
        f"Logins exitosos con null user: {null_shares}\n"
        f"Logins exitosos con anonymous user: {anonymous_shares}\n"
        f"IPs con shares enumerados: {open_shares}\n"
    )

    print(summary)

    with open("resumen_resultado.txt", "w") as f:
        f.write(summary)

if __name__ == "__main__":
    main()
