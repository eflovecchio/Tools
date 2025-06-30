#!/bin/bash

#Ejemplo de uso:sudo ./massnmap.sh lista_ip.txt "nmap -sV -p- -O"
#               sudo ./massnmap.sh (archivo con la lista de ip) "comando de nmap sin especifica output"

# Verifica si se proporcionó un archivo de lista de IP's y un comando de Nmap como parámetros
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Debe proporcionar un archivo de lista de IP's y un comando de Nmap como parámetros."
    exit 1
fi

# Número de escaneos simultáneos
num_concurrent_scans=12

# Archivo con la lista de direcciones IP (una IP por línea)
input_file="$1"

# Comando de Nmap (sin el nombre del archivo de salida)
nmap_command="${@:2}"

# Nombre del archivo de progreso
progress_file="progreso.txt"

# Variable que indica cada cuantos segundos se debe actualizar el dashboard   
update_time_dashboard=1

# Variable para contar el número de escaneos en progreso
num_scans_in_progress=0

# Cuenta las lineas que hay en el archivo proporcionado
total_lines=($(wc -l < "$input_file"))

# Variable que determina cada cuanto se debe refrescar el dashboard
refresh_time_dashboard=2

# Función para mostrar el progreso de cada escaneo cada 5 segundos
function mostrar_progreso() {
    while true; do
        sleep $refresh_time_dashboard
        clear
        echo "=========================== MassNmap =========================="
        echo "Total IPS a escanear: $total_lines"
        echo "$nmap_command"
        echo "$($!)"
        cat  "$progress_file"
        echo "==============================================================="
    done
}
# Limpia el archivo de progreso antes de comenzar
$(rm $progress_file)

# Inicia la función de progreso en segundo plano
mostrar_progreso &

process_pid=$!

# Trap para finalizar la función de progreso cuando finalice el script
trap "kill $process_pid >/dev/null 2>&1" EXIT

# Función para ejecutar el escaneo de una IP
function ejecutar_escaneo() {
    ip=$1
    # Hora inicio del escaneo
    hora_inicio=$(date +"%H:%M")
    # Agrega la IP al archivo de progreso con el estado "En progreso"
    echo "IP: $ip - En progreso" >> "$progress_file"
    # Ejecuta el comando de Nmap para la IP con el nombre de archivo de salida
    eval "$nmap_command -oX ${ip}_nmap_xml.txt -oN ${ip}_nmap.txt $ip"
    # Verifica si el escaneo se completó exitosamente
    if [ $? -eq 0 ]; then
        # Obtiene la hora local en formato "hora:minuto"
        hora_completado=$(date +"%H:%M")
        # Actualiza el estado de la IP a "Completado" con la hora de finalización
        sed -i "s/IP: $ip - En progreso/IP: $ip - Completado $hora_completado/g" "$progress_file"
    else
        echo "Error al ejecutar el escaneo para la IP: $ip" >> "$progress_file"
    fi
}

# Lee las IP's del archivo y ejecuta los escaneos
while IFS= read -r ip; do
    # Verifica si se alcanzó el límite de escaneos simultáneos
    if [ $num_scans_in_progress -ge $num_concurrent_scans ]; then
        # Espera a que finalice algún escaneo antes de continuar
        wait -n
        ((num_scans_in_progress--))
    fi
    # Ejecuta el escaneo en segundo plano
    ejecutar_escaneo "$ip" &
    ((num_scans_in_progress++))
done < "$input_file"
wait 
# No funciona el aviso de finalizacion del escaneo Je
echo "Escaneo finalizado"
exit 0
