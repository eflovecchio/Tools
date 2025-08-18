VNC Credential Finder & Analyzer
Mostrar imagen
Descripción
VNC Credential Finder & Analyzer es una herramienta avanzada para búsqueda, extracción y desencriptación de credenciales VNC en sistemas Windows. Diseñada específicamente para profesionales de seguridad durante auditorías autorizadas, permite identificar configuraciones inseguras y contraseñas VNC almacenadas en archivos de configuración, registro de Windows y otros lugares comunes.
Esta herramienta es compatible con las implementaciones más populares de VNC, incluyendo:

RealVNC (v4.x, v5.x, v6.x)
TightVNC
UltraVNC
TigerVNC

Características principales

🔍 Búsqueda exhaustiva de credenciales VNC en ubicaciones específicas del sistema
🔓 Desencriptación integrada para algoritmos comunes de VNC
📊 Generación de informes detallados en formato texto plano y CSV
🛡️ Optimización para entornos con recursos limitados (compatible con Windows 7)
🔑 Soporte para múltiples algoritmos de encriptación de VNC
📝 Registro detallado de la actividad para análisis posterior

Uso
En sistemas Windows
powershell# Uso básico (requiere permisos de administrador)
.\vnc_finder.ps1

# Uso con salida detallada
.\vnc_finder.ps1 -Verbose

# Desencriptar una clave específica
.\vnc_decrypt.ps1 -EncryptedKey "E8CD86985B500E5D"
En entornos de pruebas de penetración (Kali Linux)
bash# Escaneo remoto de objetivos VNC
./vnc_scanner.sh 192.168.1.0/24

# Prueba de credenciales contra un servidor específico
./vnc_brute.sh 192.168.1.100 passwords.txt

# Desencriptar credenciales extraídas
./vnc_decrypt.sh C8ED86985B900E5D
Instalación
Windows
No requiere instalación. Simplemente descarga los scripts y ejecútalos con PowerShell:
powershell# Asegúrate de tener permisos para ejecutar scripts
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\vnc_finder.ps1
Kali Linux / Sistemas Unix
bash# Clona el repositorio
git clone https://github.com/tu-usuario/vnc-credential-finder.git
cd vnc-credential-finder

# Otorga permisos de ejecución
chmod +x *.sh

# Instala dependencias necesarias
./install_dependencies.sh
Estructura del proyecto
vnc-credential-finder/
├── windows/
│   ├── vnc_finder.ps1         # Script principal para Windows
│   ├── vnc_decrypt.ps1        # Herramienta de desencriptación específica
│   └── README.md              # Instrucciones para Windows
├── linux/
│   ├── vnc_scanner.sh         # Escáner de redes para servidores VNC
│   ├── vnc_brute.sh           # Herramienta de fuerza bruta
│   ├── vnc_decrypt.sh         # Herramienta de desencriptación
│   └── common_passwords.txt   # Lista de contraseñas comunes para VNC
└── docs/
    ├── VNC_Locations.md       # Documentación sobre ubicaciones VNC
    └── Algorithms.md          # Explicación de algoritmos de encriptación
Uso detallado
Extracción de credenciales en Windows
La herramienta principal vnc_finder.ps1 busca credenciales VNC en ubicaciones conocidas:

Ejecuta la herramienta con permisos de administrador:
powershell.\vnc_finder.ps1

Revisa los resultados:

vnc_credenciales.txt: Contiene las credenciales encontradas en formato legible
vnc_busqueda.log: Log detallado de todo el proceso de búsqueda


Análisis de los resultados:

Las contraseñas encontradas se intentan desencriptar automáticamente
Si no es posible desencriptar, se sugieren contraseñas comunes



Desencriptación específica de claves VNC
Para desencriptar una clave VNC específica (como la encontrada en el registro):
powershell.\vnc_decrypt.ps1 -EncryptedKey "C8ED86985B900E5D"
Este script intentará múltiples algoritmos de desencriptación y mostrará posibles resultados.
Escaneo y prueba desde Kali Linux

Escanear una red en busca de servidores VNC:
bash./vnc_scanner.sh 192.168.1.0/24
Esto identificará todos los servidores VNC activos en el rango especificado.
Probar credenciales en servidores encontrados:
bash./vnc_brute.sh 192.168.1.100 passwords.txt
Realizará pruebas sistemáticas con las contraseñas proporcionadas.
Desencriptar contraseñas extraídas de Windows:
bash./vnc_decrypt.sh C8ED86985B900E5D
Intentará desencriptar la clave usando múltiples algoritmos conocidos.

Escenarios de uso
Auditoría interna de seguridad
Ideal para administradores de sistemas que necesitan verificar si hay configuraciones VNC inseguras en la red corporativa:
powershell# Ejecutar en cada servidor Windows
.\vnc_finder.ps1 -Verbose | Out-File -FilePath "\\servidor-central\logs\$env:COMPUTERNAME-vnc-audit.log"
Respuesta a incidentes
Cuando se sospecha de accesos no autorizados a través de VNC:
powershell# Búsqueda rápida de configuraciones VNC
.\vnc_finder.ps1

# Verificar resultados
Get-Content vnc_credenciales.txt
Pruebas de penetración
Como parte de una evaluación de seguridad autorizada:
bash# Desde Kali Linux, escanear toda la red
./vnc_scanner.sh 10.0.0.0/16 > vnc_targets.txt

# Probar contraseñas por defecto en todos los objetivos
for target in $(cat vnc_targets.txt); do
    ./vnc_brute.sh $target common_passwords.txt
done
Ubicaciones analizadas
La herramienta busca exhaustivamente en ubicaciones donde VNC almacena credenciales:
Archivos

Archivos de configuración .vnc
Archivos passwd sin extensión
Archivos de configuración .ini
Archivos personalizados de conexiones guardadas

Registro de Windows

HKLM\SOFTWARE\RealVNC
HKLM\SOFTWARE\TightVNC
HKLM\SOFTWARE\UltraVNC
HKCU\SOFTWARE\RealVNC
Y muchas otras ubicaciones específicas de cada implementación

Algoritmos de desencriptación soportados
La herramienta implementa los siguientes algoritmos de desencriptación:

RealVNC 4.x (algoritmo DES modificado)
TightVNC (variante de DES)
UltraVNC (cifrado propietario)
RealVNC 5.x y 6.x
Variantes de cifrado VeNCrypt
TigerVNC

Notas de seguridad

Uso ético: Esta herramienta está diseñada exclusivamente para auditorías de seguridad autorizadas.
Permisos adecuados: Obtenga siempre autorización antes de ejecutar la herramienta en cualquier sistema.
Privacidad: La información extraída puede ser sensible; manéjela de acuerdo con las políticas de seguridad aplicables.
Limitaciones de responsabilidad: Los autores no se responsabilizan por el uso indebido de esta herramienta.

Contribuciones
Las contribuciones son bienvenidas. Para contribuir:

Haz un fork del repositorio
Crea una rama para tu funcionalidad (git checkout -b nueva-funcionalidad)
Haz commit de tus cambios (git commit -m 'Añadir nueva funcionalidad')
Haz push a la rama (git push origin nueva-funcionalidad)
Abre un Pull Request

Licencia
Este proyecto está licenciado bajo la licencia MIT - ver el archivo LICENSE para más detalles.
Autores

Tu Nombre - Trabajo inicial - tu-usuario

Agradecimientos

Agradecimiento a los investigadores de seguridad que documentaron los algoritmos de cifrado de VNC
Herramientas como vncpwd y TightVNC por la inspiración y conocimientos técnicos
La comunidad de seguridad por su continuo apoyo y contribuciones


⚠️ Descargo de responsabilidad: Esta herramienta está diseñada exclusivamente para fines de seguridad legítimos y autorizados. El uso indebido para acceder sin autorización a sistemas informáticos puede constituir un delito en muchas jurisdicciones.
